/* SPDX-License-Identifier: LicenseRef-Proprietary
   Copyright (c) 2026 wwm-spec. All rights reserved.
 */

#include "vpncore/vpn_tun.h"
#include "vpncore/vpn_error.h"
#include "vpncore/vpn_log.h"
#include "vpncore/vpn_net.h"
#include "vpncore/vpn_platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __linux__
#include <linux/if_tun.h>
#endif
#endif

/* ---------------- 基于 fd 的 ops（Android VpnService / Linux TUN 共用） ---------------- */
typedef struct {
    int  fd;
    bool owns;
} fd_ctx;

static int fd_read(void *ctx, void *buf, size_t cap, int timeout_ms)
{
    fd_ctx *f = (fd_ctx *)ctx;
#ifndef _WIN32
    /* timeout_ms >= 0 都先 poll：0 表示"非阻塞探测"，绝不能直接 read 阻塞 */
    if (timeout_ms >= 0) {
        struct pollfd pfd;
        pfd.fd = f->fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        int rc = poll(&pfd, 1, timeout_ms);
        if (rc == 0)
            return VPN_ERR_TIMEOUT;
        if (rc < 0)
            return errno == EINTR ? VPN_ERR_TIMEOUT : VPN_ERR_IO;
    }
    for (;;) {
        ssize_t n = read(f->fd, buf, cap);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return VPN_ERR_TIMEOUT;
            return VPN_ERR_IO;
        }
        return (int)n;
    }
#else
    (void)f; (void)buf; (void)cap; (void)timeout_ms;
    return VPN_ERR_UNSUPPORTED;
#endif
}

static int fd_write(void *ctx, const void *buf, size_t len)
{
    fd_ctx *f = (fd_ctx *)ctx;
#ifndef _WIN32
    for (;;) {
        ssize_t n = write(f->fd, buf, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return VPN_ERR_IO;
        }
        return (int)n;
    }
#else
    (void)f; (void)buf; (void)len;
    return VPN_ERR_UNSUPPORTED;
#endif
}

static void fd_destroy(void *ctx)
{
    fd_ctx *f = (fd_ctx *)ctx;
    if (!f)
        return;
#ifndef _WIN32
    if (f->owns && f->fd >= 0)
        close(f->fd);
#endif
    free(f);
}

int vpn_tun_ops_from_fd(int fd, bool owns_fd, vpn_tun_ops *out)
{
    fd_ctx *f;

    if (fd < 0 || !out)
        return VPN_ERR_INVALID;

    f = (fd_ctx *)calloc(1, sizeof(*f));
    if (!f)
        return VPN_ERR_NOMEM;
    f->fd = fd;
    f->owns = owns_fd;

#ifndef _WIN32
    /* 客户端主循环用 timeout_ms=0 轮询：fd 必须非阻塞，否则单线程事件循环会被
     * 无数据时的 read() 永久挂住（SSTP 心跳/收包全部停摆）。 */
    {
        int fl = fcntl(fd, F_GETFL, 0);
        if (fl >= 0)
            fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    }
#endif

    out->read = fd_read;
    out->write = fd_write;
    out->destroy = fd_destroy;
    out->ctx = f;
    return VPN_OK;
}

#ifndef _WIN32
int vpn_tun_open(const char *dev_name, uint32_t mtu, char *name_out, size_t name_len,
                 vpn_tun_ops *out)
{
#ifdef __linux__
    struct ifreq ifr;
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        VPN_ERROR("打开 /dev/net/tun 失败: %s（需要 root 或 CAP_NET_ADMIN）", strerror(errno));
        return VPN_ERR_IO;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (dev_name && dev_name[0])
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", dev_name);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        VPN_ERROR("TUNSETIFF 失败: %s", strerror(errno));
        close(fd);
        return VPN_ERR_IO;
    }

    if (name_out && name_len)
        snprintf(name_out, name_len, "%s", ifr.ifr_name);

    int rc = vpn_tun_ops_from_fd(fd, true, out);
    if (rc != VPN_OK)
        close(fd);
    else if (mtu)
        vpn_tun_configure(ifr.ifr_name, 0, 0, 0, mtu);
    return rc;
#else
    (void)dev_name; (void)mtu; (void)name_out; (void)name_len; (void)out;
    return VPN_ERR_UNSUPPORTED;
#endif
}

static int ctl_socket(void)
{
    return socket(AF_INET, SOCK_DGRAM, 0);
}

int vpn_tun_configure(const char *dev_name, uint32_t local_ip, uint32_t peer_ip,
                      uint32_t netmask, uint32_t mtu)
{
#ifdef __linux__
    struct ifreq ifr;
    struct sockaddr_in *sin;
    int s = ctl_socket();
    int rc = VPN_OK;

    if (s < 0)
        return VPN_ERR_IO;

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", dev_name);

    if (local_ip) {
        sin = (struct sockaddr_in *)&ifr.ifr_addr;
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = local_ip;
        if (ioctl(s, SIOCSIFADDR, &ifr) < 0)
            rc = VPN_ERR_IO;
    }

    if (peer_ip) {
        memset(&ifr, 0, sizeof(ifr));
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", dev_name);
        sin = (struct sockaddr_in *)&ifr.ifr_dstaddr;
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = peer_ip;
        if (ioctl(s, SIOCSIFDSTADDR, &ifr) < 0)
            rc = VPN_ERR_IO;
    }

    if (netmask) {
        memset(&ifr, 0, sizeof(ifr));
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", dev_name);
        sin = (struct sockaddr_in *)&ifr.ifr_netmask;
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = netmask;
        if (ioctl(s, SIOCSIFNETMASK, &ifr) < 0)
            rc = VPN_ERR_IO;
    }

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", dev_name);
    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
        rc = VPN_ERR_IO;
    } else {
        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
        if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0)
            rc = VPN_ERR_IO;
    }

    if (mtu) {
        memset(&ifr, 0, sizeof(ifr));
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", dev_name);
        ifr.ifr_mtu = (int)mtu;
        if (ioctl(s, SIOCSIFMTU, &ifr) < 0)
            rc = VPN_ERR_IO;
    }

    close(s);
    return rc;
#else
    (void)dev_name; (void)local_ip; (void)peer_ip; (void)netmask; (void)mtu;
    return VPN_ERR_UNSUPPORTED;
#endif
}

int vpn_tun_add_route_metric(const char *dev_name, uint32_t dst, uint32_t mask,
                             uint32_t gateway, int metric)
{
#ifdef __linux__
    struct rtentry rt;
    struct sockaddr_in *sin;
    int s = ctl_socket();
    int rc = VPN_OK;

    if (s < 0)
        return VPN_ERR_IO;

    memset(&rt, 0, sizeof(rt));
    sin = (struct sockaddr_in *)&rt.rt_dst;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = dst;

    sin = (struct sockaddr_in *)&rt.rt_genmask;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = mask;

    sin = (struct sockaddr_in *)&rt.rt_gateway;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = gateway;

    rt.rt_dev = (char *)dev_name;
    rt.rt_flags = RTF_UP;
    if (gateway)
        rt.rt_flags |= RTF_GATEWAY;
    if (mask == 0xffffffffu)
        rt.rt_flags |= RTF_HOST;
    if (metric > 0)
        rt.rt_metric = (short)metric;

    if (ioctl(s, SIOCADDRT, &rt) < 0)
        rc = VPN_ERR_IO;
    close(s);
    return rc;
#else
    (void)dev_name; (void)dst; (void)mask; (void)gateway; (void)metric;
    return VPN_ERR_UNSUPPORTED;
#endif
}

int vpn_tun_add_route_via(const char *dev_name, uint32_t dst, uint32_t mask,
                          uint32_t gateway)
{
    return vpn_tun_add_route_metric(dev_name, dst, mask, gateway, 0);
}

int vpn_tun_add_route(const char *dev_name, uint32_t dst, uint32_t mask)
{
    return vpn_tun_add_route_via(dev_name, dst, mask, 0);
}

int vpn_tun_del_route(const char *dev_name, uint32_t dst, uint32_t mask)
{
#ifdef __linux__
    struct rtentry rt;
    struct sockaddr_in *sin;
    int s = ctl_socket();
    int rc = VPN_OK;

    if (s < 0)
        return VPN_ERR_IO;

    memset(&rt, 0, sizeof(rt));
    sin = (struct sockaddr_in *)&rt.rt_dst;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = dst;

    sin = (struct sockaddr_in *)&rt.rt_genmask;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = mask;

    rt.rt_dev = (char *)dev_name;

    if (ioctl(s, SIOCDELRT, &rt) < 0)
        rc = VPN_ERR_IO;
    close(s);
    return rc;
#else
    (void)dev_name; (void)dst; (void)mask;
    return VPN_ERR_UNSUPPORTED;
#endif
}

int vpn_tun_set_dns_pref(const char *dev_name, uint32_t dns1, uint32_t dns2, int metric)
{
    (void)metric;   /* Linux 侧解析顺序由 resolv.conf/systemd-resolved 决定 */
    return vpn_tun_set_dns(dev_name, dns1, dns2);
}

int vpn_tun_clear_dns(const char *dev_name)
{
    (void)dev_name;
    return VPN_OK;
}

int vpn_tun_set_dns(const char *dev_name, uint32_t dns1, uint32_t dns2)
{
    /* Linux 无统一接口，交给 resolvconf/systemd-resolved；此处仅记录日志。
     * Android 由 VpnService.Builder.addDnsServer 完成，Windows 由 shell 用 API 设置。 */
    char b1[32], b2[32];
    if (dns1)
        VPN_INFO("接口 %s DNS1 = %s", dev_name, vpn_ip_ntoa(dns1, b1, sizeof(b1)));
    if (dns2)
        VPN_INFO("接口 %s DNS2 = %s", dev_name, vpn_ip_ntoa(dns2, b2, sizeof(b2)));
    return VPN_OK;
}
#endif /* !_WIN32（Windows 侧实现见 vpn_tun_win.c） */
