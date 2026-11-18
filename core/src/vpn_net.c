/* SPDX-License-Identifier: LicenseRef-Proprietary
   Copyright (c) 2026 wwm-spec. All rights reserved.
 */

#include "vpncore/vpn_net.h"
#include "vpncore/vpn_error.h"
#include "vpncore/vpn_log.h"
#include "vpncore/vpn_platform.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <ws2tcpip.h>
#define vpn_close_sock closesocket
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <unistd.h>
#define vpn_close_sock close
#endif

int vpn_net_init(void)
{
#ifdef _WIN32
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0 ? VPN_OK : VPN_ERR_IO;
#else
    return VPN_OK;
#endif
}

void vpn_net_cleanup(void)
{
#ifdef _WIN32
    WSACleanup();
#endif
}

int vpn_net_error(void)
{
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

int vpn_net_resolve(const char *host, uint16_t port, struct sockaddr_storage *out,
                    socklen_t *outlen)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    char portstr[16];
    int rc;

    if (!host || !out || !outlen)
        return VPN_ERR_INVALID;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);

    rc = getaddrinfo(host, portstr, &hints, &res);
    if (rc != 0 || !res) {
        VPN_ERROR("DNS 解析失败: %s (%s)", host,
#ifdef _WIN32
                  "getaddrinfo"
#else
                  gai_strerror(rc)
#endif
        );
        if (res)
            freeaddrinfo(res);
        return VPN_ERR_IO;
    }

    memcpy(out, res->ai_addr, res->ai_addrlen);
    *outlen = (socklen_t)res->ai_addrlen;
    freeaddrinfo(res);
    return VPN_OK;
}

static int wait_writable(vpn_sock_t sock, int timeout_ms)
{
#ifdef _WIN32
    fd_set wfds;
    struct timeval tv;
    FD_ZERO(&wfds);
    FD_SET((SOCKET)sock, &wfds);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int rc = select(0, NULL, &wfds, NULL, &tv);
    return rc > 0 ? VPN_OK : (rc == 0 ? VPN_ERR_TIMEOUT : VPN_ERR_IO);
#else
    struct pollfd pfd;
    pfd.fd = sock;
    pfd.events = POLLOUT;
    pfd.revents = 0;
    int rc = poll(&pfd, 1, timeout_ms);
    if (rc == 0)
        return VPN_ERR_TIMEOUT;
    if (rc < 0)
        return VPN_ERR_IO;
    return VPN_OK;
#endif
}

static vpn_protect_fn g_protect;
static void *g_protect_ctx;

void vpn_net_set_protect(vpn_protect_fn fn, void *ctx)
{
    g_protect = fn;
    g_protect_ctx = ctx;
}

static void protect_socket(vpn_sock_t s)
{
    if (!g_protect || s == VPN_INVALID_SOCK)
        return;
    if (g_protect(g_protect_ctx, (int)s) != 0)
        VPN_WARN("socket protect 失败（fd=%d），隧道可能被自身路由中断", (int)s);
}

int vpn_net_tcp_connect(const char *host, uint16_t port, int timeout_ms, vpn_sock_t *sock)
{
    struct sockaddr_storage ss;
    socklen_t sslen = 0;
    int rc;

    if (!sock)
        return VPN_ERR_INVALID;
    *sock = VPN_INVALID_SOCK;

    rc = vpn_net_resolve(host, port, &ss, &sslen);
    if (rc != VPN_OK)
        return rc;

    vpn_sock_t s = socket(ss.ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (s == VPN_INVALID_SOCK)
        return VPN_ERR_IO;

    protect_socket(s);

    vpn_net_set_nonblock(s, true);

    int cr = connect(s, (struct sockaddr *)&ss, sslen);
    bool in_progress = false;
    if (cr != 0) {
#ifdef _WIN32
        int we = WSAGetLastError();
        in_progress = (we == WSAEWOULDBLOCK);
#else
        in_progress = (errno == EINPROGRESS);
#endif
        if (!in_progress) {
            VPN_ERROR("TCP 连接 %s:%u 失败: errno=%d", host, port, vpn_net_error());
            vpn_net_close(&s);
            return VPN_ERR_IO;
        }
    }

    if (in_progress) {
        if (timeout_ms <= 0)
            timeout_ms = 15000;
        rc = wait_writable(s, timeout_ms);
        if (rc != VPN_OK) {
            VPN_WARN("TCP 连接 %s:%u 超时(%dms)", host, port, timeout_ms);
            vpn_net_close(&s);
            return rc;
        }
        int soerr = 0;
        socklen_t slen = sizeof(soerr);
        if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&soerr, &slen) != 0 || soerr != 0) {
            VPN_ERROR("TCP 连接 %s:%u 被拒绝: errno=%d", host, port, soerr);
            vpn_net_close(&s);
            return VPN_ERR_IO;
        }
    }

    vpn_net_set_nonblock(s, false);
    vpn_net_set_nodelay(s);
    VPN_INFO("TCP 已连接 %s:%u", host, port);
    *sock = s;
    return VPN_OK;
}

int vpn_net_udp_connect(const char *host, uint16_t port, vpn_sock_t *sock)
{
    struct sockaddr_storage ss;
    socklen_t sslen = 0;
    int rc;

    if (!sock)
        return VPN_ERR_INVALID;
    *sock = VPN_INVALID_SOCK;

    rc = vpn_net_resolve(host, port, &ss, &sslen);
    if (rc != VPN_OK)
        return rc;

    vpn_sock_t s = socket(ss.ss_family, SOCK_DGRAM, IPPROTO_UDP);
    if (s == VPN_INVALID_SOCK)
        return VPN_ERR_IO;

    protect_socket(s);

    /* 不设置 DF 位（与 xl2tpd 一致）：部分实现的 L2TP 数据面按 DF 分路径处理。
     * Windows(winsock) 没有 IP_MTU_DISCOVER，跳过即可 */
    {
#ifdef IP_MTU_DISCOVER
        int pmtu = 0;   /* IP_PMTUDISC_DONT */
        setsockopt(s, IPPROTO_IP, IP_MTU_DISCOVER, (const void *)&pmtu, sizeof(pmtu));
#endif
    }

    /* 关闭 UDP 校验和（与 xl2tpd 一致）：部分 RouterOS 版本的 L2TP 数据面
     * 对该路径的校验和校验异常，带校验和的 T=0 报文会被静默丢弃 */
    {
        int nocheck = 1;
#ifdef SO_NO_CHECK
        setsockopt(s, SOL_SOCKET, SO_NO_CHECK, &nocheck, sizeof(nocheck));
#endif
        (void)nocheck;
    }

    if (connect(s, (struct sockaddr *)&ss, sslen) != 0) {
        VPN_ERROR("UDP connect %s:%u 失败", host, port);
        vpn_net_close(&s);
        return VPN_ERR_IO;
    }
    VPN_INFO("UDP 已连接 %s:%u", host, port);
    *sock = s;
    return VPN_OK;
}

/* 绑定本地固定端口后再连服务器：L2TP 数据通道要求源端口 1701，
 * 用随机端口时 RouterOS 会丢弃所有 PPP 帧（LCP 永远无响应） */
int vpn_net_udp_connect_local(uint16_t local_port, const char *host, uint16_t port,
                              vpn_sock_t *sock)
{
    struct sockaddr_storage ss;
    socklen_t sslen = 0;
    int rc;

    if (!sock)
        return VPN_ERR_INVALID;
    *sock = VPN_INVALID_SOCK;

    rc = vpn_net_resolve(host, port, &ss, &sslen);
    if (rc != VPN_OK)
        return rc;

    vpn_sock_t s = socket(ss.ss_family, SOCK_DGRAM, IPPROTO_UDP);
    if (s == VPN_INVALID_SOCK)
        return VPN_ERR_IO;

    protect_socket(s);

    if (local_port) {
        int on = 1;
        struct sockaddr_in la;

#ifdef _WIN32
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on));
#else
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#endif
        memset(&la, 0, sizeof(la));
        la.sin_family = AF_INET;
        la.sin_addr.s_addr = htonl(INADDR_ANY);
        la.sin_port = htons(local_port);
        if (bind(s, (struct sockaddr *)&la, sizeof(la)) != 0) {
            VPN_WARN("绑定本地 UDP 端口 %u 失败（可能已被其他 L2TP 客户端占用）", local_port);
            if (local_port == 1701) {
                /* 端口被占用是硬错误：继续用随机端口只会在 PPP 阶段卡死 */
                vpn_net_close(&s);
                return VPN_ERR_IO;
            }
        }
    }

    /* 不设置 DF 位（与 xl2tpd 一致）：部分实现的 L2TP 数据面按 DF 分路径处理。
     * Windows(winsock) 没有 IP_MTU_DISCOVER，跳过即可 */
    {
#ifdef IP_MTU_DISCOVER
        int pmtu = 0;   /* IP_PMTUDISC_DONT */
        setsockopt(s, IPPROTO_IP, IP_MTU_DISCOVER, (const void *)&pmtu, sizeof(pmtu));
#endif
    }

    /* 关闭 UDP 校验和（与 xl2tpd 一致）：部分 RouterOS 版本的 L2TP 数据面
     * 对该路径的校验和校验异常，带校验和的 T=0 报文会被静默丢弃 */
    {
        int nocheck = 1;
#ifdef SO_NO_CHECK
        setsockopt(s, SOL_SOCKET, SO_NO_CHECK, &nocheck, sizeof(nocheck));
#endif
        (void)nocheck;
    }

    if (connect(s, (struct sockaddr *)&ss, sslen) != 0) {
        VPN_ERROR("UDP connect %s:%u 失败", host, port);
        vpn_net_close(&s);
        return VPN_ERR_IO;
    }
    *sock = s;
    return VPN_OK;
}

int vpn_net_raw_esp_connect(const char *host, vpn_sock_t *sock)
{
#if defined(_WIN32) || !defined(IPPROTO_ESP)
    (void)host;
    (void)sock;
    return VPN_ERR_IO;
#else
    struct sockaddr_storage ss;
    socklen_t sslen = 0;
    vpn_sock_t s;
    int rc;

    if (!host || !sock)
        return VPN_ERR_INVALID;
    *sock = VPN_INVALID_SOCK;

    rc = vpn_net_resolve(host, 0, &ss, &sslen);
    if (rc != VPN_OK)
        return rc;
    if (ss.ss_family != AF_INET)
        return VPN_ERR_INVALID;

    s = socket(AF_INET, SOCK_RAW, IPPROTO_ESP);
    if (s == VPN_INVALID_SOCK) {
        /* 非 root 或系统禁止：退回 UDP 封装路径，不算致命错误 */
        VPN_DEBUG("原始 ESP socket 不可用（需要 root/CAP_NET_RAW），改用 UDP 封装");
        return VPN_ERR_IO;
    }
    protect_socket(s);

    if (connect(s, (struct sockaddr *)&ss, sslen) != 0) {
        vpn_net_close(&s);
        return VPN_ERR_IO;
    }
    *sock = s;
    return VPN_OK;
#endif
}

/* ------------------------------------------------------------------ */
/* GRE 发送                                                           */
/* ------------------------------------------------------------------ */
#define GRE_PEERS_MAX 4

typedef struct {
    vpn_sock_t sock;
    uint32_t   src;
    uint32_t   dst;
} gre_peer_entry;

static gre_peer_entry g_gre_peers[GRE_PEERS_MAX];

#ifdef _WIN32
/* Windows 上 GRE 的发送方式由 IP_HDRINCL 决定，两种模式在线上完全不同：
 *   1 = 应用自带 IPv4 头（IP_HDRINCL=TRUE）
 *   0 = 只发 GRE，内核补头（IP_HDRINCL=FALSE）
 * 默认 1；设 VPN_GRE_NOHDR=1 切到 0，便于现场一次构建排除两种可能 */
static int g_gre_hdrincl = 1;
#endif
#ifdef _WIN32
static uint16_t       g_gre_ip_id; /* 仅 Windows 构造 IP 头时用 */
#endif

/* PPTP 的 GRE(47) 数据面：需要 raw socket 权限，且系统/防火墙必须放行 GRE */
int vpn_net_raw_gre_connect(const char *host, vpn_sock_t *sock)
{
    struct sockaddr_storage ss;
    struct sockaddr_in local;
    socklen_t sslen = 0, llen;
    vpn_sock_t s, probe;
    int rc;

    if (!host || !sock)
        return VPN_ERR_INVALID;
    *sock = VPN_INVALID_SOCK;

    rc = vpn_net_resolve(host, 0, &ss, &sslen);
    if (rc != VPN_OK)
        return rc;
    if (ss.ss_family != AF_INET)
        return VPN_ERR_INVALID;

    /* 先用 UDP socket 走一次选路，拿到内核实际会用的源地址：
     * Windows 的 RAW socket 必须 bind 到这个地址才能收/发 GRE，
     * 只 connect 不 bind 会出现「能发出去但收不到回包」的假死 */
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    probe = socket(AF_INET, SOCK_DGRAM, 0);
    if (probe != VPN_INVALID_SOCK) {
        if (connect(probe, (struct sockaddr *)&ss, sslen) == 0) {
            llen = sizeof(local);
            if (getsockname(probe, (struct sockaddr *)&local, &llen) != 0)
                local.sin_addr.s_addr = 0;
        } else {
            local.sin_addr.s_addr = 0;
        }
        vpn_net_close(&probe);
    }

    s = socket(AF_INET, SOCK_RAW, 47 /* IPPROTO_GRE */);
    if (s == VPN_INVALID_SOCK) {
        VPN_ERROR("GRE(47) raw socket 创建失败：需要管理员权限（Windows）"
                  "或 root/CAP_NET_RAW（Linux）");
        return VPN_ERR_UNSUPPORTED;
    }
    protect_socket(s);

#ifdef _WIN32
    /* 显式设定 IP_HDRINCL 并记住结果，发送时据此决定是否自带 IP 头。
     * 两种模式必须严格配套：开了却发裸 GRE → 首字节 0x20 被当成 IP 版本 2
     * 丢掉；没开却自带 IP 头 → 内核再套一层，对端读到 0x45 判非法丢弃。
     * 两者的共同症状都是「send 成功、对端毫无反应」*/
    {
        const char *mode = getenv("VPN_GRE_NOHDR");
        BOOL hdrincl = (mode && mode[0] == '1') ? FALSE : TRUE;

        if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, (const char *)&hdrincl,
                       (int)sizeof(hdrincl)) != 0) {
            VPN_WARN("GRE raw socket 设置 IP_HDRINCL 失败（错误 %d），"
                     "按内核补头方式发送", WSAGetLastError());
            g_gre_hdrincl = 0;
        } else {
            g_gre_hdrincl = hdrincl ? 1 : 0;
        }
        VPN_INFO("GRE 发送模式：%s", g_gre_hdrincl ? "自带 IPv4 头（IP_HDRINCL）"
                                                  : "裸 GRE（内核补 IP 头）");
    }

    if (local.sin_addr.s_addr) {
        local.sin_port = 0;
        if (bind(s, (struct sockaddr *)&local, sizeof(local)) != 0)
            VPN_WARN("GRE raw socket bind 本机地址失败（错误 %d），可能收不到回包",
                     WSAGetLastError());
        else
            VPN_DEBUG("GRE raw socket 已绑定本机 %08x", ntohl(local.sin_addr.s_addr));
    } else {
        VPN_WARN("无法确定 GRE 的本机源地址，Windows 上可能收发异常");
    }
#endif
    (void)local;
    (void)llen;

    if (connect(s, (struct sockaddr *)&ss, sslen) != 0) {
        VPN_ERROR("GRE raw socket 绑定对端失败");
        vpn_net_close(&s);
        return VPN_ERR_IO;
    }

    /* 登记本机/对端地址，供发送时在 Windows 上构造 IP 头 */
    {
        struct sockaddr_in *peer = (struct sockaddr_in *)&ss;
        size_t i, slot = GRE_PEERS_MAX;

        for (i = 0; i < GRE_PEERS_MAX; i++) {
            if (g_gre_peers[i].sock == VPN_INVALID_SOCK) {
                slot = i;
                break;
            }
        }
        if (slot == GRE_PEERS_MAX)
            slot = 0; /* 表满：覆盖最老的（PPTP 同时只有一个 GRE 通道） */
        g_gre_peers[slot].sock = s;
        g_gre_peers[slot].src = local.sin_addr.s_addr;
        g_gre_peers[slot].dst = peer->sin_addr.s_addr;
    }

    *sock = s;
    return VPN_OK;
}

int vpn_net_raw_gre_send(vpn_sock_t sock, const void *buf, size_t len)
{
    if (sock == VPN_INVALID_SOCK || (!buf && len))
        return VPN_ERR_INVALID;

#ifdef _WIN32
    if (!g_gre_hdrincl) {
        /* 内核补头模式：只投递 GRE，协议号由 socket(47) 决定 */
        if (send((SOCKET)sock, (const char *)buf, (int)len, 0) == SOCKET_ERROR) {
            int we = WSAGetLastError();

            if (we == WSAEWOULDBLOCK || we == WSAEINTR)
                return VPN_OK;
            VPN_WARN("GRE 发送失败（错误 %d）", we);
            return VPN_ERR_IO;
        }
        return VPN_OK;
    }

    {
        uint8_t  pkt[2048];
        size_t   i, total = 20 + len;
        uint32_t src = 0, dst = 0;
        uint16_t ck;

        if (total > sizeof(pkt))
            return VPN_ERR_INVALID;

        for (i = 0; i < GRE_PEERS_MAX; i++) {
            if (g_gre_peers[i].sock == sock) {
                src = g_gre_peers[i].src;
                dst = g_gre_peers[i].dst;
                break;
            }
        }
        if (!dst) {
            VPN_WARN("GRE 发送缺少对端地址，丢弃 %zu 字节", len);
            return VPN_ERR_IO;
        }

        memset(pkt, 0, 20);
        pkt[0] = 0x45; /* IPv4, IHL=5 */
        pkt[2] = (uint8_t)(total >> 8);
        pkt[3] = (uint8_t)(total & 0xff);
        ++g_gre_ip_id;
        pkt[4] = (uint8_t)(g_gre_ip_id >> 8);
        pkt[5] = (uint8_t)(g_gre_ip_id & 0xff);
        pkt[8] = 64; /* TTL */
        pkt[9] = 47; /* GRE */
        /* src/dst 来自 sin_addr.s_addr，内存里已经是网络序字节，
         * 直接按内存拷贝；用移位拆字节会把地址写反 */
        memcpy(pkt + 12, &src, 4);
        memcpy(pkt + 16, &dst, 4);

        ck = vpn_ipv4_checksum(pkt, 20);
        pkt[10] = (uint8_t)(ck >> 8);
        pkt[11] = (uint8_t)(ck & 0xff);

        if (len)
            memcpy(pkt + 20, buf, len);

        if (send((SOCKET)sock, (const char *)pkt, (int)total, 0) == SOCKET_ERROR) {
            int we = WSAGetLastError();

            if (we == WSAEWOULDBLOCK || we == WSAEINTR)
                return VPN_OK;
            VPN_WARN("GRE 发送失败（错误 %d）：源 %u.%u.%u.%u", we,
                     ((const uint8_t *)&src)[0], ((const uint8_t *)&src)[1],
                     ((const uint8_t *)&src)[2], ((const uint8_t *)&src)[3]);
            return VPN_ERR_IO;
        }
        {
            static int logged;

            if (!logged) {
                logged = 1;
                VPN_DEBUG("GRE: 已附加 IPv4 头（20 字节，协议 47）：%u.%u.%u.%u → %u.%u.%u.%u，"
                         "总计 %zu 字节",
                         ((const uint8_t *)&src)[0], ((const uint8_t *)&src)[1],
                         ((const uint8_t *)&src)[2], ((const uint8_t *)&src)[3],
                         ((const uint8_t *)&dst)[0], ((const uint8_t *)&dst)[1],
                         ((const uint8_t *)&dst)[2], ((const uint8_t *)&dst)[3],
                         total);
            }
        }
        return VPN_OK;
    }
#else
    {
        /* Linux 的 RAW socket 由内核补 IP 头，直接投递 GRE 即可 */
        ssize_t sn = send(sock, buf, len, MSG_NOSIGNAL);

        if (sn < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                return VPN_OK;
            return VPN_ERR_IO;
        }
        return VPN_OK;
    }
#endif
}

static int wait_readable(vpn_sock_t sock, int timeout_ms)
{
#ifdef _WIN32
    fd_set rfds;
    struct timeval tv;
    FD_ZERO(&rfds);
    FD_SET((SOCKET)sock, &rfds);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int rc = select(0, &rfds, NULL, NULL, &tv);
    if (rc == 0) return VPN_ERR_TIMEOUT;
    return rc > 0 ? VPN_OK : VPN_ERR_IO;
#else
    struct pollfd pfd;
    pfd.fd = sock;
    pfd.events = POLLIN;
    pfd.revents = 0;
    int rc = poll(&pfd, 1, timeout_ms);
    if (rc == 0)
        return VPN_ERR_TIMEOUT;
    if (rc < 0)
        return errno == EINTR ? VPN_ERR_TIMEOUT : VPN_ERR_IO;
    return VPN_OK;
#endif
}

int vpn_net_read(vpn_sock_t sock, void *buf, size_t cap, int timeout_ms)
{
    if (timeout_ms > 0) {
        int rc = wait_readable(sock, timeout_ms);
        if (rc != VPN_OK)
            return rc;
    }

    for (;;) {
#ifdef _WIN32
        int n = recv((SOCKET)sock, (char *)buf, (int)cap, 0);
        if (n == SOCKET_ERROR) {
            int we = WSAGetLastError();
            if (we == WSAEWOULDBLOCK) return VPN_ERR_TIMEOUT;
            if (we == WSAEINTR) continue;
            return VPN_ERR_IO;
        }
#else
        ssize_t n = recv(sock, buf, cap, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return VPN_ERR_TIMEOUT;
            return VPN_ERR_IO;
        }
#endif
        return (int)n;
    }
}

/* 最近一次 send 失败的原始错误码，供上层诊断；0 表示没有失败过 */
static int g_last_send_errno = 0;

int vpn_net_last_send_errno(void)
{
    return g_last_send_errno;
}

int vpn_net_write_all(vpn_sock_t sock, const void *buf, size_t len, int timeout_ms)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t off = 0;

    while (off < len) {
        if (timeout_ms > 0) {
            int rc = wait_writable(sock, timeout_ms);
            if (rc != VPN_OK)
                return rc;
        }
#ifdef _WIN32
        int n = send((SOCKET)sock, (const char *)p + off, (int)(len - off), 0);
        if (n == SOCKET_ERROR) {
            int we = WSAGetLastError();
            if (we == WSAEWOULDBLOCK) continue;
            if (we == WSAEINTR) continue;
            g_last_send_errno = we;
            return VPN_ERR_IO;
        }
#else
        ssize_t n = send(sock, p + off, len - off, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            /* 留一份 errno：上层判断断网时需要区分"没路由(ENETUNREACH /
             * ENETDOWN)"和"权限(EPERM)"，否则只能看到笼统的 i/o error */
            g_last_send_errno = errno;
            return VPN_ERR_IO;
        }
#endif
        off += (size_t)n;
    }
    return (int)off;
}

int vpn_net_peer(vpn_sock_t sock, struct sockaddr_storage *out, socklen_t *outlen)
{
    *outlen = sizeof(*out);
    if (getpeername(sock, (struct sockaddr *)out, outlen) != 0)
        return VPN_ERR_IO;
    return VPN_OK;
}

int vpn_net_local_addr(vpn_sock_t sock, uint8_t out[4])
{
    struct sockaddr_storage ss;
    socklen_t len = sizeof(ss);
    const struct sockaddr_in *sin;

    if (!out)
        return VPN_ERR_INVALID;
    memset(&ss, 0, sizeof(ss));
    if (getsockname(sock, (struct sockaddr *)&ss, &len) != 0)
        return VPN_ERR_IO;
    if (ss.ss_family != AF_INET)
        return VPN_ERR_UNSUPPORTED;
    sin = (const struct sockaddr_in *)&ss;
    memcpy(out, &sin->sin_addr, 4);
    return VPN_OK;
}

int vpn_net_peer_ipv4(vpn_sock_t sock, uint8_t out[4])
{
    struct sockaddr_storage ss;
    socklen_t len = sizeof(ss);
    const struct sockaddr_in *sin;

    if (!out)
        return VPN_ERR_INVALID;
    memset(&ss, 0, sizeof(ss));
    if (getpeername(sock, (struct sockaddr *)&ss, &len) != 0)
        return VPN_ERR_IO;
    if (ss.ss_family != AF_INET)
        return VPN_ERR_UNSUPPORTED;
    sin = (const struct sockaddr_in *)&ss;
    memcpy(out, &sin->sin_addr, 4);
    return VPN_OK;
}

void vpn_net_close(vpn_sock_t *sock)
{
    if (sock && *sock != VPN_INVALID_SOCK) {
        vpn_close_sock(*sock);
        *sock = VPN_INVALID_SOCK;
    }
}

int vpn_net_set_nonblock(vpn_sock_t sock, bool nonblock)
{
#ifdef _WIN32
    u_long mode = nonblock ? 1 : 0;
    return ioctlsocket((SOCKET)sock, FIONBIO, &mode) == 0 ? VPN_OK : VPN_ERR_IO;
#else
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0)
        return VPN_ERR_IO;
    flags = nonblock ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
    return fcntl(sock, F_SETFL, flags) == 0 ? VPN_OK : VPN_ERR_IO;
#endif
}

int vpn_net_set_nodelay(vpn_sock_t sock)
{
    int one = 1;
    return setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof(one));
}

int vpn_ip_parse(const char *s, uint32_t *out_be)
{
    struct in_addr a;
    if (!s || inet_pton(AF_INET, s, &a) != 1)
        return VPN_ERR_INVALID;
    if (out_be)
        *out_be = a.s_addr; /* 网络字节序 */
    return VPN_OK;
}

const char *vpn_ip_ntoa(uint32_t be, char *buf, size_t buflen)
{
    struct in_addr a;
    a.s_addr = be;
    if (!inet_ntop(AF_INET, &a, buf, (socklen_t)buflen))
        snprintf(buf, buflen, "0.0.0.0");
    return buf;
}

uint16_t vpn_ipv4_checksum(const void *data, size_t len)
{
    const uint8_t *b = (const uint8_t *)data;
    uint32_t sum = 0;
    size_t i;

    /* 按大端 16 位累加，避免非对齐访问，返回值即"应写入头部的 16 位值" */
    for (i = 0; i + 1 < len; i += 2)
        sum += ((uint32_t)b[i] << 8) | b[i + 1];
    if (len & 1)
        sum += (uint32_t)b[len - 1] << 8;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return (uint16_t)~sum;
}
