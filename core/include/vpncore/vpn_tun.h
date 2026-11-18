/* vpn_tun.h - 虚拟网卡抽象
 *
 * 平台差异完全收敛在 vpn_tun_ops：
 *   - Android: VpnService.establish() 得到 ParcelFileDescriptor，dup fd 后交给
 *              vpn_tun_from_fd()，读写就是 read/write 系统调用。
 *   - Windows: Wintun 会话句柄用 P/Invoke 读写，由 C# 侧实现 ops 回调传入。
 *   - Linux CLI: /dev/net/tun (TUN 模式)。
 */
#ifndef VPN_TUN_H
#define VPN_TUN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    /* 返回读到的字节数；0 表示无数据；<0 错误（-4 超时） */
    int  (*read)(void *ctx, void *buf, size_t cap, int timeout_ms);
    int  (*write)(void *ctx, const void *buf, size_t len);
    void (*destroy)(void *ctx);
    void *ctx;
} vpn_tun_ops;

/* 由文件描述符构造 ops（Android / Linux）。owns_fd=true 时 destroy 会 close(fd) */
int vpn_tun_ops_from_fd(int fd, bool owns_fd, vpn_tun_ops *out);

/* Linux/Android 通用：打开 TUN 设备（需要 root 或 Android VpnService 之外不可用） */
int vpn_tun_open(const char *dev_name, uint32_t mtu, char *name_out, size_t name_len,
                 vpn_tun_ops *out);

/* 配置接口地址/掩码/MTU（Linux ioctl；Android 由 VpnService.Builder 负责，可跳过） */
int vpn_tun_configure(const char *dev_name, uint32_t local_ip, uint32_t peer_ip,
                      uint32_t netmask, uint32_t mtu);

int vpn_tun_add_route(const char *dev_name, uint32_t dst, uint32_t mask);
/* 带网关的路由（VPN 场景：先给服务器 IP 加一条走原网关的 /32 主机路由，避免回路） */
int vpn_tun_add_route_via(const char *dev_name, uint32_t dst, uint32_t mask,
                          uint32_t gateway);
/* 带优先级的同上网关路由：metric 越大优先级越低（默认 add_route_via 用 5）
 * 注意：dst 与 mask 均传【网络序】（如 htonl(0xFF000000) 表示 /8） */
int vpn_tun_add_route_metric(const char *dev_name, uint32_t dst, uint32_t mask,
                             uint32_t gateway, int metric);
/* 删除经该接口的路由（断开时清理，避免残留影响本机联网） */
int vpn_tun_del_route(const char *dev_name, uint32_t dst, uint32_t mask);
int vpn_tun_set_dns(const char *dev_name, uint32_t dns1, uint32_t dns2);
/* 设置 DNS 并把接口度量压到 metric，让系统优先用这台 DNS（metric<=0 则不调整） */
int vpn_tun_set_dns_pref(const char *dev_name, uint32_t dns1, uint32_t dns2, int metric);
/* 清空该接口的 DNS 并把度量还原为自动（断开时调用） */
int vpn_tun_clear_dns(const char *dev_name);

#ifdef __cplusplus
}
#endif

#endif /* VPN_TUN_H */
