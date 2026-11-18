/* vpn_net.h - socket / 解析 / 超时读写抽象
 *
 * 同时服务 SSTP(TCP) 与 L2TP(UDP)，统一在内部处理 EINTR/EAGAIN 与超时。
 */
#ifndef VPN_NET_H
#define VPN_NET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef int vpn_sock_t;
#define VPN_INVALID_SOCK (-1)
#else
#include <netinet/in.h>
#include <sys/socket.h>
typedef int vpn_sock_t;
#define VPN_INVALID_SOCK (-1)
#endif

#ifdef __cplusplus
extern "C" {
#endif

int  vpn_net_init(void);   /* Windows 下为 WSAStartup，其它平台空实现 */
void vpn_net_cleanup(void);

/* 解析 host(:port) -> sockaddr；port 由调用方给出（0 表示使用内置默认） */
int vpn_net_resolve(const char *host, uint16_t port,
                    struct sockaddr_storage *out, socklen_t *outlen);

/* TCP 连接，成功返回 0 并写 *sock；timeout_ms<=0 表示使用系统默认 */
int vpn_net_tcp_connect(const char *host, uint16_t port, int timeout_ms, vpn_sock_t *sock);
/* UDP socket 连到对端（使用 connect 以便直接 send/recv） */
int vpn_net_udp_connect(const char *host, uint16_t port, vpn_sock_t *sock);
/* 先绑定本地固定端口再连接（L2TP 必须用 1701 作源端口） */
int vpn_net_udp_connect_local(uint16_t local_port, const char *host, uint16_t port,
                              vpn_sock_t *sock);

/* 原始 ESP socket（IP 协议 50），connect 到对端后可直接 send/recv。
 * 用于用户态实现 transport 模式 ESP：不需要 NAT-T 时对端内核只接受协议 50。
 * 仅 Linux/Unix root（或有 CAP_NET_RAW）可用，其它情况返回 VPN_ERR_IO。
 * 注意：该 socket 收包时【包含 IP 头】，调用方需自行跳过。 */
int vpn_net_raw_esp_connect(const char *host, vpn_sock_t *sock);

/* PPTP 的 GRE(47) raw socket：需要管理员/root 权限，失败返回 VPN_ERR_UNSUPPORTED */
int vpn_net_raw_gre_connect(const char *host, vpn_sock_t *sock);

/* 发送一个 GRE 帧（原始数据，不含 IP 头）。
 * Windows 的 RAW socket 不会替应用补 IPv4 头——内核会把首字节当成 IP
 * 版本号解析，非 4 的包被静默丢弃（send 仍返回成功），这正是
 * 「GRE 已发出但服务器一个包都收不到」的根因。此函数在 Windows 上
 * 自动构造 IP 头，Linux 上直接投递。 */
int vpn_net_raw_gre_send(vpn_sock_t sock, const void *buf, size_t len);

/* 带超时的读；返回 >0 字节数，0 对端关闭，<0 错误（VPN_ERR_TIMEOUT 表示超时） */
int vpn_net_read(vpn_sock_t sock, void *buf, size_t cap, int timeout_ms);
int vpn_net_write_all(vpn_sock_t sock, const void *buf, size_t len, int timeout_ms);

/* peer 地址（UDP 收包后需要判断来源） */
int vpn_net_peer(vpn_sock_t sock, struct sockaddr_storage *out, socklen_t *outlen);

/* 本端出口地址（IPv4 点分写入 out[4]）。已 connect 的 socket 上调用。 */
int vpn_net_local_addr(vpn_sock_t sock, uint8_t out[4]);
/* 对端地址（IPv4 写入 out[4]）。已 connect 的 socket 上调用。 */
int vpn_net_peer_ipv4(vpn_sock_t sock, uint8_t out[4]);

/* 平台钩子（Android）：VpnService.protect() 把 socket 绑定到物理网卡，
 * 避免隧道建立后通往服务器的连接被自己的路由捕获。返回 0 = 成功。 */
typedef int (*vpn_protect_fn)(void *ctx, int fd);
void vpn_net_set_protect(vpn_protect_fn fn, void *ctx);

void vpn_net_close(vpn_sock_t *sock);
int  vpn_net_set_nonblock(vpn_sock_t sock, bool nonblock);
int  vpn_net_set_nodelay(vpn_sock_t sock);
int  vpn_net_error(void);   /* 最近的 socket 错误码 */
int  vpn_net_last_send_errno(void);  /* 最近一次 send 失败的原生错误码 */

/* 工具：点分十进制/字符串互转 */
int  vpn_ip_parse(const char *s, uint32_t *out_be);
const char *vpn_ip_ntoa(uint32_t be, char *buf, size_t buflen);

/* 计算 IP 头校验和（返回网络字节序） */
uint16_t vpn_ipv4_checksum(const void *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* VPN_NET_H */
