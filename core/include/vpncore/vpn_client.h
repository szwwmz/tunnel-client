/* vpn_client.h - 连接生命周期编排（核心层对外唯一入口）
 *
 * 职责：
 *   1. 按配置选择传输层（SSTP / L2TP / PPTP）
 *   2. 把传输层与共享 PPP 栈交叉接线
 *   3. TUN 转发线程（IP 包 <-> PPP）
 *   4. 保活、断线重连、状态回调、统计
 *
 * 平台外壳只需：准备 TUN ops、填配置、注册回调、start/stop。
 */
#ifndef VPN_CLIENT_H
#define VPN_CLIENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "vpn_config.h"
#include "vpn_tun.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    VPN_STATE_IDLE = 0,
    VPN_STATE_CONNECTING,     /* TCP/UDP + TLS + SSTP/L2TP 控制通道 */
    VPN_STATE_AUTHENTICATING, /* PPP LCP + 认证 */
    VPN_STATE_CONNECTED,
    VPN_STATE_RECONNECTING,
    VPN_STATE_DISCONNECTED,
    VPN_STATE_FAILED
} vpn_state;

typedef struct {
    uint64_t rx_bytes;   /* 服务器 -> 本机 */
    uint64_t tx_bytes;   /* 本机 -> 服务器 */
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t dropped;
    uint32_t reconnects;
    int64_t  connected_since_ms;
    uint32_t rtt_ms;
    char     local_ip[32];
    char     peer_ip[32];
    char     dns1[32];
    char     dns2[32];
    char     cipher[128];
    char     cert_fingerprint[96];
} vpn_stats;

typedef struct {
    void (*on_state)(void *ctx, vpn_state state, const char *detail);
    void (*on_stats)(void *ctx, const vpn_stats *stats);
    void *ctx;
} vpn_client_cbs;

typedef struct vpn_client vpn_client;

/* tun 可以为 NULL：此时不做 IP 转发（仅验证协议连通性，CLI 的 --no-tun 模式） */
vpn_client *vpn_client_new(const vpn_config *cfg, const vpn_tun_ops *tun,
                           const vpn_client_cbs *cbs);
int         vpn_client_free(vpn_client *c);   /* 0=已释放，非 0=线程未退出、故意泄漏 */

int  vpn_client_start(vpn_client *c);   /* 后台线程运行，非阻塞 */
void vpn_client_stop(vpn_client *c);    /* 请求停止并等待线程退出 */
int  vpn_client_wait(vpn_client *c, int timeout_ms); /* 等待连接建立 */

/* 运行期挂接/摘除 TUN（Android 需要：PPP 协商拿到地址后才能 establish()）。
 * attach 只在当前没有 TUN 时成功（否则返回 VPN_ERR_BUSY），所有权转移给核心；
 * detach 请在 vpn_client_stop() 之后调用。 */
int  vpn_client_attach_tun(vpn_client *c, const vpn_tun_ops *tun);
void vpn_client_detach_tun(vpn_client *c);

vpn_state vpn_client_get_state(vpn_client *c);
void      vpn_client_get_stats(vpn_client *c, vpn_stats *out);
const char *vpn_state_name(vpn_state st);

/* 单次阻塞连接（CLI/测试用，内部就是 start+wait） */
int vpn_client_connect_blocking(vpn_client *c, int timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* VPN_CLIENT_H */
