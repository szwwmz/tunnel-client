/* vpn_ppp.h - PPP 协议栈（共享核心）
 *
 * SSTP = TLS 上的 PPP；L2TP = UDP 上的 PPP。两条路径在核心层汇聚到同一套
 * LCP / CHAP / MS-CHAPv2 / PAP / IPCP 状态机，保证双平台认证行为一致。
 *
 * 本模块只处理"未封装"的 PPP 帧（协议号 + 载荷），HDLC 成帧由 SSTP 层负责，
 * L2TP 层直接透传（RFC 1661 over L2TP 无 HDLC）。
 */
#ifndef VPN_PPP_H
#define VPN_PPP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "vpn_config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PPP_PROTO_IP      0x0021
#define PPP_PROTO_IPV6    0x0057
#define PPP_PROTO_IPCP    0x8021
#define PPP_PROTO_IPV6CP  0x8057
#define PPP_PROTO_LCP     0xc021
#define PPP_PROTO_PAP     0xc023
#define PPP_PROTO_CHAP    0xc223
#define PPP_PROTO_CCP     0x80fd

#define PPP_HEADER_LEN    4 /* addr + ctrl + proto(2) */

/* LCP / IPCP 使用的 FSM 状态（RFC 1661 §4.1） */
typedef enum {
    PPP_FSM_INITIAL = 0,
    PPP_FSM_STARTING,
    PPP_FSM_CLOSED,
    PPP_FSM_STOPPED,
    PPP_FSM_CLOSING,
    PPP_FSM_STOPPING,
    PPP_FSM_REQ_SENT,
    PPP_FSM_ACK_RCVD,
    PPP_FSM_ACK_SENT,
    PPP_FSM_OPEN
} ppp_fsm_state;

typedef struct {
    vpn_auth_mode auth;      /* AUTO: MS-CHAPv2 -> CHAP -> PAP 逐级降级 */
    char          username[128];
    char          password[256];
    uint32_t      mtu;       /* 0 = 1400 */
    uint32_t      mru;
    char          local_ip[64]; /* 空 = 由服务器分配 */
    char          dns1[64];
    char          dns2[64];
    bool          enable_ipv6cp; /* 可选 */
} ppp_config;

typedef struct {
    uint32_t local_ip;  /* 主机字节序 */
    uint32_t peer_ip;
    uint32_t dns1;
    uint32_t dns2;
    uint32_t mtu;
    bool     using_mschapv2;
} ppp_net_info;

typedef struct {
    /* 发送一个 PPP 帧（协议号 + 载荷，不含 HDLC 封装/FCS） */
    void (*send)(void *ctx, const uint8_t *frame, size_t len);
    /* IPCP 完成，可以开始收发 IP 包 */
    void (*up)(void *ctx, const ppp_net_info *info);
    /* 收到一个 IP 包（写出到 TUN） */
    void (*ip)(void *ctx, const uint8_t *pkt, size_t len);
    void (*auth_failed)(void *ctx, const char *reason);
    void (*closed)(void *ctx, const char *reason);
    void *ctx;
} ppp_callbacks;

typedef struct vpn_ppp vpn_ppp;

vpn_ppp *vpn_ppp_new(const ppp_config *cfg, const ppp_callbacks *cbs);
void     vpn_ppp_free(vpn_ppp *p);

void vpn_ppp_start(vpn_ppp *p, int64_t now_ms);
/* 输入一个完整 PPP 帧（协议号起始） */
void vpn_ppp_input(vpn_ppp *p, const uint8_t *frame, size_t len, int64_t now_ms);
/* 驱动重传/超时定时器 */
void vpn_ppp_tick(vpn_ppp *p, int64_t now_ms);
/* 发送一个 IP 包（自动加 PPP 协议头） */
int  vpn_ppp_send_ip(vpn_ppp *p, const uint8_t *pkt, size_t len);
bool vpn_ppp_is_up(const vpn_ppp *p);
void vpn_ppp_close(vpn_ppp *p, const char *reason);

/* 供 SSTP Crypto-Binding 使用的 MPPE 密钥（仅 MS-CHAPv2 有效） */
bool vpn_ppp_mppe_keys(const vpn_ppp *p, uint8_t send_key[16], uint8_t recv_key[16]);
bool vpn_ppp_has_session_key(const vpn_ppp *p);
void vpn_ppp_get_net(const vpn_ppp *p, ppp_net_info *out);
const char *vpn_ppp_fsm_name(ppp_fsm_state st);
/* 调试：导出 LCP/IPCP 当前状态与统计 */
void vpn_ppp_dump(vpn_ppp *p, char *out, size_t outlen);

#ifdef __cplusplus
}
#endif

#endif /* VPN_PPP_H */
