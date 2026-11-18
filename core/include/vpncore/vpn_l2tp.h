/* vpn_l2tp.h - L2TP 客户端（RFC 2661，voluntary tunnel / LAC 模式）
 *
 * 流程：SCCRQ -> SCCRP -> SCCCN -> ICRQ -> ICRP -> ICCN，随后在数据通道里
 * 透传 PPP 帧（无 HDLC 封装）。
 *
 * IPsec：use_ipsec 且 psk 非空时，本模块自己跑 IKEv1 主模式 + Quick Mode，
 * 之后所有 L2TP 报文都经 ESP transport（NAT-T UDP/4500 封装）收发，
 * 不依赖系统 strongSwan，也不需要 root（不走 IP 协议 50）。
 */
#ifndef VPN_L2TP_H
#define VPN_L2TP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "vpn_config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define L2TP_PORT_DEFAULT 1701

typedef struct {
    char     host[VPN_HOST_LEN];
    uint16_t port;                       /* 0 => 1701 */
    bool     use_ipsec;                  /* MikroTik use-ipsec=yes */
    char     psk[128];                   /* 非空则在此建立 IPsec 通道 */
    int      connect_timeout_ms;
    int      io_timeout_ms;
    char     tunnel_name[64];            /* 显示在服务器会话列表 */
    uint16_t recv_window;
} vpn_l2tp_params;

typedef struct {
    void (*on_ppp)(void *ctx, const uint8_t *frame, size_t len);
    void (*on_connected)(void *ctx);     /* ICCN 已发送，PPP 可开始 */
    void (*on_closed)(void *ctx, const char *reason);
    void *ctx;
} vpn_l2tp_cbs;

typedef struct vpn_l2tp vpn_l2tp;

vpn_l2tp *vpn_l2tp_new(const vpn_l2tp_params *p, const vpn_l2tp_cbs *cbs);
void      vpn_l2tp_free(vpn_l2tp *l);

int  vpn_l2tp_open(vpn_l2tp *l);
int  vpn_l2tp_send_ppp(vpn_l2tp *l, const uint8_t *frame, size_t len);
int  vpn_l2tp_run_once(vpn_l2tp *l, int timeout_ms);
int  vpn_l2tp_send_hello(vpn_l2tp *l);
void vpn_l2tp_close(vpn_l2tp *l, const char *reason);
bool vpn_l2tp_is_open(const vpn_l2tp *l);
int  vpn_l2tp_fd(const vpn_l2tp *l);

/* 调试信息：tunnel_id / session_id / ns,nr */
void vpn_l2tp_info(const vpn_l2tp *l, char *out, size_t outlen);

/* 报文构造（单元测试用） */
int vpn_l2tp_build_sccrq(uint8_t *out, size_t cap, uint16_t tunnel_id,
                         uint16_t recv_window, const char *hostname);
int vpn_l2tp_build_icrq(uint8_t *out, size_t cap, uint16_t tunnel_id, uint16_t session_id);
int vpn_l2tp_build_iccn(uint8_t *out, size_t cap, uint16_t tunnel_id, uint16_t session_id);

#ifdef __cplusplus
}
#endif

#endif /* VPN_L2TP_H */
