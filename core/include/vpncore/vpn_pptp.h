/* SPDX-License-Identifier: LicenseRef-Proprietary
   Copyright (c) 2026 wwm-spec. All rights reserved.
 */

/* vpn_pptp.h - PPTP 兼容实现（RFC 2637，P2 优先级）
 *
 * 安全提示：PPTP 的 MPPE 已被攻破，且部分运营商封锁 GRE(47)。核心层允许实现，
 * 但 UI 层必须在连接前给出风险确认（见 vpn_client 的 risk_ack 字段）。
 *
 * 限制：GRE 需要 RAW socket 权限。Android 非 root 环境不可用，调用时会返回
 * VPN_ERR_UNSUPPORTED；Windows 需要管理员权限的服务（或 WFP 驱动）。
 */
#ifndef VPN_PPTP_H
#define VPN_PPTP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "vpn_config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PPTP_PORT_DEFAULT 1723
#define PPTP_GRE_PROTO    47

/* 控制报文类型（RFC 2637 §2.1） */
typedef enum {
    PPTP_MSG_START_CTRL_CONN_REQ = 1,
    PPTP_MSG_START_CTRL_CONN_REPLY = 2,
    PPTP_MSG_STOP_CTRL_CONN_REQ = 3,
    PPTP_MSG_STOP_CTRL_CONN_REPLY = 4,
    PPTP_MSG_ECHO_REQ = 5,
    PPTP_MSG_ECHO_REPLY = 6,
    PPTP_MSG_OUTGOING_CALL_REQ = 7,
    PPTP_MSG_OUTGOING_CALL_REPLY = 8,
    PPTP_MSG_INCOMING_CALL_REQ = 9,
    PPTP_MSG_INCOMING_CALL_REPLY = 10,
    PPTP_MSG_CALL_CLEAR_REQ = 12,
    PPTP_MSG_CALL_DISCONNECT_NOTIFY = 13,
    PPTP_MSG_WAN_ERROR_NOTIFY = 14,
    PPTP_MSG_SET_LINK_INFO = 15
} pptp_msg_type;

typedef struct {
    char     host[VPN_HOST_LEN];
    uint16_t port;                /* 0 => 1723 */
    uint32_t call_id;             /* 客户端本地 call id */
    int      connect_timeout_ms;
    int      io_timeout_ms;
    uint32_t framming_cap;        /* 0 = 使用默认 async framing */
} vpn_pptp_params;

typedef struct {
    void (*on_ppp)(void *ctx, const uint8_t *frame, size_t len);
    void (*on_connected)(void *ctx);
    void (*on_closed)(void *ctx, const char *reason);
    void *ctx;
} vpn_pptp_cbs;

typedef struct vpn_pptp vpn_pptp;

vpn_pptp *vpn_pptp_new(const vpn_pptp_params *p, const vpn_pptp_cbs *cbs);
void      vpn_pptp_free(vpn_pptp *p);

int  vpn_pptp_open(vpn_pptp *p);   /* TCP 1723 控制连接 + Outgoing Call */
int  vpn_pptp_send_ppp(vpn_pptp *p, const uint8_t *frame, size_t len);
int  vpn_pptp_run_once(vpn_pptp *p, int timeout_ms);
void vpn_pptp_close(vpn_pptp *p, const char *reason);
bool vpn_pptp_is_open(const vpn_pptp *p);

/* GRE 封装（RFC 2637 §4.1）：把 PPP 帧封成 GRE 包 */
int vpn_pptp_gre_encapsulate(uint32_t call_id, uint32_t seq, const uint8_t *ppp, size_t len,
                             uint8_t *out, size_t cap);
int vpn_pptp_gre_decapsulate(const uint8_t *gre, size_t len,
                             uint32_t expect_call_id, uint8_t *out, size_t cap);
/* 当前平台是否支持 PPTP（GRE 权限） */
bool vpn_pptp_supported(void);

#ifdef __cplusplus
}
#endif

#endif /* VPN_PPTP_H */
