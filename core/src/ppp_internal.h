/* ppp_internal.h - PPP 栈模块内部结构（不对外暴露） */
#ifndef PPP_INTERNAL_H
#define PPP_INTERNAL_H

#include "vpncore/vpn_buf.h"
#include "vpncore/vpn_crypto.h"
#include "vpncore/vpn_error.h"
#include "vpncore/vpn_log.h"
#include "vpncore/vpn_net.h"
#include "vpncore/vpn_platform.h"
#include "vpncore/vpn_ppp.h"

/* ---- PPP 报文码 ---- */
#define PPP_CODE_CONF_REQ  1
#define PPP_CODE_CONF_ACK  2
#define PPP_CODE_CONF_NAK  3
#define PPP_CODE_CONF_REJ  4
#define PPP_CODE_TERM_REQ  5
#define PPP_CODE_TERM_ACK  6
#define PPP_CODE_CODE_REJ  7
#define PPP_CODE_PROTO_REJ 8
#define PPP_CODE_ECHO_REQ  9
#define PPP_CODE_ECHO_REPLY 10
#define PPP_CODE_DISC_REQ  11

/* ---- LCP 选项 ---- */
#define LCP_OPT_MRU       1
#define LCP_OPT_ACCM      2
#define LCP_OPT_AUTH      3
#define LCP_OPT_QUALITY   4
#define LCP_OPT_MAGIC     5
#define LCP_OPT_PFC       7
#define LCP_OPT_ACFC      8

/* ---- IPCP 选项 ---- */
#define IPCP_OPT_ADDR     3
#define IPCP_OPT_DNS1     129
#define IPCP_OPT_DNS2     131

/* ---- CHAP 算法 ---- */
#define CHAP_ALG_MD5      0x05
/* CHAP 报文 Value 里的算法字节（RFC 2759） */
#define CHAP_ALG_MSCHAPV1 0x80
#define CHAP_ALG_MSCHAPV2 0xC9
/* LCP 认证选项里的算法字节：0x80=MS-CHAPv1, 0x81=MS-CHAPv2 */
#define CHAP_LCP_ALG_MSCHAPV1 0x80
#define CHAP_LCP_ALG_MSCHAPV2 0x81

#define PPP_MAX_FRAME     1504
#define PPP_MAX_OPTS      128
#define PPP_RESTART_MS    3000
#define PPP_MAX_CONFREQ   10
#define PPP_MAX_FAILURE   5
#define PPP_MAX_TERM      2

typedef struct {
    ppp_fsm_state state;
    uint8_t       id;
    int           retries;           /* Configure-Request 重传次数 */
    int64_t       last_tx_ms;
    int64_t       last_rx_ms;
    int64_t       opened_ms;
    bool          we_acked;          /* 对端已 Ack 我们的 Conf-Req */
    bool          peer_acked;        /* 我们已 Ack 对端的 Conf-Req */
    bool          pending_ack;       /* 还需重发 Ack */
    uint8_t       pending_ack_id;
    uint8_t       pending_ack_buf[PPP_MAX_OPTS];
    size_t        pending_ack_len;
    int           term_retries;
    uint32_t      rx_count;
    uint32_t      tx_count;
} ppp_fsm;

struct vpn_ppp {
    ppp_config   cfg;
    ppp_callbacks cbs;

    ppp_fsm      lcp;
    ppp_fsm      ipcp;

    /* LCP 协商结果 */
    uint32_t     peer_mru;
    uint32_t     peer_accm;
    uint32_t     magic;
    uint32_t     peer_magic;
    bool         peer_pfc;
    bool         peer_acfc;
    bool         lcp_pfc;
    bool         lcp_acfc;

    /* 认证 */
    bool         auth_required;
    uint16_t     auth_proto;      /* 0xc023 PAP / 0xc223 CHAP */
    uint8_t      chap_alg;
    char         auth_name[256];
    uint8_t      chap_id;
    uint8_t      auth_challenge[64];
    uint8_t      auth_challenge_len;
    uint8_t      peer_challenge[16];
    uint8_t      nt_hash[16];
    uint8_t      mppe_send_key[16];
    uint8_t      mppe_recv_key[16];
    bool         has_mppe;
    bool         auth_done;
    bool         auth_started;
    ppp_net_info net;

    /* IPCP 协商中的候选值（收到 Nak 后重发） */
    uint32_t     want_local_ip;
    uint32_t     want_dns1;
    uint32_t     want_dns2;
    bool         ipcp_no_dns1;    /* 服务器 Reject 了 DNS1 选项 */
    bool         ipcp_no_dns2;    /* 服务器 Reject 了 DNS2 选项 */

    bool         up;
    bool         closed;
    int64_t      last_keepalive_ms;
    uint32_t     echo_id;
    uint8_t      misc_id;         /* Protocol-Reject 等主动报文用的独立 ID */

    uint8_t      txbuf[PPP_MAX_FRAME + 32];
};

/* ---- 内部工具 ---- */
void ppp_send_frame(vpn_ppp *p, uint16_t proto, const uint8_t *payload, size_t len);
void ppp_send_fsm(vpn_ppp *p, ppp_fsm *fsm, uint16_t proto, uint8_t code,
                  uint8_t id, const uint8_t *data, size_t len);

void ppp_fsm_init(ppp_fsm *fsm);
void ppp_fsm_open(vpn_ppp *p, ppp_fsm *fsm, uint16_t proto);
void ppp_fsm_close(vpn_ppp *p, ppp_fsm *fsm, uint16_t proto, const char *reason);
void ppp_fsm_tick(vpn_ppp *p, ppp_fsm *fsm, uint16_t proto, int64_t now);
void ppp_fsm_rx_ack(vpn_ppp *p, ppp_fsm *fsm, uint8_t id, bool ipcp);
void ppp_fsm_rx_conf_req(vpn_ppp *p, ppp_fsm *fsm, uint16_t proto, uint8_t id,
                         const uint8_t *opts, size_t len);
void ppp_fsm_rx_term_req(vpn_ppp *p, ppp_fsm *fsm, uint16_t proto, uint8_t id);

int  ppp_build_conf_req(vpn_ppp *p, ppp_fsm *fsm, uint16_t proto, uint8_t *buf, size_t cap);
int  ppp_process_conf_req(vpn_ppp *p, uint16_t proto, const uint8_t *opts, size_t len,
                          uint8_t *out, size_t cap, size_t *out_len, bool *reject);

/* 认证子模块 */
void ppp_auth_start(vpn_ppp *p);
void ppp_auth_rx_chap(vpn_ppp *p, const uint8_t *payload, size_t len);
void ppp_auth_rx_pap(vpn_ppp *p, const uint8_t *payload, size_t len);
void ppp_auth_finish_ok(vpn_ppp *p);
void ppp_auth_finish_fail(vpn_ppp *p, const char *reason);
void ppp_send_chap_response(vpn_ppp *p);
void ppp_start_ipcp(vpn_ppp *p);

#endif /* PPP_INTERNAL_H */
