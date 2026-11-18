/* vpn_sstp.h - SSTP 客户端（MS-SSTP）
 *
 * 层次：TCP -> TLS -> SSTP 控制报文 + PPP over HDLC-like 帧
 * 关键点（对应需求文档）：
 *   - 端口可配置（默认 443，非 443 时上层提示穿透性）
 *   - 证书验证默认开启，可切换为"忽略"，双平台同一套代码
 */
#ifndef VPN_SSTP_H
#define VPN_SSTP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "vpn_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SSTP 控制报文类型（MS-SSTP 2.2.2） */
typedef enum {
    SSTP_MSG_CALL_CONNECT_REQUEST = 1,
    SSTP_MSG_CALL_CONNECT_ACK     = 2,
    SSTP_MSG_CALL_CONNECT_NAK     = 3,
    SSTP_MSG_CALL_CONNECTED       = 4,
    SSTP_MSG_CALL_ABORT           = 5,
    SSTP_MSG_CALL_DISCONNECT      = 6,
    SSTP_MSG_CALL_DISCONNECT_ACK  = 7,
    SSTP_MSG_ECHO_REQUEST         = 8,
    SSTP_MSG_ECHO_RESPONSE        = 9
} sstp_msg_type;

/* SSTP 属性 ID */
typedef enum {
    /* MS-SSTP 2.2.4：属性 ID 从 1 开始，不是 0（实测 RouterOS 一致） */
    SSTP_ATTR_ENCAPSULATED_PROTOCOL_ID = 1,
    SSTP_ATTR_STATUS_INFO              = 2,
    SSTP_ATTR_CRYPTO_BINDING           = 3,
    SSTP_ATTR_CRYPTO_BINDING_REQUEST   = 4
} sstp_attr_id;

#define SSTP_VERSION           0x10
#define SSTP_ENCAP_PPP         0x0001
#define SSTP_STATUS_NO_ERROR   0
#define SSTP_MAX_CONTROL_LEN   4096
#define SSTP_MAX_DATA_LEN      65535

typedef struct {
    char          host[VPN_HOST_LEN];
    uint16_t      port;          /* 0 => 443 */
    vpn_cert_mode cert_mode;
    char          ca_file[VPN_PATH_LEN];
    char          ca_dir[VPN_PATH_LEN];
    char          server_name[VPN_HOST_LEN];
    bool          verify_hostname;
    int           connect_timeout_ms;
    int           io_timeout_ms;
    bool          use_crypto_binding; /* 默认 true；老服务器不支持时自动回退 */
} vpn_sstp_params;

typedef struct {
    void (*on_ppp)(void *ctx, const uint8_t *frame, size_t len);
    void (*on_connected)(void *ctx);                     /* CALL_CONNECTED 已收到 */
    void (*on_closed)(void *ctx, const char *reason);
    void *ctx;
} vpn_sstp_cbs;

typedef struct vpn_sstp vpn_sstp;

vpn_sstp *vpn_sstp_new(const vpn_sstp_params *p, const vpn_sstp_cbs *cbs);
void      vpn_sstp_free(vpn_sstp *s);

/* 建立 TCP + TLS，发送 CALL_CONNECT_REQUEST 并等待 CALL_CONNECTED */
int  vpn_sstp_open(vpn_sstp *s);
/* 发送一个 PPP 帧（自动 HDLC 封装） */
int  vpn_sstp_send_ppp(vpn_sstp *s, const uint8_t *frame, size_t len);
/* 处理一次输入（等待数据/超时），返回 VPN_OK 或错误 */
int  vpn_sstp_run_once(vpn_sstp *s, int timeout_ms);
/* 发送 ECHO_REQUEST（保活） */
int  vpn_sstp_send_echo(vpn_sstp *s);
void vpn_sstp_close(vpn_sstp *s, const char *reason);
int  vpn_sstp_fd(const vpn_sstp *s);
bool vpn_sstp_is_open(const vpn_sstp *s);

/* 提供 PPP 认证产生的 MPPE 密钥，用于 Crypto-Binding 计算 */
void vpn_sstp_set_mppe_keys(vpn_sstp *s, const uint8_t send_key[16], const uint8_t recv_key[16]);
/* 证书指纹（诊断页展示） */
const char *vpn_sstp_peer_fingerprint(vpn_sstp *s);
const char *vpn_sstp_tls_summary(vpn_sstp *s);

/* 报文编解码（单元测试可单独验证） */
int vpn_sstp_build_control(uint8_t *out, size_t cap, uint16_t msg_type,
                           const uint8_t *attrs, size_t attrs_len);
int vpn_sstp_build_attr(uint8_t *out, size_t cap, uint8_t attr_id,
                        const uint8_t *value, size_t value_len);

#ifdef __cplusplus
}
#endif

#endif /* VPN_SSTP_H */
