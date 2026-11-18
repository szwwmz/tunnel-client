/* SPDX-License-Identifier: LicenseRef-Proprietary
   Copyright (c) 2026 wwm-spec. All rights reserved.
 */

/* vpn_config.h - 跨平台连接配置
 *
 * 字段与 Android/Windows 的 UI 一一对应：服务器、端口（SSTP 可自定义）、
 * 认证、证书策略、路由分流、DNS、保活/重连。
 */
#ifndef VPN_CONFIG_H
#define VPN_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    VPN_PROTO_SSTP = 0, /* P0 首要：TLS/443，可自定义端口 */
    VPN_PROTO_L2TP = 1, /* P1：UDP 1701 + IPsec */
    VPN_PROTO_PPTP = 2  /* P2 兼容：TCP 1723，风险提示 */
} vpn_proto;

typedef enum {
    VPN_CERT_VERIFY = 0, /* 默认：校验证书链 + 主机名 */
    VPN_CERT_IGNORE = 1  /* 高级选项：不校验（UI 必须给风险提示） */
} vpn_cert_mode;

typedef enum {
    VPN_AUTH_MSCHAPV2 = 0, /* MikroTik SSTP/L2TP 常用 */
    VPN_AUTH_CHAP     = 1,
    VPN_AUTH_PAP      = 2,
    VPN_AUTH_AUTO     = 3   /* 优先 MS-CHAPv2，服务器拒绝则降级 CHAP -> PAP */
} vpn_auth_mode;

#define VPN_MAX_ROUTES 16
#define VPN_HOST_LEN   256
#define VPN_PATH_LEN   512

typedef struct {
    vpn_proto      proto;
    char           host[VPN_HOST_LEN]; /* 服务器地址或域名 */
    uint16_t       port;               /* 0 = 协议默认端口 */
    char           username[128];
    char           password[256];
    char           psk[128];           /* L2TP/IPsec 预共享密钥 */

    vpn_auth_mode  auth;
    vpn_cert_mode  cert_mode;
    char           ca_file[VPN_PATH_LEN]; /* 自定义 CA（PEM），可空 */
    char           ca_dir[VPN_PATH_LEN];
    char           server_name[VPN_HOST_LEN]; /* SNI/证书校验名，空=host */
    bool           verify_hostname;

    uint32_t       mtu;  /* 0 = 1400 */
    uint32_t       mru;

    /* IPCP 期望地址，空/0 = 由服务器分配 */
    char           local_ip[64];
    char           remote_ip[64];
    char           dns1[64];
    char           dns2[64];

    bool           use_default_route;         /* 全局路由 0.0.0.0/0 */
    char           routes[VPN_MAX_ROUTES][32];/* 分流网段 */
    int            route_count;

    int            connect_timeout_s;
    int            io_timeout_s;
    int            keepalive_interval_s; /* 0 = 关闭 */
    int            reconnect_delay_s;
    int            max_retries;          /* -1 = 无限重连 */
    bool           auto_reconnect;       /* 断开后自动重连，默认开启 */

    int            log_level;            /* vpn_log_level */
} vpn_config;

void        vpn_config_init(vpn_config *cfg);
const char *vpn_proto_name(vpn_proto p);
int         vpn_proto_from_name(const char *name, vpn_proto *out);
uint16_t    vpn_proto_default_port(vpn_proto p);
const char *vpn_cert_mode_name(vpn_cert_mode m);
const char *vpn_auth_mode_name(vpn_auth_mode m);

/* 配置校验，返回 VPN_OK 或 VPN_ERR_CONFIG，err 写入可读原因 */
int vpn_config_validate(const vpn_config *cfg, char *err, size_t errlen);

/* 端口是否会影响 SSTP 穿透性（非 443） */
bool vpn_config_port_needs_hint(const vpn_config *cfg);

#ifdef __cplusplus
}
#endif

#endif /* VPN_CONFIG_H */
