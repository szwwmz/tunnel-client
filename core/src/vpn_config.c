/* SPDX-License-Identifier: LicenseRef-Proprietary
   Copyright (c) 2026 wwm-spec. All rights reserved.
 */

#include "vpncore/vpn_config.h"
#include "vpncore/vpn_error.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>

void vpn_config_init(vpn_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->proto = VPN_PROTO_SSTP;
    cfg->port = 0;
    cfg->auth = VPN_AUTH_AUTO;
    cfg->cert_mode = VPN_CERT_VERIFY;
    cfg->verify_hostname = true;
    cfg->mtu = 1400;
    cfg->mru = 1400;
    strcpy(cfg->dns1, "0.0.0.0"); /* 0 = 由服务器下发 */
    strcpy(cfg->dns2, "0.0.0.0");
    cfg->use_default_route = true;
    cfg->connect_timeout_s = 15;
    cfg->io_timeout_s = 30;
    cfg->keepalive_interval_s = 30;
    cfg->reconnect_delay_s = 5;
    cfg->max_retries = -1;      /* 默认无限重连，配合 auto_reconnect */
    cfg->auto_reconnect = true; /* 断开自动重连默认开启 */
    cfg->log_level = 2; /* INFO */
}

const char *vpn_proto_name(vpn_proto p)
{
    switch (p) {
    case VPN_PROTO_SSTP: return "sstp";
    case VPN_PROTO_L2TP: return "l2tp";
    case VPN_PROTO_PPTP: return "pptp";
    default:             return "unknown";
    }
}

int vpn_proto_from_name(const char *name, vpn_proto *out)
{
    if (!name || !out)
        return VPN_ERR_INVALID;
    if (!strcasecmp(name, "sstp")) { *out = VPN_PROTO_SSTP; return VPN_OK; }
    if (!strcasecmp(name, "l2tp") || !strcasecmp(name, "l2tp/ipsec")) { *out = VPN_PROTO_L2TP; return VPN_OK; }
    if (!strcasecmp(name, "pptp")) { *out = VPN_PROTO_PPTP; return VPN_OK; }
    return VPN_ERR_INVALID;
}

uint16_t vpn_proto_default_port(vpn_proto p)
{
    switch (p) {
    case VPN_PROTO_SSTP: return 443;
    case VPN_PROTO_L2TP: return 1701;
    case VPN_PROTO_PPTP: return 1723;
    default:             return 443;
    }
}

const char *vpn_cert_mode_name(vpn_cert_mode m)
{
    return m == VPN_CERT_IGNORE ? "ignore" : "verify";
}

const char *vpn_auth_mode_name(vpn_auth_mode m)
{
    switch (m) {
    case VPN_AUTH_MSCHAPV2: return "mschapv2";
    case VPN_AUTH_CHAP:     return "chap";
    case VPN_AUTH_PAP:      return "pap";
    case VPN_AUTH_AUTO:     return "auto";
    default:                return "unknown";
    }
}

bool vpn_config_port_needs_hint(const vpn_config *cfg)
{
    if (!cfg)
        return false;
    /* 只有 SSTP 才吃"伪装成 443 提高穿透性"这套建议：
     * L2TP(UDP/1701) 与 PPTP(TCP/1723) 是固定标准端口，改成 443 根本连不上 */
    if (cfg->proto != VPN_PROTO_SSTP)
        return false;
    uint16_t port = cfg->port ? cfg->port : vpn_proto_default_port(cfg->proto);
    return port != 443;
}

int vpn_config_validate(const vpn_config *cfg, char *err, size_t errlen)
{
    if (!cfg) {
        if (err) snprintf(err, errlen, "配置为空");
        return VPN_ERR_CONFIG;
    }
    if (cfg->host[0] == '\0') {
        if (err) snprintf(err, errlen, "服务器地址不能为空");
        return VPN_ERR_CONFIG;
    }
    if (cfg->username[0] == '\0') {
        if (err) snprintf(err, errlen, "用户名不能为空");
        return VPN_ERR_CONFIG;
    }
    if (cfg->auth == VPN_AUTH_PAP && cfg->proto != VPN_PROTO_SSTP && cfg->proto != VPN_PROTO_L2TP) {
        if (err) snprintf(err, errlen, "PAP 不适用于 %s", vpn_proto_name(cfg->proto));
        return VPN_ERR_CONFIG;
    }
    if (cfg->proto == VPN_PROTO_PPTP && cfg->password[0] == '\0') {
        if (err) snprintf(err, errlen, "PPTP 需要密码（MS-CHAPv2/MPPE）");
        return VPN_ERR_CONFIG;
    }
    if (cfg->mtu && (cfg->mtu < 576 || cfg->mtu > 1500)) {
        if (err) snprintf(err, errlen, "MTU 需在 576~1500 之间");
        return VPN_ERR_CONFIG;
    }
    if (cfg->route_count > VPN_MAX_ROUTES) {
        if (err) snprintf(err, errlen, "分流网段数量超限");
        return VPN_ERR_CONFIG;
    }
    return VPN_OK;
}
