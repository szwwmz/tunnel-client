/* SPDX-License-Identifier: LicenseRef-Proprietary
   Copyright (c) 2026 wwm-spec. All rights reserved.
 */

/* vpn_sstp.c - MS-SSTP 客户端：TCP + TLS + 控制报文 + PPP over HDLC */
#include "vpncore/vpn_sstp.h"
#include "vpncore/vpn_buf.h"
#include "vpncore/vpn_crypto.h"
#include "vpncore/vpn_error.h"
#include "vpncore/vpn_log.h"
#include "vpncore/vpn_net.h"
#include "vpncore/vpn_platform.h"
#include "vpncore/vpn_ppp_frame.h"
#include "vpncore/vpn_tls.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Crypto-Binding 的 CMK 派生与 Compound MAC 需要 HMAC-SHA1 / HMAC-SHA256，
 * 直接复用 TLS 层的 OpenSSL（与 vpn_tls.c 一致，避免再造一套 SHA-256）。 */
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define SSTP_RX_CAP (32 * 1024)
#define SSTP_ACK_TIMEOUT_MS 20000

struct vpn_sstp {
    vpn_sstp_params p;
    vpn_sstp_cbs    cbs;

    vpn_sock_t      sock;
    vpn_tls        *tls;
    vpn_hdlc_decoder hdlc;

    uint8_t         rx[SSTP_RX_CAP];
    size_t          rxlen;

    bool            open;             /* 控制通道已建立（收到 ACK） */
    bool            connected_sent;    /* 已发出 CALL_CONNECTED */
    bool            need_crypto_binding;
    uint8_t         cb_hash_mask;      /* 服务器 Crypto-Binding-Request 支持的哈希位图 */
    bool            has_mppe;
    uint8_t         mppe_send[16];
    uint8_t         mppe_recv[16];

    /* 服务器 CALL_CONNECT_ACK 原文，用于 Crypto-Binding 的 Compound MAC */
    uint8_t         ack_pkt[SSTP_MAX_CONTROL_LEN];
    size_t          ack_len;

    int64_t         last_rx_ms;
    int64_t         last_echo_ms;
    uint32_t        echo_seq;
    char            reason[192];
    char            fingerprint[96];
    char            tls_summary[192];
};

/* ------------------------------------------------------------------ */
/* 报文构造                                                            */
/* ------------------------------------------------------------------ */
int vpn_sstp_build_attr(uint8_t *out, size_t cap, uint8_t attr_id,
                        const uint8_t *value, size_t value_len)
{
    if (!out || cap < 4 + value_len)
        return -1;
    out[0] = 0;               /* Reserved */
    out[1] = attr_id;         /* Attribute ID */
    /* Length 必须包含 4 字节属性头本身（MS-SSTP 2.2.1） */
    vpn_put_be16(out + 2, (uint16_t)(4 + value_len));
    if (value_len && value)
        memcpy(out + 4, value, value_len);
    return (int)(4 + value_len);
}

int vpn_sstp_build_control(uint8_t *out, size_t cap, uint16_t msg_type,
                           const uint8_t *attrs, size_t attrs_len)
{
    size_t total = 8 + attrs_len;
    uint16_t nattrs = 0;
    size_t pos = 0;

    if (!out || cap < total)
        return -1;

    while (pos + 4 <= attrs_len) {
        uint16_t alen = vpn_be16(attrs + pos + 2);
        if (alen < 4 || pos + alen > attrs_len)
            break;
        nattrs++;
        pos += alen;
    }

    out[0] = SSTP_VERSION;
    out[1] = 0x01;                    /* Reserved(7) | C=1 */
    vpn_put_be16(out + 2, (uint16_t)total);
    vpn_put_be16(out + 4, msg_type);
    vpn_put_be16(out + 6, nattrs);
    if (attrs_len)
        memcpy(out + 8, attrs, attrs_len);
    return (int)total;
}

static int sstp_write(vpn_sstp *s, const void *data, size_t len)
{
    if (!s->tls)
        return VPN_ERR_CLOSED;
    int rc = vpn_tls_write(s->tls, data, len, s->p.io_timeout_ms);
    if (rc < 0)
        VPN_ERROR("SSTP 发送失败: %s", vpn_strerror(rc));
    else
        VPN_DEBUG("SSTP: TLS 写入 %d/%zu 字节", rc, len);
    return rc < 0 ? rc : VPN_OK;
}

static int sstp_send_control(vpn_sstp *s, uint16_t type, const uint8_t *attrs, size_t alen)
{
    uint8_t pkt[SSTP_MAX_CONTROL_LEN];
    int len = vpn_sstp_build_control(pkt, sizeof(pkt), type, attrs, alen);

    if (len < 0)
        return VPN_ERR_INVALID;

    VPN_DEBUG("SSTP -> 控制报文 type=%u len=%d attrs=%zu", type, len, alen);
    return sstp_write(s, pkt, (size_t)len);
}

/* ------------------------------------------------------------------ */
/* Crypto-Binding                                                      */
/* ------------------------------------------------------------------ */
/* MS-SSTP 2.2.11：CALL_CONNECTED 固定 112 字节，Crypto Binding 属性内嵌其中。
 *
 *  0    Version 0x10
 *  1    Reserved(7) | C=1
 *  2    LengthPacket = 112
 *  4    Message Type = 4
 *  6    Num Attributes = 1
 *  8    Reserved1
 *  9    Attribute ID = 3 (Crypto Binding)
 *  10   LengthPacket1 = 104（含 4 字节属性头）
 *  12   Reserved2 (3 字节)
 *  15   Hash Protocol Bitmask = 0x01 (SHA1)
 *  16   Nonce (32)  —— 回显 Call Connect ACK 里的 nonce
 *  48   Cert Hash (20) —— 服务器证书 DER 的 SHA-1
 *  68   Padding (12)
 *  80   Compound MAC (20)
 *  100  Padding1 (12)
 */
#define SSTP_CONNECTED_LEN 112
#define SSTP_HASH_PROTOCOL_SHA1 0x01
#define SSTP_HASH_PROTOCOL_SHA256 0x02
#define SSTP_CB_SEED "SSTP inner method derived CMK" /* 29 字节，无 NUL */

/* 解析 CALL_CONNECT_ACK 里的 Crypto-Binding-Request：取 nonce 与服务器支持的哈希位图。
 * 属性 value = Reserved(3) + Hash Protocol Bitmask(1) + Nonce(32) */
static int sstp_cb_request(const uint8_t *ack, size_t ack_len,
                           uint8_t nonce[32], uint8_t *hash_mask)
{
    uint16_t nattrs;
    size_t pos = 8;

    if (!ack || ack_len < 8)
        return VPN_ERR_INVALID;

    nattrs = vpn_be16(ack + 6);
    for (uint16_t i = 0; i < nattrs && pos + 4 <= ack_len; i++) {
        uint16_t alen = vpn_be16(ack + pos + 2);

        if (alen < 4 || pos + alen > ack_len)
            break;
        if (ack[pos + 1] == SSTP_ATTR_CRYPTO_BINDING_REQUEST && alen >= 4 + 4 + 32) {
            if (hash_mask)
                *hash_mask = ack[pos + 7];
            memcpy(nonce, ack + pos + 8, 32);
            return VPN_OK;
        }
        pos += alen;
    }
    return VPN_ERR_INVALID;
}

static const EVP_MD *sstp_cb_md(uint8_t hash_id, size_t *hash_len)
{
    if (hash_id == SSTP_HASH_PROTOCOL_SHA256) {
        *hash_len = 32;
        return EVP_sha256();
    }
    *hash_len = 20;
    return EVP_sha1();
}

/* CMK = PRF+(HLAK, "SSTP inner method derived CMK" | LEN(小端 16 位) | 0x01) 的前 len 字节
 * 由 MS-SSTP 3.2.5.2.2 / 3.2.5.2.4 定义（PRF+ 见 RFC 4306 2.13）。 */
static int sstp_derive_cmk(const uint8_t hlak[32], const EVP_MD *md, size_t len, uint8_t *cmk)
{
    uint8_t seed[40];
    uint8_t t[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;
    size_t pos = sizeof(SSTP_CB_SEED) - 1;

    memcpy(seed, SSTP_CB_SEED, pos);
    seed[pos++] = (uint8_t)(len & 0xff);
    seed[pos++] = (uint8_t)((len >> 8) & 0xff);
    seed[pos++] = 0x01; /* PRF+ 计数器 T1 */

    if (!HMAC(md, hlak, 32, seed, pos, t, &mdlen) || mdlen < len)
        return VPN_ERR_INVALID;

    memcpy(cmk, t, len);
    return VPN_OK;
}

static int sstp_send_connected(vpn_sstp *s)
{
    uint8_t pkt[SSTP_CONNECTED_LEN];
    uint8_t nonce[32];
    uint8_t hash_mask = 0;
    uint8_t cert_hash[32];
    uint8_t hlak[32];
    uint8_t cmk[EVP_MAX_MD_SIZE];
    uint8_t mac[EVP_MAX_MD_SIZE];
    uint8_t hash_id;
    size_t hash_len, cmk_len;
    const EVP_MD *md;
    unsigned int maclen = 0;
    const char *env;

    if (!s->need_crypto_binding) {
        /* 服务器不要求绑定：发最小的 CALL_CONNECTED（Encap=PPP）即可。 */
        uint8_t attrs[8];
        vpn_put_be16(attrs + 4, SSTP_ENCAP_PPP);
        int n = vpn_sstp_build_attr(attrs, sizeof(attrs),
                                    SSTP_ATTR_ENCAPSULATED_PROTOCOL_ID, attrs + 4, 2);
        int rc = n < 0 ? VPN_ERR_INVALID : sstp_send_control(s, SSTP_MSG_CALL_CONNECTED, attrs, (size_t)n);
        if (rc == VPN_OK) {
            s->connected_sent = true;
            VPN_INFO("SSTP: 已发送 CALL_CONNECTED");
        }
        return rc;
    }

    if (!s->has_mppe) {
        VPN_WARN("SSTP: 服务器要求 Crypto-Binding 但未取得 MPPE 密钥");
        return VPN_ERR_INVALID;
    }
    if (sstp_cb_request(s->ack_pkt, s->ack_len, nonce, &hash_mask) != VPN_OK) {
        VPN_ERROR("SSTP: ACK 里找不到 Crypto-Binding-Request 的 nonce");
        return VPN_ERR_INVALID;
    }

    /* 选择哈希算法：默认优先 SHA-256（Windows 7+ 行为），可用环境变量强制 */
    env = getenv("VPN_SSTP_CB_HASH");
    if (env && !strcmp(env, "sha1"))
        hash_id = SSTP_HASH_PROTOCOL_SHA1;
    else if (env && !strcmp(env, "sha256"))
        hash_id = SSTP_HASH_PROTOCOL_SHA256;
    else
        hash_id = (hash_mask & SSTP_HASH_PROTOCOL_SHA256) ? SSTP_HASH_PROTOCOL_SHA256
                                                          : SSTP_HASH_PROTOCOL_SHA1;

    md = sstp_cb_md(hash_id, &hash_len);
    if (hash_id == SSTP_HASH_PROTOCOL_SHA256) {
        if (vpn_tls_peer_cert_sha256(s->tls, cert_hash) != VPN_OK) {
            VPN_ERROR("SSTP: 取不到服务器证书 SHA-256，无法完成 Crypto-Binding");
            return VPN_ERR_INVALID;
        }
    } else {
        if (vpn_tls_peer_cert_sha1(s->tls, cert_hash) != VPN_OK) {
            VPN_ERROR("SSTP: 取不到服务器证书 SHA-1，无法完成 Crypto-Binding");
            return VPN_ERR_INVALID;
        }
    }

    memset(pkt, 0, sizeof(pkt));
    pkt[0] = SSTP_VERSION;
    pkt[1] = 0x01;                                   /* C=1 */
    vpn_put_be16(pkt + 2, SSTP_CONNECTED_LEN);
    vpn_put_be16(pkt + 4, SSTP_MSG_CALL_CONNECTED);
    vpn_put_be16(pkt + 6, 1);                        /* Num Attributes */
    pkt[8] = 0;                                      /* Reserved1 */
    pkt[9] = SSTP_ATTR_CRYPTO_BINDING;
    vpn_put_be16(pkt + 10, SSTP_CONNECTED_LEN - 8);  /* 104 */
    pkt[15] = hash_id;                               /* Hash Protocol Bitmask */
    memcpy(pkt + 16, nonce, 32);
    memcpy(pkt + 48, cert_hash, hash_len);           /* 48..79：证书哈希 + 零填充 */
    /* 80..111：Compound MAC + 零填充，先全 0 参与计算 */

    /* HLAK（客户端）= MasterSendKey | MasterReceiveKey = MPPE send || recv */
    if (getenv("VPN_SSTP_HLAK_SWAP")) {
        memcpy(hlak, s->mppe_recv, 16);
        memcpy(hlak + 16, s->mppe_send, 16);
    } else {
        memcpy(hlak, s->mppe_send, 16);
        memcpy(hlak + 16, s->mppe_recv, 16);
    }

    cmk_len = hash_len;
    env = getenv("VPN_SSTP_CB_CMKLEN");
    if (env) {
        long v = strtol(env, NULL, 10);
        if (v == 20 || v == 32)
            cmk_len = (size_t)v;
    }

    if (sstp_derive_cmk(hlak, md, cmk_len, cmk) != VPN_OK) {
        VPN_ERROR("SSTP: CMK 派生失败");
        return VPN_ERR_INVALID;
    }
    /* Compound MAC = HMAC(CMK, 整条 112 字节，MAC 与 Padding 置 0) */
    if (!HMAC(md, cmk, (int)cmk_len, pkt, sizeof(pkt), mac, &maclen) || maclen < hash_len) {
        VPN_ERROR("SSTP: Compound MAC 计算失败");
        return VPN_ERR_INVALID;
    }
    memcpy(pkt + 80, mac, hash_len);

    VPN_INFO("SSTP: CALL_CONNECTED Crypto-Binding (%s, 服务器位图=0x%02x, CMK=%s CMAC=%s)",
             hash_id == SSTP_HASH_PROTOCOL_SHA256 ? "SHA256" : "SHA1", hash_mask,
             vpn_hexdump(cmk, cmk_len), vpn_hexdump(mac, hash_len));
    VPN_DEBUG("SSTP: CALL_CONNECTED 原始报文 %s", vpn_hexdump(pkt, sizeof(pkt)));

    int rc = sstp_write(s, pkt, sizeof(pkt));
    if (rc == VPN_OK) {
        s->connected_sent = true;
        VPN_INFO("SSTP: 已发送 CALL_CONNECTED");
    }
    return rc;
}

void vpn_sstp_set_mppe_keys(vpn_sstp *s, const uint8_t send_key[16], const uint8_t recv_key[16])
{
    if (!s || !send_key || !recv_key)
        return;
    memcpy(s->mppe_send, send_key, 16);
    memcpy(s->mppe_recv, recv_key, 16);
    s->has_mppe = true;

    if (s->need_crypto_binding && !s->connected_sent)
        sstp_send_connected(s);
}

/* ------------------------------------------------------------------ */
/* 控制报文处理                                                        */
/* ------------------------------------------------------------------ */
static void sstp_handle_control(vpn_sstp *s, const uint8_t *pkt, size_t len)
{
    uint16_t type, nattrs;
    size_t pos = 8;

    if (len < 8) {
        VPN_WARN("SSTP: 控制报文过短 (%zu 字节)", len);
        return;
    }

    type = vpn_be16(pkt + 4);
    nattrs = vpn_be16(pkt + 6);
    (void)nattrs;

    VPN_DEBUG("SSTP <- 控制报文 type=%u len=%zu %s", type, len, vpn_hexdump(pkt, len));

    switch (type) {
    case SSTP_MSG_CALL_CONNECT_ACK: {
        /* 解析属性，判断是否需要 Crypto-Binding */
        while (pos + 4 <= len) {
            uint8_t aid = pkt[pos + 1];
            uint16_t alen = vpn_be16(pkt + pos + 2);
            if (alen < 4 || pos + alen > len)
                break;
            if (aid == SSTP_ATTR_CRYPTO_BINDING_REQUEST) {
                s->need_crypto_binding = true;
                if (alen >= 4 + 4 + 32)
                    s->cb_hash_mask = pkt[pos + 7];
                VPN_INFO("SSTP: 服务器请求 Crypto-Binding（MS-CHAPv2 密钥校验，哈希位图=0x%02x）",
                         s->cb_hash_mask);
            }
            pos += alen;
        }

        if (len <= sizeof(s->ack_pkt)) {
            memcpy(s->ack_pkt, pkt, len);
            s->ack_len = len;
        }

        s->open = true;
        if (!s->need_crypto_binding || s->has_mppe)
            sstp_send_connected(s);
        else
            VPN_DEBUG("SSTP: 等待 PPP 认证完成后再发送 CALL_CONNECTED");

        if (s->cbs.on_connected)
            s->cbs.on_connected(s->cbs.ctx);
        break;
    }
    case SSTP_MSG_CALL_CONNECT_NAK: {
        uint32_t status = 0;
        while (pos + 4 <= len) {
            uint8_t aid = pkt[pos + 1];
            uint16_t alen = vpn_be16(pkt + pos + 2);
            if (alen < 4 || pos + alen > len)
                break;
            if (aid == SSTP_ATTR_STATUS_INFO && alen >= 8)
                status = vpn_be32(pkt + pos + 4);
            pos += alen;
        }
        snprintf(s->reason, sizeof(s->reason),
                 "服务器拒绝 SSTP 连接 (status=0x%08x)", status);
        VPN_ERROR("%s", s->reason);
        if (s->cbs.on_closed)
            s->cbs.on_closed(s->cbs.ctx, s->reason);
        break;
    }
    case SSTP_MSG_ECHO_REQUEST:
        sstp_send_control(s, SSTP_MSG_ECHO_RESPONSE, NULL, 0);
        break;
    case SSTP_MSG_ECHO_RESPONSE:
        s->last_rx_ms = vpn_now_ms();
        break;
    case SSTP_MSG_CALL_DISCONNECT:
        snprintf(s->reason, sizeof(s->reason), "服务器主动断开 SSTP 连接");
        sstp_send_control(s, SSTP_MSG_CALL_DISCONNECT_ACK, NULL, 0);
        s->open = false;
        if (s->cbs.on_closed)
            s->cbs.on_closed(s->cbs.ctx, s->reason);
        break;
    case SSTP_MSG_CALL_ABORT:
        snprintf(s->reason, sizeof(s->reason), "服务器中止 SSTP 连接 (CALL_ABORT)");
        s->open = false;
        if (s->cbs.on_closed)
            s->cbs.on_closed(s->cbs.ctx, s->reason);
        break;
    default:
        VPN_DEBUG("SSTP: 未处理控制报文 type=%u", type);
        break;
    }
}

static void sstp_on_ppp_frame(void *ctx, const uint8_t *frame, size_t len)
{
    vpn_sstp *s = (vpn_sstp *)ctx;
    if (s->cbs.on_ppp)
        s->cbs.on_ppp(s->cbs.ctx, frame, len);
}

/* ------------------------------------------------------------------ */
/* 收包                                                                */
/* ------------------------------------------------------------------ */
static int sstp_parse_buffer(vpn_sstp *s)
{
    while (s->rxlen >= 4) {
        uint8_t version = s->rx[0];
        uint8_t ctl = s->rx[1] & 0x01;
        uint16_t total = vpn_be16(s->rx + 2);

        if (version != SSTP_VERSION) {
            VPN_WARN("SSTP: 版本字节异常 0x%02x，尝试重同步", version);
            memmove(s->rx, s->rx + 1, s->rxlen - 1);
            s->rxlen--;
            continue;
        }
        if (total < 4) {
            VPN_ERROR("SSTP: 报文长度非法 %u", total);
            return VPN_ERR_PROTO;
        }
        if (s->rxlen < total)
            return VPN_OK; /* 等待更多数据 */

        if (ctl) {
            sstp_handle_control(s, s->rx, total);
        } else {
            /* 数据报文：负载是裸 PPP 帧（Address 0xFF + Control 0x03 + PPP 包），
             * 不含 HDLC 标志/FCS/转义，不能走 HDLC 解码器。 */
            const uint8_t *pp = s->rx + 4;
            size_t plen = (size_t)total - 4;

            if (plen >= 2 && pp[0] == 0xFF && pp[1] == 0x03) {
                pp += 2;
                plen -= 2;
            }
            VPN_DEBUG("SSTP: PPP 负载 %zu 字节", plen);
            if (plen > 0 && s->cbs.on_ppp)
                s->cbs.on_ppp(s->cbs.ctx, pp, plen);
        }

        memmove(s->rx, s->rx + total, s->rxlen - total);
        s->rxlen -= total;
        s->last_rx_ms = vpn_now_ms();
    }
    return VPN_OK;
}

int vpn_sstp_run_once(vpn_sstp *s, int timeout_ms)
{
    int rc;

    if (!s || !s->tls)
        return VPN_ERR_INVALID;

    if (s->rxlen >= sizeof(s->rx))
        return VPN_ERR_PROTO;

    rc = vpn_tls_read(s->tls, s->rx + s->rxlen, sizeof(s->rx) - s->rxlen, timeout_ms);
    if (rc == 0) {
        snprintf(s->reason, sizeof(s->reason), "服务器关闭了 TLS 连接");
        s->open = false;
        if (s->cbs.on_closed)
            s->cbs.on_closed(s->cbs.ctx, s->reason);
        return VPN_ERR_CLOSED;
    }
    if (rc < 0)
        return rc; /* 超时也直接返回，由调用方继续循环 */

    s->rxlen += (size_t)rc;
    s->last_rx_ms = vpn_now_ms();
    VPN_DEBUG("SSTP: 收到 %d 字节（缓冲 %zu）", rc, s->rxlen);
    return sstp_parse_buffer(s);
}

/* ------------------------------------------------------------------ */
/* 建立 / 发送 / 关闭                                                  */
/* ------------------------------------------------------------------ */
vpn_sstp *vpn_sstp_new(const vpn_sstp_params *p, const vpn_sstp_cbs *cbs)
{
    vpn_sstp *s;

    if (!p || !cbs)
        return NULL;

    s = (vpn_sstp *)calloc(1, sizeof(*s));
    if (!s)
        return NULL;

    s->p = *p;
    s->cbs = *cbs;
    s->sock = VPN_INVALID_SOCK;
    if (s->p.port == 0)
        s->p.port = 443;
    if (s->p.connect_timeout_ms <= 0)
        s->p.connect_timeout_ms = 15000;
    if (s->p.io_timeout_ms <= 0)
        s->p.io_timeout_ms = 30000;
    if (s->p.server_name[0] == '\0')
        snprintf(s->p.server_name, sizeof(s->p.server_name), "%s", s->p.host);

    vpn_hdlc_decoder_init(&s->hdlc, sstp_on_ppp_frame, s);
    return s;
}

void vpn_sstp_free(vpn_sstp *s)
{
    if (!s)
        return;
    if (s->tls)
        vpn_tls_free(s->tls);
    vpn_net_close(&s->sock);
    free(s);
}

/* SSTP 报文并不直接跑在裸 TLS 上：TLS 建立后必须先发一个 SSTP_DUPLEX_POST
 * 的 HTTP 请求，服务器回 200 OK 之后才进入 SSTP 控制报文阶段（MS-SSTP 2.2.1）。
 * RouterOS 的 sstp-server 严格按此实现：缺少这一步时它会静默等待 HTTP 头，
 * 既不回 CALL_CONNECT_ACK 也不记日志。 */
static int sstp_http_upgrade(vpn_sstp *s)
{
    static const char guid[] = "{BA195980-CD49-458b-9E23-C84EE0ADCD75}";
    char req[512];
    char resp[1024];
    char first[128];
    size_t got = 0;
    size_t i;
    int len, rc;

    len = snprintf(req, sizeof(req),
                   "SSTP_DUPLEX_POST /sra_%s/ HTTP/1.1\r\n"
                   "Host: %s\r\n"
                   "SSTPCORRELATIONID: %s\r\n"
                   "Content-Length: 18446744073709551615\r\n"
                   "\r\n",
                   guid, s->p.host, guid);
    if (len <= 0 || (size_t)len >= sizeof(req))
        return VPN_ERR_INVALID;

    rc = vpn_tls_write(s->tls, req, (size_t)len, s->p.io_timeout_ms);
    if (rc < 0) {
        snprintf(s->reason, sizeof(s->reason), "发送 SSTP_DUPLEX_POST 失败");
        return rc;
    }
    VPN_DEBUG("SSTP: 已发送 SSTP_DUPLEX_POST（HTTP 封装层）");

    for (;;) {
        if (got + 1 >= sizeof(resp))
            break;
        rc = vpn_tls_read(s->tls, resp + got, sizeof(resp) - 1 - got, s->p.io_timeout_ms);
        if (rc <= 0) {
            snprintf(s->reason, sizeof(s->reason), "%s",
                     rc == 0 ? "服务器在 SSTP HTTP 阶段关闭了连接"
                             : "读取 SSTP HTTP 响应失败");
            return rc == 0 ? VPN_ERR_CLOSED : rc;
        }
        got += (size_t)rc;
        resp[got] = '\0';
        if (strstr(resp, "\r\n\r\n"))
            break;
    }

    for (i = 0; i < got && i + 1 < sizeof(first) && resp[i] != '\r'; i++)
        first[i] = resp[i];
    first[i] = '\0';

    if (!strstr(resp, " 200")) {
        snprintf(s->reason, sizeof(s->reason), "SSTP HTTP 升级被拒绝（%s）",
                 first[0] ? first : "无响应");
        return VPN_ERR_PROTO;
    }

    /* HTTP 头之后可能已经带出数据，转入 SSTP 解析缓冲 */
    {
        char *end = strstr(resp, "\r\n\r\n");
        if (end) {
            size_t hlen = (size_t)(end - resp) + 4;
            size_t extra = got > hlen ? got - hlen : 0;
            if (extra > 0) {
                if (extra > sizeof(s->rx))
                    extra = sizeof(s->rx);
                memcpy(s->rx, resp + hlen, extra);
                s->rxlen = extra;
            }
        }
    }

    VPN_INFO("SSTP: HTTP 隧道已建立（%s）", first);
    return VPN_OK;
}

int vpn_sstp_open(vpn_sstp *s)
{
    vpn_tls_params tp;
    uint8_t attrs[64];
    uint8_t encap[2];
    int n, rc;
    int64_t deadline;

    if (!s)
        return VPN_ERR_INVALID;

    VPN_INFO("SSTP: 连接 %s:%u (证书策略=%s)", s->p.host, s->p.port,
             vpn_cert_mode_name(s->p.cert_mode));

    rc = vpn_net_tcp_connect(s->p.host, s->p.port, s->p.connect_timeout_ms, &s->sock);
    if (rc != VPN_OK)
        return rc;

    memset(&tp, 0, sizeof(tp));
    tp.sock = s->sock;
    tp.cert_mode = s->p.cert_mode;
    tp.ca_file = s->p.ca_file[0] ? s->p.ca_file : NULL;
    tp.ca_dir = s->p.ca_dir[0] ? s->p.ca_dir : NULL;
    tp.server_name = s->p.server_name;
    tp.verify_hostname = s->p.verify_hostname;
    tp.handshake_timeout_ms = s->p.connect_timeout_ms;

    s->tls = vpn_tls_new(&tp);
    if (!s->tls) {
        snprintf(s->reason, sizeof(s->reason), "TLS 初始化失败");
        return VPN_ERR_TLS;
    }

    rc = vpn_tls_handshake(s->tls);
    if (rc != VPN_OK) {
        snprintf(s->reason, sizeof(s->reason), "%s", vpn_tls_last_error(s->tls));
        return rc;
    }

    vpn_tls_peer_fingerprint(s->tls, s->fingerprint, sizeof(s->fingerprint));
    snprintf(s->tls_summary, sizeof(s->tls_summary), "TLS %s / %s",
             vpn_tls_version_str(s->tls), vpn_tls_cipher_name(s->tls));

    /* 先完成 HTTP 封装层，否则服务器不会进入 SSTP 状态机 */
    rc = sstp_http_upgrade(s);
    if (rc != VPN_OK) {
        VPN_ERROR("SSTP: %s", s->reason);
        return rc;
    }

    /* CALL_CONNECT_REQUEST：只需要 Encapsulated Protocol ID = PPP */
    vpn_put_be16(encap, SSTP_ENCAP_PPP);
    n = vpn_sstp_build_attr(attrs, sizeof(attrs), SSTP_ATTR_ENCAPSULATED_PROTOCOL_ID, encap, 2);
    if (n < 0)
        return VPN_ERR_INVALID;

    rc = sstp_send_control(s, SSTP_MSG_CALL_CONNECT_REQUEST, attrs, (size_t)n);
    if (rc != VPN_OK)
        return rc;
    VPN_INFO("SSTP: CALL_CONNECT_REQUEST 已发出（Encap=PPP, %d 字节）",
             8 + n);

    VPN_INFO("SSTP: 已发送 CALL_CONNECT_REQUEST，等待服务器 ACK（最多 %d 秒）",
             s->p.connect_timeout_ms / 1000 > 0 ? s->p.connect_timeout_ms / 1000 : 1);

    /* 等待 CALL_CONNECT_ACK */
    deadline = vpn_now_ms() + s->p.connect_timeout_ms;
    while (!s->open) {
        if (vpn_now_ms() > deadline) {
            snprintf(s->reason, sizeof(s->reason),
                     "等待 CALL_CONNECT_ACK 超时（服务器已接受 HTTP 隧道但未回 ACK，"
                     "请检查 RouterOS 的 sstp-server 认证配置与 /log）");
            VPN_ERROR("SSTP: %s", s->reason);
            return VPN_ERR_TIMEOUT;
        }
        rc = vpn_sstp_run_once(s, 1000);
        if (rc == VPN_ERR_CLOSED || rc == VPN_ERR_IO || rc == VPN_ERR_TLS)
            return rc;
        if (rc == VPN_ERR_PROTO)
            return rc;
    }

    VPN_INFO("SSTP: 控制通道已建立（%s）", s->tls_summary);
    s->last_rx_ms = vpn_now_ms();
    return VPN_OK;
}

int vpn_sstp_send_ppp(vpn_sstp *s, const uint8_t *frame, size_t len)
{
    uint8_t buf[4096];
    int hlen;

    if (!s || !s->tls)
        return VPN_ERR_INVALID;
    if (!s->open)
        return VPN_ERR_CLOSED;

    /* SSTP 的 PPP 负载是裸帧：Address(0xFF)+Control(0x03)+PPP 包，
     * 不带 HDLC 标志/FCS/字节转义。 */
    if (len + 6 > sizeof(buf))
        return VPN_ERR_INVALID;

    buf[4] = 0xFF;
    buf[5] = 0x03;
    memcpy(buf + 6, frame, len);
    hlen = (int)len + 2;

    buf[0] = SSTP_VERSION;
    buf[1] = 0x00;
    vpn_put_be16(buf + 2, (uint16_t)(hlen + 4));

    return sstp_write(s, buf, (size_t)hlen + 4);
}

int vpn_sstp_send_echo(vpn_sstp *s)
{
    if (!s || !s->open)
        return VPN_ERR_INVALID;
    s->echo_seq++;
    s->last_echo_ms = vpn_now_ms();
    return sstp_send_control(s, SSTP_MSG_ECHO_REQUEST, NULL, 0);
}

void vpn_sstp_close(vpn_sstp *s, const char *reason)
{
    if (!s)
        return;

    if (s->tls && s->open) {
        sstp_send_control(s, SSTP_MSG_CALL_DISCONNECT, NULL, 0);
        VPN_INFO("SSTP: 已发送 CALL_DISCONNECT (%s)", reason ? reason : "-");
    }
    s->open = false;
    if (s->tls) {
        vpn_tls_free(s->tls);
        s->tls = NULL;
    }
    vpn_net_close(&s->sock);
}

int vpn_sstp_fd(const vpn_sstp *s) { return s ? (int)s->sock : -1; }
bool vpn_sstp_is_open(const vpn_sstp *s) { return s && s->open; }
const char *vpn_sstp_peer_fingerprint(vpn_sstp *s) { return s ? s->fingerprint : ""; }
const char *vpn_sstp_tls_summary(vpn_sstp *s) { return s ? s->tls_summary : ""; }
