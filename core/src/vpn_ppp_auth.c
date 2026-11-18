/* SPDX-License-Identifier: LicenseRef-Proprietary
   Copyright (c) 2026 wwm-spec. All rights reserved.
 */

/* vpn_ppp_auth.c - PPP 认证：MS-CHAPv2 / CHAP-MD5 / PAP（RFC 2759 / 1994 / 1334） */
#include "ppp_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int ascii_ieq_n(const char *a, const char *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        char ca = a[i], cb = b[i];
        if (ca >= 'a' && ca <= 'z')
            ca = (char)(ca - 'a' + 'A');
        if (cb >= 'a' && cb <= 'z')
            cb = (char)(cb - 'a' + 'A');
        if (ca != cb)
            return 0;
    }
    return 1;
}

void ppp_start_ipcp(vpn_ppp *p)
{
    if (p->ipcp.state == PPP_FSM_REQ_SENT || p->ipcp.state == PPP_FSM_OPEN)
        return;
    VPN_INFO("认证完成，开始 IPCP 协商");
    ppp_fsm_open(p, &p->ipcp, PPP_PROTO_IPCP);
}

void ppp_auth_finish_ok(vpn_ppp *p)
{
    if (p->auth_done)
        return;
    p->auth_done = true;
    VPN_INFO("PPP 认证成功 (%s)",
             p->auth_proto == PPP_PROTO_PAP ? "PAP" : "CHAP");
    ppp_start_ipcp(p);
}

void ppp_auth_finish_fail(vpn_ppp *p, const char *reason)
{
    VPN_ERROR("PPP 认证失败: %s", reason ? reason : "-");
    p->auth_done = false;
    if (p->cbs.auth_failed)
        p->cbs.auth_failed(p->cbs.ctx, reason ? reason : "认证失败");
}

void ppp_send_chap_response(vpn_ppp *p)
{
    uint8_t buf[128];
    size_t pos = 0;
    const char *name = p->cfg.username;
    size_t namelen = strlen(name);

    if (namelen > 64)
        namelen = 64;

    if (p->chap_alg == CHAP_ALG_MSCHAPV2) {
        uint8_t nt_response[24];
        uint8_t peer_chal[16];
        int rc;

        vpn_rand_bytes(peer_chal, sizeof(peer_chal));
        memcpy(p->peer_challenge, peer_chal, 16);

        rc = vpn_mschapv2_nt_response(p->cfg.password, peer_chal, p->auth_challenge,
                                      p->cfg.username, nt_response, p->nt_hash);
        if (rc != VPN_OK) {
            ppp_auth_finish_fail(p, "MS-CHAPv2 计算 NT-Response 失败");
            return;
        }

        /* RFC 2759 §2.2 / pppd chap_ms.c：MS-CHAPv2 的 Response Value
         * = Peer-Challenge(16) + Reserved(8) + NT-Response(24) + Flags(1)，
         * 共 49 字节，【不含】算法字节（算法只出现在 LCP 选项和 Challenge 里）。 */
        memcpy(buf + pos, peer_chal, 16);
        pos += 16;
        memset(buf + pos, 0, 8); /* Reserved */
        pos += 8;
        memcpy(buf + pos, nt_response, 24);
        pos += 24;
        buf[pos++] = 0x00; /* Flags */

        /* 便于排查：按 RFC 3079 预派生 MPPE 密钥（SSTP Crypto-Binding 用） */
        if (vpn_mschapv2_mppe_keys(p->nt_hash, nt_response, p->mppe_send_key,
                                   p->mppe_recv_key) == VPN_OK) {
            p->has_mppe = true;
        }
        VPN_DEBUG("发送 MS-CHAPv2 Response (id=%u)", p->chap_id);
    } else {
        /* CHAP-MD5: value = MD5(id || password || challenge) */
        uint8_t md5in[1 + 256 + 64];
        size_t mlen = 0;
        uint8_t digest[16];

        md5in[mlen++] = p->chap_id;
        memcpy(md5in + mlen, p->cfg.password, strlen(p->cfg.password));
        mlen += strlen(p->cfg.password);
        memcpy(md5in + mlen, p->auth_challenge, p->auth_challenge_len);
        mlen += p->auth_challenge_len;

        vpn_md5(md5in, mlen, digest);
        buf[pos++] = 16;
        memcpy(buf + pos, digest, 16);
        pos += 16;
        VPN_DEBUG("发送 CHAP-MD5 Response (id=%u)", p->chap_id);
    }

    /* CHAP 报文: code,id,length,value-size,value,name */
    {
        uint8_t pkt[256];
        size_t off = 0;

        pkt[off++] = 2; /* Response */
        pkt[off++] = p->chap_id;
        /* Length 含 Value-Size 这 1 字节；Name 放在 Value 之外（与 RouterOS 一致） */
        vpn_put_be16(pkt + off, (uint16_t)(5 + pos + namelen));
        off += 2;
        pkt[off++] = (uint8_t)pos; /* Value-Size */
        memcpy(pkt + off, buf, pos);
        off += pos;
        memcpy(pkt + off, name, namelen);
        off += namelen;

        VPN_DEBUG("CHAP Response 报文: %s", vpn_hexdump(pkt, off));
        ppp_send_frame(p, PPP_PROTO_CHAP, pkt, off);
    }
}

void ppp_auth_start(vpn_ppp *p)
{
    if (p->auth_started || p->auth_done)
        return;
    p->auth_started = true;

    if (!p->auth_required) {
        VPN_INFO("服务器未要求认证，直接进入 IPCP");
        ppp_auth_finish_ok(p);
        return;
    }

    if (p->auth_proto == PPP_PROTO_PAP) {
        uint8_t pkt[512];
        size_t off = 0;
        size_t ulen = strlen(p->cfg.username);
        size_t plen = strlen(p->cfg.password);
        size_t total;

        if (ulen > 255)
            ulen = 255;
        if (plen > 255)
            plen = 255;

        total = 4 + 1 + ulen + 1 + plen;
        pkt[off++] = 1; /* Authenticate-Request */
        pkt[off++] = (uint8_t)(vpn_rand_u32() & 0xff);
        vpn_put_be16(pkt + off, (uint16_t)total);
        off += 2;
        pkt[off++] = (uint8_t)ulen;
        memcpy(pkt + off, p->cfg.username, ulen);
        off += ulen;
        pkt[off++] = (uint8_t)plen;
        memcpy(pkt + off, p->cfg.password, plen);
        off += plen;

        ppp_send_frame(p, PPP_PROTO_PAP, pkt, off);
        VPN_INFO("已发送 PAP Authenticate-Request (用户 %s)", p->cfg.username);
    } else {
        VPN_INFO("等待服务器下发 CHAP Challenge...");
    }
}

void ppp_auth_rx_chap(vpn_ppp *p, const uint8_t *payload, size_t len)
{
    uint8_t code, id;
    uint16_t plen;

    if (len < 4)
        return;

    VPN_DEBUG("CHAP 收到: %s", vpn_hexdump(payload, len));

    code = payload[0];
    id = payload[1];
    plen = vpn_be16(payload + 2);
    if (plen < 4 || plen > len)
        plen = (uint16_t)len;

    switch (code) {
    case 1: { /* Challenge */
        uint8_t vsize = payload[4];
        const uint8_t *value = payload + 5;
        const uint8_t *name = value + vsize;
        size_t namelen = plen > 5 + (size_t)vsize ? plen - 5 - vsize : 0;

        if (vsize < 2 || 5 + (size_t)vsize > plen) {
            ppp_auth_finish_fail(p, "CHAP Challenge 报文格式错误");
            return;
        }

        p->chap_id = id;

        /* 三种布局都要支持：
         *   RFC 2759 标准：Value = Algorithm(1) + Challenge(16)（vsize=17，算法 0x80/0x81/0xC9）
         *   pppd 风格：Value = 长度字节(0x10) + Challenge(16)（vsize=17，算法由 LCP 决定）
         *   RouterOS 精简：Value = Challenge(16)，Name 在 Value 之外
         * 精简格式没有算法字节，算法已由 LCP 协商确定。 */
        int has_prefix = 0;
        if (vsize == 17) {
            if (value[0] == CHAP_ALG_MSCHAPV1 || value[0] == 0x81) {
                p->chap_alg = CHAP_ALG_MSCHAPV1;
                has_prefix = 1;
            } else if (value[0] == CHAP_ALG_MSCHAPV2) {
                p->chap_alg = CHAP_ALG_MSCHAPV2;
                has_prefix = 1;
            } else if (value[0] == 16) {
                has_prefix = 1; /* pppd：首字节是挑战长度 */
            }
        }
        if (has_prefix) {
            p->auth_challenge_len = (uint8_t)(vsize - 1);
            if (p->auth_challenge_len > sizeof(p->auth_challenge))
                p->auth_challenge_len = sizeof(p->auth_challenge);
            memcpy(p->auth_challenge, value + 1, p->auth_challenge_len);
        } else {
            p->auth_challenge_len = vsize;
            if (p->auth_challenge_len > sizeof(p->auth_challenge))
                p->auth_challenge_len = sizeof(p->auth_challenge);
            memcpy(p->auth_challenge, value, p->auth_challenge_len);
        }
        if (namelen) {
            size_t n = namelen < sizeof(p->auth_name) - 1 ? namelen : sizeof(p->auth_name) - 1;
            memcpy(p->auth_name, name, n);
            p->auth_name[n] = '\0';
        }

        VPN_INFO("收到 CHAP Challenge (id=%u, 算法=0x%02x, 服务器=%s)", id, p->chap_alg,
                 p->auth_name[0] ? p->auth_name : "-");

        if (p->chap_alg != CHAP_ALG_MSCHAPV2 && p->chap_alg != CHAP_ALG_MD5) {
            char msg[96];
            snprintf(msg, sizeof(msg), "服务器要求不支持的 CHAP 算法 0x%02x", p->chap_alg);
            ppp_auth_finish_fail(p, msg);
            return;
        }
        if (p->chap_alg == CHAP_ALG_MSCHAPV2 && p->auth_challenge_len != 16) {
            ppp_auth_finish_fail(p, "MS-CHAPv2 Challenge 长度应为 16 字节");
            return;
        }

        ppp_send_chap_response(p);
        break;
    }
    case 2: /* Response：我们是认证方时才会收到，忽略 */
        break;
    case 3: { /* Success */
        /* RFC 2759 §2.3：MS-CHAP Success 的正文是 Message 字段（"S=... M=..."），
         * 【没有】Value-Size 字节，正文直接从偏移 4 开始。 */
        const uint8_t *value = payload + 4;

        if (plen < 4) {
            ppp_auth_finish_fail(p, "CHAP Success 报文格式错误");
            return;
        }

        if (p->chap_alg == CHAP_ALG_MSCHAPV2 && p->has_mppe) {
            char expect[64];
            char got[64];
            size_t n = plen - 4;

            if (n >= sizeof(got))
                n = sizeof(got) - 1;
            memcpy(got, value, n);
            got[n] = '\0';

            if (vpn_mschapv2_authenticator_response(p->nt_hash, p->peer_challenge,
                                                    p->auth_challenge, p->cfg.username,
                                                    expect, sizeof(expect)) == VPN_OK) {
                /* 成功报文形如 "S=<40 hex> M=..."，只比较前 41 字节并忽略大小写 */
                if (n >= 41 && !ascii_ieq_n(expect, got, 41)) {
                    VPN_ERROR("服务器 AuthenticatorResponse 不匹配（期望 %s 实收 %s）", expect,
                              got);
                    ppp_auth_finish_fail(p, "MS-CHAPv2 服务器认证响应不匹配，可能存在中间人攻击");
                    return;
                }
                VPN_INFO("MS-CHAPv2 服务器认证响应校验通过");
            }
        }

        ppp_auth_finish_ok(p);
        break;
    }
    case 4: { /* Failure */
        /* 同 Success：正文是 Message 字段（"E=691 R=0 ... M=..."），无 Value-Size */
        char reason[160];
        size_t n = plen > 4 ? plen - 4 : 0;
        char msg[128];

        if (n >= sizeof(msg))
            n = sizeof(msg) - 1;
        if (n) {
            memcpy(msg, payload + 4, n);
            msg[n] = '\0';
            snprintf(reason, sizeof(reason), "服务器拒绝认证: %s", msg);
        } else {
            snprintf(reason, sizeof(reason), "服务器拒绝认证（用户名或密码错误）");
        }
        ppp_auth_finish_fail(p, reason);
        break;
    }
    default:
        VPN_DEBUG("CHAP 未知 code=%u", code);
        break;
    }
}

void ppp_auth_rx_pap(vpn_ppp *p, const uint8_t *payload, size_t len)
{
    uint8_t code = payload[0];
    uint16_t plen;

    if (len < 4)
        return;
    plen = vpn_be16(payload + 2);
    if (plen < 4 || plen > len)
        plen = (uint16_t)len;

    if (code == 2) {
        VPN_INFO("PAP 认证成功");
        ppp_auth_finish_ok(p);
    } else if (code == 3) {
        char msg[128];
        size_t mlen = 0;
        if (plen > 5) {
            mlen = payload[4];
            if (5 + mlen > plen)
                mlen = plen - 5;
            if (mlen >= sizeof(msg))
                mlen = sizeof(msg) - 1;
            memcpy(msg, payload + 5, mlen);
            msg[mlen] = '\0';
        } else {
            msg[0] = '\0';
        }
        VPN_ERROR("PAP 认证失败: %s", msg);
        p->auth_done = false;
        if (p->cbs.auth_failed)
            p->cbs.auth_failed(p->cbs.ctx, msg[0] ? msg : "用户名或密码错误");
    }
}
