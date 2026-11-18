/* SPDX-License-Identifier: LicenseRef-Proprietary
   Copyright (c) 2026 wwm-spec. All rights reserved.
 */

/* vpn_ppp.c - PPP FSM / LCP / IPCP（RFC 1661 / 1332 / 1877） */
#include "ppp_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

const char *vpn_ppp_fsm_name(ppp_fsm_state st)
{
    switch (st) {
    case PPP_FSM_INITIAL:  return "Initial";
    case PPP_FSM_STARTING: return "Starting";
    case PPP_FSM_CLOSED:   return "Closed";
    case PPP_FSM_STOPPED:  return "Stopped";
    case PPP_FSM_CLOSING:  return "Closing";
    case PPP_FSM_STOPPING: return "Stopping";
    case PPP_FSM_REQ_SENT: return "Req-Sent";
    case PPP_FSM_ACK_RCVD: return "Ack-Rcvd";
    case PPP_FSM_ACK_SENT: return "Ack-Sent";
    case PPP_FSM_OPEN:     return "Open";
    default:               return "?";
    }
}

/* ------------------------------------------------------------------ */
/* 基础发送                                                            */
/* ------------------------------------------------------------------ */
void ppp_send_frame(vpn_ppp *p, uint16_t proto, const uint8_t *payload, size_t len)
{
    uint8_t *buf = p->txbuf;

    if (!p->cbs.send)
        return;
    if (len + 2 > sizeof(p->txbuf))
        return;

    buf[0] = (uint8_t)(proto >> 8);
    buf[1] = (uint8_t)proto;
    if (len)
        memcpy(buf + 2, payload, len);

    p->cbs.send(p->cbs.ctx, buf, len + 2);
}

void ppp_send_fsm(vpn_ppp *p, ppp_fsm *fsm, uint16_t proto, uint8_t code,
                  uint8_t id, const uint8_t *data, size_t len)
{
    uint8_t buf[PPP_MAX_OPTS + 4];

    if (len + 4 > sizeof(buf))
        return;

    buf[0] = code;
    buf[1] = id;
    vpn_put_be16(buf + 2, (uint16_t)(len + 4));
    if (len)
        memcpy(buf + 4, data, len);

    ppp_send_frame(p, proto, buf, len + 4);
    fsm->tx_count++;
    /* 只有 Configure-Request 才重置 Restart 计时器。回给对端的 Conf-Ack/Nak/Rej
     * 不能重置，否则对端每次重发 Conf-Req 都会把我们的重传推迟（实测把 LCP
     * 拖了 8 秒才完成，RouterOS 侧的 PPP 会话建立超时判定随之变紧）。 */
    if (code == PPP_CODE_CONF_REQ)
        fsm->last_tx_ms = vpn_now_ms();
}

/* ------------------------------------------------------------------ */
/* FSM                                                                 */
/* ------------------------------------------------------------------ */
void ppp_fsm_init(ppp_fsm *fsm)
{
    memset(fsm, 0, sizeof(*fsm));
    fsm->state = PPP_FSM_INITIAL;
    /* 与 xl2tpd 一致从 1 开始：RouterOS 的 PPP 栈对随机起始 Identifier 的
     * Conf-Ack 匹配存在问题（实测随机 id 时服务器持续推进 Conf-Request，
     * 始终不回应我们） */
    fsm->id = 1;
}

void ppp_fsm_open(vpn_ppp *p, ppp_fsm *fsm, uint16_t proto)
{
    uint8_t opts[PPP_MAX_OPTS];
    int len;

    fsm->state = PPP_FSM_REQ_SENT;
    fsm->we_acked = false;
    fsm->peer_acked = false;
    fsm->retries = 0;
    fsm->id++;

    len = ppp_build_conf_req(p, fsm, proto, opts, sizeof(opts));
    ppp_send_fsm(p, fsm, proto, PPP_CODE_CONF_REQ, fsm->id, opts, (size_t)len);
    fsm->last_rx_ms = vpn_now_ms();

    VPN_DEBUG("%s: sending Configure-Request (id=%u, %d bytes of options)",
              proto == PPP_PROTO_LCP ? "LCP" : "IPCP", fsm->id, len);
}

void ppp_fsm_close(vpn_ppp *p, ppp_fsm *fsm, uint16_t proto, const char *reason)
{
    if (fsm->state == PPP_FSM_OPEN || fsm->state == PPP_FSM_REQ_SENT ||
        fsm->state == PPP_FSM_ACK_RCVD || fsm->state == PPP_FSM_ACK_SENT) {
        fsm->id++;
        ppp_send_fsm(p, fsm, proto, PPP_CODE_TERM_REQ, fsm->id, NULL, 0);
        VPN_INFO("%s: closing (%s)", proto == PPP_PROTO_LCP ? "LCP" : "IPCP",
                 reason ? reason : "-");
    }
    fsm->state = PPP_FSM_STOPPED;
}

void ppp_fsm_tick(vpn_ppp *p, ppp_fsm *fsm, uint16_t proto, int64_t now)
{
    /* 只要我方 Conf-Req 还没被对端确认，就必须继续按 Restart 定时器重传。
     * 注意 ACK_SENT 状态同样要重传：对端先发来 Conf-Req 时我们会先回 Conf-Ack 并
     * 进入 ACK_SENT，此时我方的 Conf-Req 仍处于未确认状态（例如首次发送时对端 PPP
     * 栈尚未就绪被丢弃）。只在 REQ_SENT 重传会导致永久停在 ACK_SENT，
     * 对端等不到我方 Conf-Req，只能不断 Restart（id 递增）。 */
    if (fsm->state != PPP_FSM_REQ_SENT && fsm->state != PPP_FSM_ACK_SENT)
        return;
    if (fsm->we_acked)
        return;
    if (now - fsm->last_tx_ms < PPP_RESTART_MS)
        return;

    if (fsm->retries >= PPP_MAX_CONFREQ) {
        VPN_ERROR("%s: no reply after %d Configure-Request retransmits, connection failed",
                  proto == PPP_PROTO_LCP ? "LCP" : "IPCP", fsm->retries);
        fsm->state = PPP_FSM_STOPPED;
        if (proto == PPP_PROTO_LCP) {
            if (p->cbs.closed)
                p->cbs.closed(p->cbs.ctx, "LCP negotiation timed out");
        }
        return;
    }

    fsm->retries++;
    {
        uint8_t opts[PPP_MAX_OPTS];
        int len = ppp_build_conf_req(p, fsm, proto, opts, sizeof(opts));
        VPN_DEBUG("%s: retransmitting Configure-Request (attempt %d)",
                  proto == PPP_PROTO_LCP ? "LCP" : "IPCP", fsm->retries);
        ppp_send_fsm(p, fsm, proto, PPP_CODE_CONF_REQ, fsm->id, opts, (size_t)len);
    }
}

/* ------------------------------------------------------------------ */
/* 选项构造                                                            */
/* ------------------------------------------------------------------ */

/* ppp_net 里的地址字段是主机序，vpn_ip_ntoa 期待网络序，不能直接混用 */
static const char *ppp_ip_str(uint32_t host, char *buf, size_t cap)
{
    snprintf(buf, cap, "%u.%u.%u.%u", (unsigned)((host >> 24) & 0xff),
             (unsigned)((host >> 16) & 0xff), (unsigned)((host >> 8) & 0xff),
             (unsigned)(host & 0xff));
    return buf;
}

static int put_opt(uint8_t *buf, size_t cap, size_t *pos, uint8_t type,
                   const void *val, uint8_t len)
{
    if (*pos + 2 + len > cap)
        return -1;
    buf[(*pos)++] = type;
    buf[(*pos)++] = (uint8_t)(2 + len);
    if (len)
        memcpy(buf + *pos, val, len);
    *pos += len;
    return 0;
}

int ppp_build_conf_req(vpn_ppp *p, ppp_fsm *fsm, uint16_t proto, uint8_t *buf, size_t cap)
{
    size_t pos = 0;

    (void)fsm;

    if (proto == PPP_PROTO_LCP) {
        uint8_t mru[2];
        uint8_t magic[4];

        vpn_put_be16(mru, (uint16_t)(p->cfg.mru ? p->cfg.mru : 1400));
        put_opt(buf, cap, &pos, LCP_OPT_MRU, mru, 2);

        /* 不协商 ACCM：RouterOS 会 Conf-Reject 该选项 */

        vpn_put_be32(magic, p->magic);
        put_opt(buf, cap, &pos, LCP_OPT_MAGIC, magic, 4);

        /* 不请求 PFC/ACFC：保证与 MikroTik 的最大兼容性 */
        return (int)pos;
    }

    if (proto == PPP_PROTO_IPCP) {
        uint8_t addr[4];
        uint8_t dns[4];

        vpn_put_be32(addr, p->want_local_ip);
        put_opt(buf, cap, &pos, IPCP_OPT_ADDR, addr, 4);

        /* 地址与 DNS 都先请求 0.0.0.0：服务器会用 Nak 把实际值告知，
         * 这是 pppd 的标准做法（RouterOS 同样按此响应）。
         * 若服务器 Reject 了 DNS 选项（部分实现不支持），下一轮不再携带。 */
        if (!p->ipcp_no_dns1) {
            vpn_put_be32(dns, p->want_dns1);
            put_opt(buf, cap, &pos, IPCP_OPT_DNS1, dns, 4);
        }
        if (!p->ipcp_no_dns2) {
            vpn_put_be32(dns, p->want_dns2);
            put_opt(buf, cap, &pos, IPCP_OPT_DNS2, dns, 4);
        }
        return (int)pos;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* 选项处理                                                            */
/* ------------------------------------------------------------------ */
int ppp_process_conf_req(vpn_ppp *p, uint16_t proto, const uint8_t *opts, size_t len,
                         uint8_t *out, size_t cap, size_t *out_len, bool *reject)
{
    size_t pos = 0, opos = 0;

    *reject = false;

    while (pos + 2 <= len) {
        uint8_t type = opts[pos];
        uint8_t olen = opts[pos + 1];
        const uint8_t *val = opts + pos + 2;

        if (olen < 2 || pos + olen > len) {
            VPN_WARN("PPP option malformed (type=%u len=%u)", type, olen);
            break;
        }

        if (proto == PPP_PROTO_LCP) {
            switch (type) {
            case LCP_OPT_MRU:
                if (olen == 4) {
                    uint16_t mru = vpn_be16(val);
                    p->peer_mru = mru < 576 ? 576 : (mru > 1500 ? 1500 : mru);
                    memcpy(out + opos, opts + pos, olen);
                    opos += olen;
                } else {
                    *reject = true;
                    memcpy(out + opos, opts + pos, olen);
                    opos += olen;
                }
                break;
            case LCP_OPT_ACCM:
                if (olen == 6) {
                    p->peer_accm = vpn_be32(val);
                    memcpy(out + opos, opts + pos, olen);
                    opos += olen;
                } else {
                    *reject = true;
                    memcpy(out + opos, opts + pos, olen);
                    opos += olen;
                }
                break;
            case LCP_OPT_AUTH:
                if (olen >= 4) {
                    uint16_t ap = vpn_be16(val);
                    if (ap == PPP_PROTO_CHAP && olen >= 5) {
                        /* LCP 里的算法编号与 CHAP 报文内的算法字节不同 */
                        if (val[2] == CHAP_LCP_ALG_MSCHAPV2)
                            p->chap_alg = CHAP_ALG_MSCHAPV2;
                        else if (val[2] == CHAP_LCP_ALG_MSCHAPV1)
                            p->chap_alg = CHAP_ALG_MSCHAPV1;
                        else
                            p->chap_alg = val[2];
                    }
                    p->auth_required = true;
                    /* 对端每个 Conf-Req 都带认证选项，只在首次/变更时打印，
                     * 否则重传期间这一行会重复十几遍 */
                    if (p->auth_proto != ap)
                        VPN_INFO("server requested authentication: %s%s",
                                 ap == PPP_PROTO_CHAP ? "CHAP" : "PAP",
                                 ap == PPP_PROTO_CHAP
                                     ? (p->chap_alg == CHAP_ALG_MSCHAPV2 ? " (MS-CHAPv2)"
                                        : p->chap_alg == CHAP_ALG_MD5 ? " (MD5)"
                                                                      : " (unknown algorithm)")
                                     : "");
                    p->auth_proto = ap;
                    memcpy(out + opos, opts + pos, olen);
                    opos += olen;
                } else {
                    *reject = true;
                    memcpy(out + opos, opts + pos, olen);
                    opos += olen;
                }
                break;
            case LCP_OPT_MAGIC:
                if (olen == 6) {
                    p->peer_magic = vpn_be32(val);
                    if (p->peer_magic == p->magic) {
                        /* 魔数回环，回应 Nak 建议换一个 */
                        uint8_t fixed[6] = { LCP_OPT_MAGIC, 6, 0, 0, 0, 0 };
                        vpn_put_be32(fixed + 2, vpn_rand_u32());
                        memcpy(out + opos, fixed, 6);
                        opos += 6;
                        *reject = false;
                        VPN_WARN("LCP magic number conflict, replied Nak with a new value");
                    } else {
                        memcpy(out + opos, opts + pos, olen);
                        opos += olen;
                    }
                } else {
                    *reject = true;
                    memcpy(out + opos, opts + pos, olen);
                    opos += olen;
                }
                break;
            case LCP_OPT_PFC:
                p->peer_pfc = true;
                memcpy(out + opos, opts + pos, olen);
                opos += olen;
                break;
            case LCP_OPT_ACFC:
                p->peer_acfc = true;
                memcpy(out + opos, opts + pos, olen);
                opos += olen;
                break;
            default:
                VPN_WARN("LCP unknown option type=%u, sending Configure-Reject", type);
                *reject = true;
                memcpy(out + opos, opts + pos, olen);
                opos += olen;
                break;
            }
        } else if (proto == PPP_PROTO_IPCP) {
            switch (type) {
            case IPCP_OPT_ADDR:
                if (olen == 6) {
                    p->net.peer_ip = vpn_be32(val);
                    /* 用服务器给的地址作为我们的对端地址，Ack 回去 */
                    memcpy(out + opos, opts + pos, olen);
                    opos += olen;
                } else {
                    *reject = true;
                    memcpy(out + opos, opts + pos, olen);
                    opos += olen;
                }
                break;
            case IPCP_OPT_DNS1:
                if (olen == 6) {
                    p->net.dns1 = vpn_be32(val);
                    VPN_INFO("IPCP: server request carries DNS1 %s",
                             ppp_ip_str(p->net.dns1, (char[16]){ 0 }, 16));
                    memcpy(out + opos, opts + pos, olen);
                    opos += olen;
                } else {
                    *reject = true;
                    memcpy(out + opos, opts + pos, olen);
                    opos += olen;
                }
                break;
            case IPCP_OPT_DNS2:
                if (olen == 6) {
                    p->net.dns2 = vpn_be32(val);
                    VPN_INFO("IPCP: server request carries DNS2 %s",
                             ppp_ip_str(p->net.dns2, (char[16]){ 0 }, 16));
                    memcpy(out + opos, opts + pos, olen);
                    opos += olen;
                } else {
                    *reject = true;
                    memcpy(out + opos, opts + pos, olen);
                    opos += olen;
                }
                break;
            default:
                *reject = true;
                memcpy(out + opos, opts + pos, olen);
                opos += olen;
                break;
            }
        }

        pos += olen;
    }

    (void)cap;
    *out_len = opos;
    return 0;
}

/* ------------------------------------------------------------------ */
/* 收包处理                                                            */
/* ------------------------------------------------------------------ */
void ppp_fsm_rx_ack(vpn_ppp *p, ppp_fsm *fsm, uint8_t id, bool ipcp)
{
    if (id != fsm->id) {
        VPN_DEBUG("%s: ignoring stale Ack (id=%u, expected %u)", ipcp ? "IPCP" : "LCP", id, fsm->id);
        return;
    }
    if (fsm->we_acked)
        return;

    fsm->we_acked = true;
    fsm->retries = 0;
    VPN_INFO("%s: server acknowledged our Configure-Request", ipcp ? "IPCP" : "LCP");

    if (fsm->peer_acked) {
        fsm->state = PPP_FSM_OPEN;
        fsm->opened_ms = vpn_now_ms();
        VPN_INFO("%s: entered Open state", ipcp ? "IPCP" : "LCP");
        if (ipcp) {
            p->net.local_ip = p->want_local_ip;
            if (!p->net.dns1)
                p->net.dns1 = p->want_dns1;
            if (!p->net.dns2)
                p->net.dns2 = p->want_dns2;
            p->up = true;
            p->net.mtu = p->cfg.mtu ? p->cfg.mtu : 1400;
            if (p->cbs.up)
                p->cbs.up(p->cbs.ctx, &p->net);
        } else {
            ppp_auth_start(p);
        }
    } else {
        fsm->state = PPP_FSM_ACK_RCVD;
    }
}

void ppp_fsm_rx_conf_req(vpn_ppp *p, ppp_fsm *fsm, uint16_t proto, uint8_t id,
                         const uint8_t *opts, size_t len)
{
    uint8_t out[PPP_MAX_OPTS];
    size_t out_len = 0;
    bool reject = false;
    bool ipcp = (proto == PPP_PROTO_IPCP);

    ppp_process_conf_req(p, proto, opts, len, out, sizeof(out), &out_len, &reject);

    if (reject)
        ppp_send_fsm(p, fsm, proto, PPP_CODE_CONF_REJ, id, out, out_len);
    else
        ppp_send_fsm(p, fsm, proto, PPP_CODE_CONF_ACK, id, out, out_len);

    fsm->peer_acked = true;
    fsm->last_rx_ms = vpn_now_ms();

    if (fsm->we_acked) {
        if (fsm->state != PPP_FSM_OPEN) {
            fsm->state = PPP_FSM_OPEN;
            fsm->opened_ms = vpn_now_ms();
            VPN_INFO("%s: entered Open state", ipcp ? "IPCP" : "LCP");
            if (ipcp) {
                p->net.local_ip = p->want_local_ip;
                if (!p->net.dns1)
                    p->net.dns1 = p->want_dns1;
                if (!p->net.dns2)
                    p->net.dns2 = p->want_dns2;
                p->up = true;
                p->net.mtu = p->cfg.mtu ? p->cfg.mtu : 1400;
                if (p->cbs.up)
                    p->cbs.up(p->cbs.ctx, &p->net);
            } else {
                ppp_auth_start(p);
            }
        }
    } else {
        fsm->state = PPP_FSM_ACK_SENT;
    }
}

void ppp_fsm_rx_term_req(vpn_ppp *p, ppp_fsm *fsm, uint16_t proto, uint8_t id)
{
    ppp_send_fsm(p, fsm, proto, PPP_CODE_TERM_ACK, id, NULL, 0);
    fsm->state = PPP_FSM_STOPPED;
    VPN_WARN("%s: server requested disconnect", proto == PPP_PROTO_LCP ? "LCP" : "IPCP");
    if (proto == PPP_PROTO_LCP) {
        p->up = false;
        if (p->cbs.closed)
            p->cbs.closed(p->cbs.ctx, "server terminated the PPP session");
    }
}

static void handle_lcp(vpn_ppp *p, const uint8_t *pl, size_t len)
{
    uint8_t code, id;
    uint16_t plen;

    if (len < 4)
        return;
    code = pl[0];
    id = pl[1];
    plen = vpn_be16(pl + 2);
    if (plen < 4 || plen > len)
        plen = (uint16_t)len;

    p->lcp.last_rx_ms = vpn_now_ms();
    p->lcp.rx_count++;

    /* 只把真正推进协商的帧留在 INFO（2/3/4 Ack/Nak/Rej、5/6 Terminate、
     * 7/8 Code/Protocol-Reject）；其余都是周期性噪声：
     *   - code=1  对端重传的 Conf-Req，一次连接能来十几遍
     *   - code=9  对端 Echo-Request（保活探测）
     *   - code=10 对端 Echo-Reply：我们自己每 5 秒发一次 Echo-Request
     *             做保活，服务器逐条回，若不屏蔽就是每 5 秒一条日志 */
    if (code == PPP_CODE_CONF_REQ || code == PPP_CODE_ECHO_REQ ||
        code == PPP_CODE_ECHO_REPLY || code == PPP_CODE_DISC_REQ)
        VPN_DEBUG("LCP: received code=%u id=%u len=%u", code, id, plen);
    else
        VPN_INFO("LCP: received code=%u id=%u len=%u", code, id, plen);

    switch (code) {
    case PPP_CODE_CONF_REQ:
        ppp_fsm_rx_conf_req(p, &p->lcp, PPP_PROTO_LCP, id, pl + 4, plen - 4);
        break;
    case PPP_CODE_CONF_ACK:
        ppp_fsm_rx_ack(p, &p->lcp, id, false);
        break;
    case PPP_CODE_CONF_NAK:
        VPN_DEBUG("LCP: server Nak\'d our request (ignored, will resend)");
        p->lcp.we_acked = false;
        p->lcp.last_tx_ms = 0;
        break;
    case PPP_CODE_CONF_REJ:
        VPN_WARN("LCP: server rejected our options %s", vpn_hexdump(pl + 4, plen - 4));
        p->lcp.we_acked = false;
        p->lcp.last_tx_ms = 0;
        break;
    case PPP_CODE_TERM_REQ:
        ppp_fsm_rx_term_req(p, &p->lcp, PPP_PROTO_LCP, id);
        break;
    case PPP_CODE_TERM_ACK:
        p->lcp.state = PPP_FSM_STOPPED;
        break;
    case PPP_CODE_ECHO_REQ: {
        uint8_t buf[8];
        if (plen - 4 >= 4) {
            memcpy(buf, pl + 4, 4);
            vpn_put_be32(buf, p->magic);
        }
        ppp_send_fsm(p, &p->lcp, PPP_PROTO_LCP, PPP_CODE_ECHO_REPLY, id, buf, 4);
        break;
    }
    case PPP_CODE_ECHO_REPLY:
        break;
    default:
        VPN_DEBUG("LCP: unhandled code=%u", code);
        break;
    }
}

static void handle_ipcp(vpn_ppp *p, const uint8_t *pl, size_t len)
{
    uint8_t code, id;
    uint16_t plen;

    if (len < 4)
        return;
    code = pl[0];
    id = pl[1];
    plen = vpn_be16(pl + 2);
    if (plen < 4 || plen > len)
        plen = (uint16_t)len;

    p->ipcp.rx_count++;

    switch (code) {
    case PPP_CODE_CONF_REQ:
        ppp_fsm_rx_conf_req(p, &p->ipcp, PPP_PROTO_IPCP, id, pl + 4, plen - 4);
        break;
    case PPP_CODE_CONF_ACK:
        ppp_fsm_rx_ack(p, &p->ipcp, id, true);
        break;
    case PPP_CODE_CONF_NAK: {
        /* 解析 Nak 里的建议值：地址/DNS 采用服务器建议，重发 Configure-Request */
        const uint8_t *opts = pl + 4;
        size_t olen = plen - 4, pos = 0;
        bool changed = false;

        while (pos + 2 <= olen) {
            uint8_t t = opts[pos], l = opts[pos + 1];
            if (l < 2 || pos + l > olen)
                break;
            if (t == IPCP_OPT_ADDR && l == 6) {
                uint32_t a = vpn_be32(opts + pos + 2);
                if (a && a != p->want_local_ip) {
                    p->want_local_ip = a;
                    changed = true;
                }
            } else if (t == IPCP_OPT_DNS1 && l == 6) {
                uint32_t d = vpn_be32(opts + pos + 2);
                p->want_dns1 = d;
                if (d)
                    p->net.dns1 = d;   /* 服务器 Nak 出的 DNS 即刻生效 */
                changed = true;
                VPN_INFO("IPCP: server assigned DNS1 %s", ppp_ip_str(d, (char[16]){ 0 }, 16));
            } else if (t == IPCP_OPT_DNS2 && l == 6) {
                uint32_t d = vpn_be32(opts + pos + 2);
                p->want_dns2 = d;
                if (d)
                    p->net.dns2 = d;
                changed = true;
                VPN_INFO("IPCP: server assigned DNS2 %s", ppp_ip_str(d, (char[16]){ 0 }, 16));
            }
            pos += l;
        }

        if (p->ipcp.retries++ < PPP_MAX_CONFREQ && changed) {
            uint8_t opts_out[PPP_MAX_OPTS];
            int n = ppp_build_conf_req(p, &p->ipcp, PPP_PROTO_IPCP, opts_out, sizeof(opts_out));
            p->ipcp.id++;
            ppp_send_fsm(p, &p->ipcp, PPP_PROTO_IPCP, PPP_CODE_CONF_REQ, p->ipcp.id,
                         opts_out, (size_t)n);
        }
        break;
    }
    case PPP_CODE_CONF_REJ: {
        const uint8_t *opts = pl + 4;
        size_t olen = plen - 4, pos = 0;

        /* 服务器拒绝我方提议的选项属于正常协商（比如它不认某个 DNS
         * 选项），随后会带自己的提议重来，不该报成警告 */
        VPN_DEBUG("IPCP: server rejected options %s", vpn_hexdump(opts, olen));
        /* RFC 1661 §5.4：被拒选项必须从后续 Configure-Request 中移除并重发。
         * 注意按项处理：RouterOS 常只 Reject DNS2，此时 DNS1 仍可继续协商。 */
        while (pos + 2 <= olen) {
            uint8_t t = opts[pos], l = opts[pos + 1];
            if (l < 2 || pos + l > olen)
                break;
            if (t == IPCP_OPT_DNS1)
                p->ipcp_no_dns1 = true;
            else if (t == IPCP_OPT_DNS2)
                p->ipcp_no_dns2 = true;
            pos += l;
        }

        if (p->ipcp.retries++ < PPP_MAX_CONFREQ) {
            uint8_t opts_out[PPP_MAX_OPTS];
            int n = ppp_build_conf_req(p, &p->ipcp, PPP_PROTO_IPCP, opts_out, sizeof(opts_out));
            p->ipcp.id++;
            ppp_send_fsm(p, &p->ipcp, PPP_PROTO_IPCP, PPP_CODE_CONF_REQ, p->ipcp.id,
                         opts_out, (size_t)n);
        }
        break;
    }
    case PPP_CODE_TERM_REQ:
        ppp_fsm_rx_term_req(p, &p->ipcp, PPP_PROTO_IPCP, id);
        break;
    default:
        break;
    }
}

/* ------------------------------------------------------------------ */
/* 生命周期                                                            */
/* ------------------------------------------------------------------ */
vpn_ppp *vpn_ppp_new(const ppp_config *cfg, const ppp_callbacks *cbs)
{
    vpn_ppp *p = (vpn_ppp *)calloc(1, sizeof(*p));

    if (!p)
        return NULL;

    p->cfg = *cfg;
    p->cbs = *cbs;
    ppp_fsm_init(&p->lcp);
    ppp_fsm_init(&p->ipcp);
    p->magic = vpn_rand_u32();
    p->peer_mru = 1500;
    p->auth_proto = 0;
    p->chap_alg = CHAP_ALG_MSCHAPV2;
    p->want_local_ip = 0;
    p->want_dns1 = 0;
    p->want_dns2 = 0;

    if (cfg->local_ip[0] && strcmp(cfg->local_ip, "0.0.0.0") != 0)
        vpn_ip_parse(cfg->local_ip, &p->want_local_ip);
    if (cfg->dns1[0])
        vpn_ip_parse(cfg->dns1, &p->want_dns1);
    if (cfg->dns2[0])
        vpn_ip_parse(cfg->dns2, &p->want_dns2);

    p->last_keepalive_ms = vpn_now_ms();
    return p;
}

void vpn_ppp_free(vpn_ppp *p)
{
    free(p);
    if (p)
        VPN_DEBUG("PPP session released");
}

void vpn_ppp_start(vpn_ppp *p, int64_t now_ms)
{
    p->lcp.state = PPP_FSM_STARTING;
    p->ipcp.state = PPP_FSM_INITIAL;
    p->up = false;
    p->closed = false;
    p->auth_done = false;
    p->auth_started = false;
    p->auth_required = false;
    p->last_keepalive_ms = now_ms;
    ppp_fsm_open(p, &p->lcp, PPP_PROTO_LCP);
}

void vpn_ppp_input(vpn_ppp *p, const uint8_t *frame, size_t len, int64_t now_ms)
{
    uint16_t proto;
    const uint8_t *payload;
    size_t plen;

    if (!p || len < 2 || p->closed)
        return;

    proto = vpn_be16(frame);
    payload = frame + 2;
    plen = len - 2;

    switch (proto) {
    case PPP_PROTO_LCP:
        handle_lcp(p, payload, plen);
        break;
    case PPP_PROTO_IPCP:
        handle_ipcp(p, payload, plen);
        break;
    case PPP_PROTO_CHAP:
        ppp_auth_rx_chap(p, payload, plen);
        break;
    case PPP_PROTO_PAP:
        ppp_auth_rx_pap(p, payload, plen);
        break;
    case PPP_PROTO_IP:
    case PPP_PROTO_IPV6:
        if (p->up) {
            if (p->cbs.ip)
                p->cbs.ip(p->cbs.ctx, payload, plen);
        } else {
            VPN_TRACE("PPP not up yet, dropping %zu bytes of IP packet", plen);
        }
        break;
    case PPP_PROTO_IPV6CP: {
        /* 不使用 IPv6：按 RFC 1661 §5.6 回 LCP Protocol-Reject，让服务器停止发送 */
        uint8_t rej[2 + 64];
        size_t n = plen < sizeof(rej) - 2 ? plen : sizeof(rej) - 2;

        vpn_put_be16(rej, PPP_PROTO_IPV6CP);
        if (n)
            memcpy(rej + 2, payload, n);
        ppp_send_fsm(p, &p->lcp, PPP_PROTO_LCP, PPP_CODE_PROTO_REJ,
                     ++p->misc_id, rej, n + 2);
        VPN_INFO("PPP: rejecting IPv6CP (Protocol-Reject)");
        break;
    }
    default: {
        /* RFC 1661 §5.6：对不支持的协议必须回 LCP Protocol-Reject。
         * 沉默会被对端当作链路故障：RouterOS 会无限重发 MPLSCP/CCP Conf-Req，
         * 约 30 秒后判定 PPP 无响应并发 StopCCN 踢掉整个隧道。 */
        uint8_t rej[2 + 64];
        size_t n = plen < sizeof(rej) - 2 ? plen : sizeof(rej) - 2;

        vpn_put_be16(rej, proto);
        if (n)
            memcpy(rej + 2, payload, n);
        ppp_send_fsm(p, &p->lcp, PPP_PROTO_LCP, PPP_CODE_PROTO_REJ,
                     ++p->misc_id, rej, n + 2);
        VPN_DEBUG("PPP: unknown protocol 0x%04x, sent Protocol-Reject", proto);
        break;
    }
    }
    (void)now_ms;
}

void vpn_ppp_tick(vpn_ppp *p, int64_t now_ms)
{
    if (p->closed)
        return;

    ppp_fsm_tick(p, &p->lcp, PPP_PROTO_LCP, now_ms);
    if (p->lcp.state == PPP_FSM_OPEN)
        ppp_fsm_tick(p, &p->ipcp, PPP_PROTO_IPCP, now_ms);

    /* LCP Echo 保活。
     * 间隔必须小于对端 keepalive-timeout：RouterOS 的 l2tp-server 默认 10 秒，
     * 连续 3 次收不到我方报文就发 StopCCN 踢隧道（原来 15 秒间隔，实测每次
     * 都在 30 秒整被踢）。取 5 秒安全。
     * Magic-Number 必须按网络序写入：曾直接把 uint32_t 主机序内存发出去，
     * 抓包可见 Conf-Req 是 918ef607 而 Echo 变成 07f68e91（字节反序）。 */
    if (p->lcp.state == PPP_FSM_OPEN && now_ms - p->last_keepalive_ms > 5000) {
        uint8_t mb[4];
        p->last_keepalive_ms = now_ms;
        p->echo_id++;
        vpn_put_be32(mb, p->magic);
        ppp_send_fsm(p, &p->lcp, PPP_PROTO_LCP, PPP_CODE_ECHO_REQ,
                     p->echo_id, mb, 4);
    }
}

int vpn_ppp_send_ip(vpn_ppp *p, const uint8_t *pkt, size_t len)
{
    if (!p || !p->up || p->closed)
        return VPN_ERR_INVALID;
    if (len + 2 > sizeof(p->txbuf))
        return VPN_ERR_INVALID;

    p->txbuf[0] = (uint8_t)(PPP_PROTO_IP >> 8);
    p->txbuf[1] = (uint8_t)PPP_PROTO_IP;
    memcpy(p->txbuf + 2, pkt, len);
    if (p->cbs.send)
        p->cbs.send(p->cbs.ctx, p->txbuf, len + 2);
    return VPN_OK;
}

bool vpn_ppp_is_up(const vpn_ppp *p) { return p && p->up && !p->closed; }

void vpn_ppp_close(vpn_ppp *p, const char *reason)
{
    if (!p)
        return;
    if (p->up) {
        ppp_fsm_close(p, &p->ipcp, PPP_PROTO_IPCP, reason);
        ppp_fsm_close(p, &p->lcp, PPP_PROTO_LCP, reason);
    }
    p->up = false;
    p->closed = true;
    VPN_INFO("PPP session closed: %s", reason ? reason : "-");
}

bool vpn_ppp_mppe_keys(const vpn_ppp *p, uint8_t send_key[16], uint8_t recv_key[16])
{
    if (!p || !p->has_mppe)
        return false;
    memcpy(send_key, p->mppe_send_key, 16);
    memcpy(recv_key, p->mppe_recv_key, 16);
    return true;
}

bool vpn_ppp_has_session_key(const vpn_ppp *p) { return p && p->has_mppe; }

void vpn_ppp_get_net(const vpn_ppp *p, ppp_net_info *out)
{
    if (p && out)
        *out = p->net;
}

void vpn_ppp_dump(vpn_ppp *p, char *out, size_t outlen)
{
    char ip[32], peer[32], d1[32], d2[32];

    if (!p || !out)
        return;

    ppp_ip_str(p->net.local_ip, ip, sizeof(ip));
    ppp_ip_str(p->net.peer_ip, peer, sizeof(peer));
    ppp_ip_str(p->net.dns1, d1, sizeof(d1));
    ppp_ip_str(p->net.dns2, d2, sizeof(d2));

    snprintf(out, outlen,
             "LCP=%s IPCP=%s up=%d local=%s peer=%s dns=%s,%s mru=%u auth=%s mschapv2=%d "
             "lcp_rx=%u lcp_tx=%u",
             vpn_ppp_fsm_name(p->lcp.state), vpn_ppp_fsm_name(p->ipcp.state), p->up ? 1 : 0,
             ip, peer, d1, d2, p->peer_mru,
             p->auth_proto == PPP_PROTO_PAP ? "PAP"
             : p->auth_proto == PPP_PROTO_CHAP ? "CHAP" : "none",
             p->has_mppe ? 1 : 0, p->lcp.rx_count, p->lcp.tx_count);
}
