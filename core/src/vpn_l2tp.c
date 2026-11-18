/* SPDX-License-Identifier: LicenseRef-Proprietary
   Copyright (c) 2026 wwm-spec. All rights reserved.
 */

/* vpn_l2tp.c - L2TPv2 客户端（RFC 2661，voluntary tunnel / LAC 模式）
 *
 * IPsec：psk 非空时本模块自行完成 IKEv1 主模式 + Quick Mode，之后所有 L2TP
 * 报文经 ESP transport（NAT-T UDP/4500）收发。这样 Android/Windows 都不需要
 * root、不需要系统 strongSwan，也不需要 IP 协议 50 的能力。
 */
#include "vpncore/vpn_l2tp.h"
#include "vpncore/vpn_buf.h"
#include "vpncore/vpn_crypto.h"
#include "vpncore/vpn_error.h"
#include "vpncore/vpn_ike.h"
#include "vpncore/vpn_log.h"
#include "vpncore/vpn_net.h"
#include "vpncore/vpn_platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* SCCRQ 重传：原来只发一次，第一个包在 NAT/防火墙上丢掉就必然超时，
 * 而 RFC 2661 本来就允许重传（Ns 不变、Tie Breaker 不变，属标准重传语义） */
#define L2TP_SCCRQ_RTO_MS   2000
#define L2TP_SCCRQ_MAX_RETX 5

/* 控制消息 Message Type */
#define L2TP_MSG_SCCRQ  1
#define L2TP_MSG_SCCRP  2
#define L2TP_MSG_SCCCN  3
#define L2TP_MSG_STOPCCN 4
/* HELLO 必须是 6。这里曾误写为 5（5 在 RFC 2661 中保留未定义），
 * 结果是客户端每 30 秒保活发出一条 Message-Type=5 的控制消息，
 * RouterOS 侧日志为 "tunnel 457 received unknown message, disconnecting"，
 * 随即回 StopCCN 拆隧道——现象就是"连上整 30 秒必断、被踢后重连"。
 * 注意 ICRQ/ICRP/ICCN/CDN 用 10/11/12/14（与 RouterOS、xl2tpd 一致），
 * 抓包实测确认，不要按 RFC 文本改成 7/8/10/11。 */
#define L2TP_MSG_HELLO  6
#define L2TP_MSG_ICRQ   10
#define L2TP_MSG_ICRP   11
#define L2TP_MSG_ICCN   12
#define L2TP_MSG_CDN    14

/* AVP 类型 */
#define AVP_MESSAGE_TYPE    0
#define AVP_RESULT_CODE     1
#define AVP_PROTOCOL_VER    2
#define AVP_FRAMING_CAP     3
#define AVP_BEARER_CAP      4
#define AVP_TIE_BREAKER     5
#define AVP_HOST_NAME       7
#define AVP_VENDOR_NAME     8
#define AVP_ASSIGNED_TUNNEL 9
#define AVP_RECV_WINDOW     10
#define AVP_ASSIGNED_SESSION 14
#define AVP_CALL_SERIAL     15
#define AVP_FRAMING_TYPE    19
#define AVP_TX_CONNECT_SPEED 24
#define AVP_RX_CONNECT_SPEED 38
#define AVP_BEARER_TYPE     18
#define AVP_PHYS_CHAN       24
#define AVP_FIRMWARE_VER    6

#define L2TP_HEADER_LEN 12
#define L2TP_MAX_PKT    1600

struct vpn_l2tp {
    vpn_l2tp_params p;
    vpn_l2tp_cbs   cbs;

    vpn_sock_t      sock;
    vpn_ipsec      *ipsec;      /* 非空时 L2TP 报文走 ESP */
    uint8_t         rx[L2TP_MAX_PKT];
    size_t          rxlen;

    uint16_t        our_tunnel_id;
    uint16_t        peer_tunnel_id;
    /* 对端（服务器）在报文头部使用的隧道号：RouterOS 在它发出的每个控制消息
     * 头部固定填自己的 tunnel id。用于过滤不属于本隧道的消息。 */
    uint16_t        srv_tunnel_id;
    uint16_t        our_session_id;
    uint16_t        peer_session_id;
    uint16_t        ns;   /* 下一个发送序号 */
    uint16_t        nr;   /* 期望接收序号 */
    bool            have_peer_tunnel;
    bool            have_peer_session;
    uint32_t        peer_framing;   /* SCCRP 中服务器声明的 Framing Capability */
    uint16_t        data_ns;        /* 数据通道发送序号（仅在 S=1 时使用） */
    uint16_t        data_nr;        /* 数据通道期望接收序号（仅在 S=1 时使用） */
    bool            open;
    int64_t         last_rx_ms;
    char            reason[192];
};

/* ------------------------------------------------------------------ */
/* AVP 构造                                                            */
/* ------------------------------------------------------------------ */
static int avp_put(uint8_t *buf, size_t cap, size_t *pos, uint16_t type,
                   const void *val, size_t vlen)
{
    size_t need = 6 + vlen;

    if (*pos + need > cap || vlen > 1023)
        return -1;

    vpn_put_be16(buf + *pos, (uint16_t)(0x8000 | (need & 0x03ff))); /* M=1, L=len */
    vpn_put_be16(buf + *pos + 2, 0);                                /* Vendor ID */
    vpn_put_be16(buf + *pos + 4, type);
    if (vlen)
        memcpy(buf + *pos + 6, val, vlen);
    *pos += need;
    return 0;
}

static int avp_put_u16(uint8_t *buf, size_t cap, size_t *pos, uint16_t type, uint16_t v)
{
    uint8_t tmp[2];
    vpn_put_be16(tmp, v);
    return avp_put(buf, cap, pos, type, tmp, 2);
}

/* 控制消息封装：返回值 = 总长度 */
static int l2tp_build_control(uint8_t *out, size_t cap, uint16_t tunnel_id,
                              uint16_t session_id, uint16_t ns, uint16_t nr,
                              const uint8_t *avps, size_t alen)
{
    size_t total = L2TP_HEADER_LEN + alen;

    if (cap < total)
        return -1;

    vpn_put_be16(out, 0xC802); /* T=1,L=1,S=1,Ver=2 */
    vpn_put_be16(out + 2, (uint16_t)total);
    vpn_put_be16(out + 4, tunnel_id);
    vpn_put_be16(out + 6, session_id);
    vpn_put_be16(out + 8, ns);
    vpn_put_be16(out + 10, nr);
    if (alen)
        memcpy(out + L2TP_HEADER_LEN, avps, alen);
    return (int)total;
}

int vpn_l2tp_build_sccrq(uint8_t *out, size_t cap, uint16_t tunnel_id,
                         uint16_t recv_window, const char *hostname)
{
    uint8_t avps[256];
    size_t pos = 0;
    uint8_t proto[2] = { 0x01, 0x00 }; /* L2TPv2 */
    uint8_t fram[4] = { 0x00, 0x00, 0x00, 0x03 };
    uint8_t tie[8];

    for (int i = 0; i < 8; i++)
        tie[i] = (uint8_t)(vpn_rand_u32() >> (i * 4));

    avp_put_u16(avps, sizeof(avps), &pos, AVP_MESSAGE_TYPE, L2TP_MSG_SCCRQ);
    avp_put(avps, sizeof(avps), &pos, AVP_PROTOCOL_VER, proto, 2);
    avp_put(avps, sizeof(avps), &pos, AVP_FRAMING_CAP, fram, 4);
    {
        /* 与 xl2tpd 对齐：Bearer Capability 报 0，另报 Firmware Revision */
        uint8_t bear0[4] = { 0x00, 0x00, 0x00, 0x00 };
        uint8_t firm[2] = { 0x06, 0x90 };        /* 1680 */

        avp_put(avps, sizeof(avps), &pos, AVP_BEARER_CAP, bear0, 4);
        avp_put(avps, sizeof(avps), &pos, AVP_FIRMWARE_VER, firm, 2);
    }
    avp_put(avps, sizeof(avps), &pos, AVP_HOST_NAME, hostname, strlen(hostname));
    avp_put(avps, sizeof(avps), &pos, AVP_VENDOR_NAME, "vpnclient", 9);
    avp_put_u16(avps, sizeof(avps), &pos, AVP_ASSIGNED_TUNNEL, tunnel_id);
    avp_put_u16(avps, sizeof(avps), &pos, AVP_RECV_WINDOW, recv_window);
    /* Tie Breaker 在 RFC 2661 中列为 SCCRQ 必须项，xl2tpd/RouterOS 均会带 */
    avp_put(avps, sizeof(avps), &pos, AVP_TIE_BREAKER, tie, 8);

    return l2tp_build_control(out, cap, 0, 0, 0, 0, avps, pos);
}

int vpn_l2tp_build_icrq(uint8_t *out, size_t cap, uint16_t tunnel_id, uint16_t session_id)
{
    uint8_t avps[64];
    size_t pos = 0;
    uint32_t serial = vpn_rand_u32();

    avp_put_u16(avps, sizeof(avps), &pos, AVP_MESSAGE_TYPE, L2TP_MSG_ICRQ);
    avp_put_u16(avps, sizeof(avps), &pos, AVP_ASSIGNED_SESSION, session_id);
    {
        uint8_t ser[4];
        vpn_put_be32(ser, serial);
        avp_put(avps, sizeof(avps), &pos, AVP_CALL_SERIAL, ser, 4);
    }
    return l2tp_build_control(out, cap, tunnel_id, 0, 0, 0, avps, pos);
}

int vpn_l2tp_build_iccn(uint8_t *out, size_t cap, uint16_t tunnel_id, uint16_t session_id)
{
    uint8_t avps[64];
    size_t pos = 0;
    uint8_t speed[4] = { 0x00, 0x00, 0x00, 0x64 };
    uint8_t framing[4];

    /* 该版本无连接上下文，按 sync(S=2) 生成；实际连接走 l2tp_send_iccn()，
     * 那里会用 SCCRP 协商到的 peer_framing */
    vpn_put_be32(framing, 0x00000002u);

    avp_put_u16(avps, sizeof(avps), &pos, AVP_MESSAGE_TYPE, L2TP_MSG_ICCN);
    avp_put(avps, sizeof(avps), &pos, AVP_TX_CONNECT_SPEED, speed, 4);
    avp_put(avps, sizeof(avps), &pos, AVP_FRAMING_TYPE, framing, 4);
    return l2tp_build_control(out, cap, tunnel_id, session_id, 0, 0, avps, pos);
}

/* ------------------------------------------------------------------ */
/* 发送                                                                */
/* ------------------------------------------------------------------ */
/* 传输层：有 IPsec 时走 ESP，否则直连 UDP/1701                          */
/* ------------------------------------------------------------------ */
static int l2tp_xmit(vpn_l2tp *l, const uint8_t *buf, size_t len)
{
    if (l->ipsec) {
        if (vpn_ipsec_send(l->ipsec, buf, len) < 0) {
            VPN_ERROR("L2TP: ESP 发送失败");
            return VPN_ERR_IO;
        }
        return VPN_OK;
    }
    if (vpn_net_write_all(l->sock, buf, len, l->p.io_timeout_ms) < 0) {
        VPN_ERROR("L2TP: 报文发送失败");
        return VPN_ERR_IO;
    }
    return VPN_OK;
}

static int l2tp_sock(const vpn_l2tp *l)
{
    return l->ipsec ? vpn_ipsec_fd(l->ipsec) : (int)l->sock;
}

static int l2tp_send_ctrl(vpn_l2tp *l, uint16_t type, const uint8_t *avps, size_t alen)
{
    uint8_t pkt[L2TP_MAX_PKT];
    uint16_t sid = 0;

    /* ICCN/CDN 必须填写服务器分配的 Session ID：L2TP 头里的 Session ID 表示
     * "接收方"的会话号，写 0 时服务器无法把该消息关联到具体会话，
     * 会话永远停在非 UP 状态（现象就是 ICCN 之后只收到 ZLB，不下发 LCP）。 */
    if (type == L2TP_MSG_ICCN || type == L2TP_MSG_CDN)
        sid = l->peer_session_id;

    int len = l2tp_build_control(pkt, sizeof(pkt), l->peer_tunnel_id, sid, l->ns, l->nr, avps, alen);

    if (len < 0)
        return VPN_ERR_INVALID;

    l->ns++;
    if (l2tp_xmit(l, pkt, (size_t)len) != VPN_OK) {
        VPN_ERROR("L2TP: 控制消息发送失败");
        return VPN_ERR_IO;
    }
    VPN_DEBUG("L2TP -> type=%u len=%d ns=%u nr=%u", type, len, (unsigned)(l->ns - 1), l->nr);
    return VPN_OK;
}

int vpn_l2tp_send_hello(vpn_l2tp *l)
{
    uint8_t avps[16];
    size_t pos = 0;

    if (!l || !l->open)
        return VPN_ERR_INVALID;

    avp_put_u16(avps, sizeof(avps), &pos, AVP_MESSAGE_TYPE, L2TP_MSG_HELLO);
    return l2tp_send_ctrl(l, L2TP_MSG_HELLO, avps, pos);
}

static int l2tp_send_scccn(vpn_l2tp *l)
{
    uint8_t avps[16];
    size_t pos = 0;

    avp_put_u16(avps, sizeof(avps), &pos, AVP_MESSAGE_TYPE, L2TP_MSG_SCCCN);
    return l2tp_send_ctrl(l, L2TP_MSG_SCCCN, avps, pos);
}

static int l2tp_send_icrq(vpn_l2tp *l, uint16_t session_id)
{
    uint8_t avps[64];
    size_t pos = 0;
    uint8_t serial[4];

    /* Call Serial Number 固定 32 位，写成 2 字节会被 RouterOS 判为
     * "AVP too short" 并影响会话建立（表现为 ICCN 后拿不到 LCP） */
    vpn_put_be32(serial, vpn_rand_u32());
    avp_put_u16(avps, sizeof(avps), &pos, AVP_MESSAGE_TYPE, L2TP_MSG_ICRQ);
    avp_put_u16(avps, sizeof(avps), &pos, AVP_ASSIGNED_SESSION, session_id);
    avp_put(avps, sizeof(avps), &pos, AVP_CALL_SERIAL, serial, 4);
    /* Bearer Type 可选，但 RouterOS 缺了它不会把会话拉起来（xl2tpd 恒定携带） */
    {
        uint8_t bear[4] = { 0x00, 0x00, 0x00, 0x00 };
        avp_put(avps, sizeof(avps), &pos, AVP_BEARER_TYPE, bear, 4);
    }
    return l2tp_send_ctrl(l, L2TP_MSG_ICRQ, avps, pos);
}

static int l2tp_send_iccn(vpn_l2tp *l)
{
    uint8_t avps[64];
    size_t pos = 0;
    uint8_t speed[4] = { 0x00, 0x00, 0x00, 0x00 };   /* 与 xl2tpd 一致报 0 */
    uint8_t framing[4];
    /* Framing Type 报 Async(1)：RouterOS 的 PPP 栈按异步链路处理 L2TP 会话，
     * 回 Sync(2) 会让会话停在非 UP 状态，服务器从此不再下发任何 PPP 帧
     * （xl2tpd 也是固定报 1，可作对照） */
    (void)l->peer_framing;
    vpn_put_be32(framing, 0x00000001u);

    avp_put_u16(avps, sizeof(avps), &pos, AVP_MESSAGE_TYPE, L2TP_MSG_ICCN);
    avp_put(avps, sizeof(avps), &pos, AVP_TX_CONNECT_SPEED, speed, 4);
    avp_put(avps, sizeof(avps), &pos, AVP_FRAMING_TYPE, framing, 4);
    avp_put(avps, sizeof(avps), &pos, AVP_RX_CONNECT_SPEED, speed, 4);
    return l2tp_send_ctrl(l, L2TP_MSG_ICCN, avps, pos);
}

/* ------------------------------------------------------------------ */
/* 解析                                                                */
/* ------------------------------------------------------------------ */
typedef struct {
    uint16_t type;
    const uint8_t *val;
    size_t   len;
} l2tp_avp;

static int l2tp_parse_avps(const uint8_t *data, size_t len, l2tp_avp *out, int max)
{
    size_t pos = 0;
    int n = 0;

    while (pos + 6 <= len && n < max) {
        uint16_t flags = vpn_be16(data + pos);
        size_t alen = flags & 0x03ff;
        uint16_t type = vpn_be16(data + pos + 4);

        if (alen < 6 || pos + alen > len)
            break;

        out[n].type = type;
        out[n].val = data + pos + 6;
        out[n].len = alen - 6;
        n++;
        pos += alen;
    }
    return n;
}

static bool avp_find_u16(const l2tp_avp *avps, int n, uint16_t type, uint16_t *out)
{
    for (int i = 0; i < n; i++) {
        if (avps[i].type == type && avps[i].len >= 2) {
            *out = vpn_be16(avps[i].val);
            return true;
        }
    }
    return false;
}

static bool avp_find_u32(const l2tp_avp *avps, int n, uint16_t type, uint32_t *out)
{
    for (int i = 0; i < n; i++) {
        if (avps[i].type == type && avps[i].len >= 4) {
            *out = vpn_be32(avps[i].val);
            return true;
        }
    }
    return false;
}

static void l2tp_handle_control(vpn_l2tp *l, const uint8_t *pkt, size_t len)
{
    uint16_t tunnel_id, session_id, ns, nr;
    l2tp_avp avps[16];
    int n;
    uint16_t mtype = 0;

    if (len < L2TP_HEADER_LEN) {
        VPN_WARN("L2TP: 控制报文过短");
        return;
    }

    tunnel_id = vpn_be16(pkt + 4);
    session_id = vpn_be16(pkt + 6);
    ns = vpn_be16(pkt + 8);
    nr = vpn_be16(pkt + 10);

    if (ns == l->nr)
        l->nr++;

    n = l2tp_parse_avps(pkt + L2TP_HEADER_LEN, len - L2TP_HEADER_LEN, avps, 16);
    avp_find_u16(avps, n, AVP_MESSAGE_TYPE, &mtype);

    VPN_DEBUG("L2TP <- type=%u tunnel=%u session=%u ns=%u nr=%u", mtype, tunnel_id,
              session_id, ns, nr);

    /* 丢弃不属于本隧道的控制消息。同机若还有别的 L2TP 客户端（例如 xl2tpd
     * 也用源端口 1701），服务器发给它的 CDN/StopCCN 会串到本 socket，
     * 曾导致把别人的 CDN 当成自己断开。 */
    if (l->srv_tunnel_id && tunnel_id && tunnel_id != l->srv_tunnel_id) {
        VPN_DEBUG("L2TP: 忽略其它隧道的消息 tunnel=%u（本隧道=%u）",
                  tunnel_id, l->srv_tunnel_id);
        return;
    }

    switch (mtype) {
    case L2TP_MSG_SCCRP: {
        uint16_t assigned = 0;

        /* 服务器在头部填它自己的隧道号，后续消息应保持一致 */
        l->srv_tunnel_id = tunnel_id;
        l->peer_tunnel_id = tunnel_id;
        if (avp_find_u16(avps, n, AVP_ASSIGNED_TUNNEL, &assigned))
            l->peer_tunnel_id = assigned;
        avp_find_u32(avps, n, AVP_FRAMING_CAP, &l->peer_framing);
        l->have_peer_tunnel = true;
        l->nr = (uint16_t)(ns + 1);
        l->ns = nr; /* 对齐对方期望 */

        VPN_INFO("L2TP: 收到 SCCRP（服务器 tunnel id=%u）", l->peer_tunnel_id);

        l2tp_send_scccn(l);

        l->our_session_id = (uint16_t)(vpn_rand_u32() & 0x7fff);
        if (l->our_session_id == 0)
            l->our_session_id = 1;
        l2tp_send_icrq(l, l->our_session_id);
        break;
    }
    case L2TP_MSG_ICRP: {
        uint16_t assigned = 0;

        l->peer_session_id = session_id;
        if (avp_find_u16(avps, n, AVP_ASSIGNED_SESSION, &assigned))
            l->peer_session_id = assigned;
        l->have_peer_session = true;

        VPN_INFO("L2TP: 收到 ICRP（服务器 session id=%u），发送 ICCN",
                 l->peer_session_id);

        l2tp_send_iccn(l);
        l->open = true;
        if (l->cbs.on_connected)
            l->cbs.on_connected(l->cbs.ctx);
        break;
    }
    case L2TP_MSG_STOPCCN:
        snprintf(l->reason, sizeof(l->reason), "服务器停止控制连接 (StopCCN)");
        l->open = false;
        if (l->cbs.on_closed)
            l->cbs.on_closed(l->cbs.ctx, l->reason);
        break;
    case L2TP_MSG_CDN:
        snprintf(l->reason, sizeof(l->reason), "服务器断开呼叫 (CDN)");
        l->open = false;
        if (l->cbs.on_closed)
            l->cbs.on_closed(l->cbs.ctx, l->reason);
        break;
    case L2TP_MSG_HELLO:
        /* RouterOS 每 30 秒向隧道发一次 HELLO，并要求用 ZLB（只带头部、Nr=ns+1）
         * 回执。原来这里直接 break，从不回 ACK，控制通道的对端重传计数会累积。 */
        l2tp_send_ctrl(l, 0, NULL, 0);
        break;
    default:
        VPN_DEBUG("L2TP: 未处理控制消息 type=%u", mtype);
        break;
    }
}

static void l2tp_handle_data(vpn_l2tp *l, const uint8_t *pkt, size_t len)
{
    /* 数据头：6 或 8 字节（有/无序号），这里按 S/L 位解析 */
    uint16_t flags = vpn_be16(pkt);
    size_t hdr = 2;
    bool has_len = (flags & 0x4000) != 0;
    bool has_seq = (flags & 0x0800) != 0;

    if (has_len)
        hdr += 2;
    hdr += 4; /* tunnel + session id */
    if (has_seq)
        hdr += 4;

    if (len <= hdr || hdr > 16) {
        VPN_TRACE("L2TP: 数据报文头异常");
        return;
    }

    {
        const uint8_t *ppp = pkt + hdr;
        size_t plen = len - hdr;

        /* 对端可能带 HDLC 的 Address/Control（0xFF 0x03），剥掉再交给 PPP 层 */
        if (plen >= 2 && ppp[0] == 0xff && ppp[1] == 0x03) {
            ppp += 2;
            plen -= 2;
        }
        if (l->cbs.on_ppp && plen)
            l->cbs.on_ppp(l->cbs.ctx, ppp, plen);
    }
}

int vpn_l2tp_run_once(vpn_l2tp *l, int timeout_ms)
{
    int n;

    if (!l || (l->sock == VPN_INVALID_SOCK && !l->ipsec))
        return VPN_ERR_INVALID;

    if (l->ipsec) {
        n = vpn_ipsec_recv(l->ipsec, l->rx, sizeof(l->rx), timeout_ms);
        if (n < 0)
            return n;
        if (n == 0)
            return VPN_OK; /* 超时 / 非本 SA 的报文 */
    } else {
        n = vpn_net_read(l->sock, l->rx, sizeof(l->rx), timeout_ms);
        if (n < 0)
            return n;
        if (n == 0)
            return VPN_ERR_CLOSED;
    }

    l->last_rx_ms = vpn_now_ms();

    if (n < 2)
        return VPN_OK;

    uint16_t flags = vpn_be16(l->rx);
    if (flags & 0x8000)
        l2tp_handle_control(l, l->rx, (size_t)n);
    else
        l2tp_handle_data(l, l->rx, (size_t)n);

    return VPN_OK;
}

/* ------------------------------------------------------------------ */
/* 建立 / 关闭                                                         */
/* ------------------------------------------------------------------ */
vpn_l2tp *vpn_l2tp_new(const vpn_l2tp_params *p, const vpn_l2tp_cbs *cbs)
{
    vpn_l2tp *l;

    if (!p || !cbs)
        return NULL;

    l = (vpn_l2tp *)calloc(1, sizeof(*l));
    if (!l)
        return NULL;

    l->p = *p;
    l->cbs = *cbs;
    l->sock = VPN_INVALID_SOCK;
    if (l->p.port == 0)
        l->p.port = L2TP_PORT_DEFAULT;
    if (l->p.connect_timeout_ms <= 0)
        l->p.connect_timeout_ms = 15000;
    if (l->p.io_timeout_ms <= 0)
        l->p.io_timeout_ms = 30000;
    if (l->p.recv_window == 0)
        l->p.recv_window = 4;
    if (l->p.tunnel_name[0] == '\0')
        snprintf(l->p.tunnel_name, sizeof(l->p.tunnel_name), "vpnclient");

    l->our_tunnel_id = (uint16_t)(vpn_rand_u32() & 0x7fff);
    if (l->our_tunnel_id == 0)
        l->our_tunnel_id = 1;
    return l;
}

void vpn_l2tp_free(vpn_l2tp *l)
{
    if (!l)
        return;
    vpn_net_close(&l->sock);
    vpn_ipsec_free(l->ipsec);
    free(l);
}

int vpn_l2tp_open(vpn_l2tp *l)
{
    uint8_t pkt[L2TP_MAX_PKT];
    int len, rc;
    int64_t deadline, retx_at;
    int retx = 0;

    if (!l)
        return VPN_ERR_INVALID;

    VPN_INFO("L2TP: 连接 %s:%u", l->p.host, l->p.port);

    /* IPsec：psk 非空才真正建 SA；use_ipsec 只是"允许"开关 */
    if (l->p.use_ipsec && l->p.psk[0]) {
        vpn_ike_params ikp;
        char ikeerr[256];

        memset(&ikp, 0, sizeof(ikp));
        snprintf(ikp.host, sizeof(ikp.host), "%s", l->p.host);
        snprintf(ikp.psk, sizeof(ikp.psk), "%s", l->p.psk);
        ikp.port = 0;         /* 500 */
        ikp.timeout_ms = 8000;
        ikp.force_natt = true; /* 用户态必须 UDP 封装 */

        ikeerr[0] = 0;
        VPN_INFO("IPsec: 与 %s 协商 IKEv1（PSK）", l->p.host);
        l->ipsec = vpn_ipsec_new(&ikp, ikeerr, sizeof(ikeerr));
        if (!l->ipsec) {
            snprintf(l->reason, sizeof(l->reason), "IPsec 初始化失败: %s", ikeerr);
            VPN_ERROR("L2TP: %s", l->reason);
            return VPN_ERR_IO;
        }
        rc = vpn_ipsec_connect(l->ipsec, ikeerr, sizeof(ikeerr));
        if (rc != VPN_OK) {
            snprintf(l->reason, sizeof(l->reason), "IPsec 协商失败: %.40s", ikeerr);
            VPN_ERROR("L2TP: %s", l->reason);
            vpn_ipsec_free(l->ipsec);
            l->ipsec = NULL;
            return rc;
        }
        VPN_INFO("IPsec: SA 就绪（%s）", vpn_ipsec_cipher(l->ipsec));
    }

    /* 必须用 1701 作源端口：RouterOS 的 L2TP 数据通道按源端口识别对端 */
    rc = vpn_net_udp_connect_local(1701, l->p.host, l->p.port, &l->sock);
    if (rc != VPN_OK)
        return rc;

    len = vpn_l2tp_build_sccrq(pkt, sizeof(pkt), l->our_tunnel_id, l->p.recv_window,
                               l->p.tunnel_name);
    if (len < 0)
        return VPN_ERR_INVALID;

    if (l2tp_xmit(l, pkt, (size_t)len) != VPN_OK) {
        VPN_ERROR("L2TP: 发送 SCCRQ 失败");
        return VPN_ERR_IO;
    }
    l->ns = 1;
    VPN_INFO("L2TP: 已发送 SCCRQ（本地 tunnel id=%u）", l->our_tunnel_id);

    deadline = vpn_now_ms() + l->p.connect_timeout_ms;
    retx_at = vpn_now_ms() + L2TP_SCCRQ_RTO_MS;
    while (!l->have_peer_tunnel) {
        if (vpn_now_ms() > deadline) {
            /* 把重传次数写进原因：0 次说明对端连个回包都没有（大概率被
             * 服务端 use-ipsec=yes 丢弃或 1701 没放行），多次说明链路丢包 */
            snprintf(l->reason, sizeof(l->reason),
                     "等待 SCCRP 超时（已重传 %d 次；检查服务端 use-ipsec=no 且放行 UDP/1701）",
                     retx);
            VPN_ERROR("L2TP: %s", l->reason);
            return VPN_ERR_TIMEOUT;
        }

        /* 按 RTO 重发 SCCRQ。l->nr 仍为 0 表示还没收到过服务器的任何控制
         * 消息；一旦收到 SCCRP 就会退出循环，不会再多重发 */
        if (l->nr == 0 && retx < L2TP_SCCRQ_MAX_RETX && vpn_now_ms() >= retx_at) {
            if (l2tp_xmit(l, pkt, (size_t)len) == VPN_OK) {
                retx++;
                VPN_DEBUG("L2TP: 重传 SCCRQ（第 %d 次）", retx);
            }
            retx_at = vpn_now_ms() + L2TP_SCCRQ_RTO_MS;
        }

        rc = vpn_l2tp_run_once(l, 200);
        if (rc == VPN_ERR_CLOSED || rc == VPN_ERR_IO)
            return rc;
    }

    deadline = vpn_now_ms() + l->p.connect_timeout_ms;
    while (!l->open) {
        if (vpn_now_ms() > deadline) {
            snprintf(l->reason, sizeof(l->reason), "等待 ICRP 超时");
            VPN_ERROR("L2TP: %s", l->reason);
            return VPN_ERR_TIMEOUT;
        }
        rc = vpn_l2tp_run_once(l, 1000);
        if (rc == VPN_ERR_CLOSED || rc == VPN_ERR_IO)
            return rc;
    }

    VPN_INFO("L2TP: 会话已建立 (peer tunnel=%u session=%u)", l->peer_tunnel_id,
             l->peer_session_id);
    return VPN_OK;
}

int vpn_l2tp_send_ppp(vpn_l2tp *l, const uint8_t *frame, size_t len)
{
    uint8_t buf[L2TP_MAX_PKT];
    static int use_l = -1;
    size_t hdr = 6, total;

    if (!l || !l->open)
        return VPN_ERR_CLOSED;

    /* 实验开关：L2TP_LEN=1 时数据消息带 L 位与 Length 字段（同 xl2tpd
     * 的 "length bit = yes"）。用于对比 RouterOS 对 PPP 帧的处理差异。 */
    if (use_l < 0) {
        const char *e = getenv("L2TP_LEN");
        use_l = (e && atoi(e) != 0) ? 1 : 0;
    }
    if (use_l)
        hdr += 2;
    total = hdr + 2 + len;
    if (total > sizeof(buf))
        return VPN_ERR_INVALID;

    {
        size_t o = 0;
        uint16_t flags = 0x0002;

        if (use_l)
            flags |= 0x4000;
        vpn_put_be16(buf + o, flags); o += 2;
        if (use_l) {
            vpn_put_be16(buf + o, (uint16_t)total);
            o += 2;
        }
        vpn_put_be16(buf + o, l->peer_tunnel_id); o += 2;
        vpn_put_be16(buf + o, l->peer_session_id); o += 2;
        /* 未协商 ACFC 前必须带 Address(0xFF)/Control(0x03) */
        buf[o] = 0xff;
        buf[o + 1] = 0x03;
        memcpy(buf + o + 2, frame, len);
    }

    if (vpn_net_write_all(l->sock, buf, total, l->p.io_timeout_ms) < 0)
        return VPN_ERR_IO;
    return VPN_OK;
}

void vpn_l2tp_close(vpn_l2tp *l, const char *reason)
{
    if (!l)
        return;

    if (l->sock != VPN_INVALID_SOCK && l->have_peer_tunnel) {
        uint8_t avps[16];
        size_t pos = 0;

        avp_put_u16(avps, sizeof(avps), &pos, AVP_MESSAGE_TYPE, L2TP_MSG_STOPCCN);
        l2tp_send_ctrl(l, L2TP_MSG_STOPCCN, avps, pos);
        VPN_INFO("L2TP: 已发送 StopCCN (%s)", reason ? reason : "-");
    }
    l->open = false;
    vpn_net_close(&l->sock);
}

bool vpn_l2tp_is_open(const vpn_l2tp *l) { return l && l->open; }
int  vpn_l2tp_fd(const vpn_l2tp *l) { return l ? l2tp_sock(l) : -1; }

void vpn_l2tp_info(const vpn_l2tp *l, char *out, size_t outlen)
{
    if (!l || !out)
        return;
    snprintf(out, outlen, "tunnel=%u/%u session=%u/%u ns=%u nr=%u open=%d",
             l->our_tunnel_id, l->peer_tunnel_id, l->our_session_id, l->peer_session_id,
             l->ns, l->nr, l->open ? 1 : 0);
}
