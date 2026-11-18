/* SPDX-License-Identifier: LicenseRef-Proprietary
   Copyright (c) 2026 wwm-spec. All rights reserved.
 */

/* vpn_pptp.c - PPTP（RFC 2637）控制通道 + GRE 封装
 *
 * 风险提示：MPPE/PPTP 已被证明不安全，且 GRE(47) 常被运营商拦截。
 * 平台适配：GRE 需要 RAW socket 权限；Android 非 root 返回 VPN_ERR_UNSUPPORTED。
 */
#include "vpncore/vpn_pptp.h"
#include "vpncore/vpn_buf.h"
#include "vpncore/vpn_crypto.h"
#include "vpncore/vpn_error.h"
#include "vpncore/vpn_log.h"
#include "vpncore/vpn_net.h"
#include "vpncore/vpn_platform.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#define PPTP_MAGIC 0x1a2b3c4d
#define PPTP_HDR_LEN 12

struct vpn_pptp {
    vpn_pptp_params p;
    vpn_pptp_cbs   cbs;

    vpn_sock_t      ctrl;      /* TCP 1723 */
    vpn_sock_t      gre;       /* RAW GRE，可能不可用 */
    uint8_t         rx[2048];
    size_t          rxlen;

    uint32_t        server_call_id;
    uint16_t        peer_pkt_recv;
    unsigned long   gre_tx;      /* 已发出的 GRE 包数（诊断用） */
    uint32_t        gre_seq;     /* 发出的 GRE 序列号（与对端保持一致） */
    unsigned long   gre_rx;      /* 已收到的 GRE 包数（诊断用） */
    bool            ctrl_open;   /* 已收到 Start-Control-Connection-Reply */
    bool            failed;      /* 服务器明确拒绝，需立即失败而非重试 */
    bool            open;
    int64_t         last_rx_ms;
    char            reason[192];
};

/* ------------------------------------------------------------------ */
/* 封装                                                                */
/* ------------------------------------------------------------------ */
static int pptp_build(uint8_t *out, size_t cap, uint16_t type, uint16_t cookie,
                      const uint8_t *body, size_t blen)
{
    /* RFC 2637 控制消息头共 12 字节：
     *   Length(2) | PPTP Message Type(2)=1 | Magic Cookie(4) |
     *   Control Message Type(2) | Reserved0(2)
     * 旧实现漏掉了「PPTP Message Type」字段，整条报文错位 2 字节，
     * 服务器按非法报文静默丢弃 → 表现为 SCCRQ 有去无回、15 秒超时。 */
    size_t total = 12 + blen;

    (void)cookie;

    if (cap < total)
        return -1;

    vpn_put_be16(out + 0, (uint16_t)total);  /* Length */
    vpn_put_be16(out + 2, 0x0001);           /* PPTP Message Type = Control */
    vpn_put_be32(out + 4, PPTP_MAGIC);       /* Magic Cookie */
    vpn_put_be16(out + 8, type);             /* Control Message Type */
    vpn_put_be16(out + 10, 0);               /* Reserved0 */
    if (blen)
        memcpy(out + 12, body, blen);
    return (int)total;
}

static int pptp_send(vpn_pptp *p, uint16_t type, uint16_t cookie, const uint8_t *body,
                     size_t blen)
{
    uint8_t pkt[1024];
    int len = pptp_build(pkt, sizeof(pkt), type, cookie, body, blen);

    if (len < 0)
        return VPN_ERR_INVALID;
    if (vpn_net_write_all(p->ctrl, pkt, (size_t)len, p->p.io_timeout_ms) < 0)
        return VPN_ERR_IO;
    VPN_DEBUG("PPTP -> type=%u len=%d", type, len);
    return VPN_OK;
}

/* ------------------------------------------------------------------ */
/* GRE（RFC 2637 §4.1）                                                */
/* ------------------------------------------------------------------ */
int vpn_pptp_gre_encapsulate(uint32_t call_id, uint32_t seq, const uint8_t *ppp,
                             size_t len, uint8_t *out, size_t cap)
{
    /* GRE 头(8) + Sequence(4) + Address/Control(2) + PPP 帧。PPP 层内部给的是
     * [协议][载荷]，而 RFC 2637 的 GRE 载荷是完整 PPP 帧，未协商 ACFC
     * 时必须带 0xFF 0x03 前缀——缺了它路由器的 PPP 解帧会直接丢弃，
     * 表现为「GRE 双向都通、但 LCP 一个包都收不到」 */
    size_t total = 8 + 4 + 2 + len;

    if (!out || cap < total || len == 0)
        return -1;

    /* Flags/Version：K=1(Call ID 存在) + S=1(序列号存在) + Ver=1 -> 0x3001。
     * 必须和对端保持一致：RouterOS 自己发的每个 GRE 都是 0x3001，
     * Windows RAS / pptp-linux 也都带序列号。之前发 0x2001（无序列号）
     * 时，对端按自己的头格式取字段，把 FF03C021 当成序列号、后面
     * 整体错位 → 静默丢弃，LCP 永远收不到回应 */
    vpn_put_be16(out, 0x3001);
    vpn_put_be16(out + 2, 0x880b); /* PPP 的 EtherType */
    /* Payload Length：Address/Control + PPP 帧的实际字节数，
     * 不含 Call ID 和序列号（与 RouterOS 的 plen=23 语义一致） */
    vpn_put_be16(out + 4, (uint16_t)(len + 2));
    vpn_put_be16(out + 6, (uint16_t)(call_id & 0xffff));
    vpn_put_be32(out + 8, seq);
    out[12] = 0xff;
    out[13] = 0x03;
    memcpy(out + 14, ppp, len);
    return (int)total;
}

int vpn_pptp_gre_decapsulate(const uint8_t *pkt, size_t len, uint32_t expect_call_id,
                             uint8_t *out, size_t cap)
{
    const uint8_t *gre = pkt;
    uint16_t flags, proto_field, plen, call_id;
    size_t hdr = 8;
    size_t payload_len;

    if (!pkt || len < 8)
        return -1;

    /* Windows 的 RAW socket 收到的是【完整 IP 报文】（首字节 0x45 = IPv4、
     * 首部长度 5），Linux 回环亦然。必须先按 IHL 剥掉 IP 头，否则
     * GRE 解析永远从 0x45 开始错位，表现为「GRE 一个包都收不到」 */
    if ((pkt[0] >> 4) == 4 && len >= 20 && pkt[9] == 47 /* GRE */) {
        size_t ihl = (size_t)(pkt[0] & 0x0f) * 4;

        if (ihl < 20 || len < ihl + 8)
            return -1;
        gre = pkt + ihl;
        len -= ihl;
    }

    flags = vpn_be16(gre);
    proto_field = vpn_be16(gre + 2);
    plen = vpn_be16(gre + 4);
    call_id = vpn_be16(gre + 6);

    if ((flags & 0x0007) != 1)
        return -1;
    if (proto_field != 0x880b)
        return -1;
    if (flags & 0x8000)
        hdr += 4; /* C 位：存在校验和 */
    if (flags & 0x1000)
        hdr += 4; /* S 位：存在序列号（部分实现会带） */
    if (flags & 0x0080)
        hdr += 4; /* A 位：存在 Ack */
    if (expect_call_id && call_id != (expect_call_id & 0xffff))
        return -1;
    if (plen < 4)
        return -1;

    /* Payload Length 的语义各家不一：RouterOS 给的是纯载荷长度，
     * 另一些实现把 Call ID 的 4 字节也算进去。用「剩余字节数」反推，
     * 谁对得上就用谁——之前无条件 -4 会把 RouterOS 的帧截掉 4 字节，
     * 表现为 LCP 选项解析到最后一个就 len 超界（type=5 len=6） */
    payload_len = plen;
    if (hdr + payload_len > len) {
        if (plen >= 4 && hdr + (size_t)plen - 4 <= len)
            payload_len = (size_t)plen - 4;
        else
            return -1;
    }
    if (payload_len > len - hdr || payload_len > cap)
        return -1;

    {
        const uint8_t *pp = gre + hdr;
        size_t n = payload_len;

        /* 对端发来的是完整 PPP 帧（0xFF 0x03 + 协议 + 载荷），而 PPP 层
         * 内部按 [协议][载荷] 解析，必须剥掉 Address/Control，否则
         * 会把 0xFF03 当成未知协议丢弃 */
        if (n >= 2 && pp[0] == 0xff && pp[1] == 0x03) {
            pp += 2;
            n -= 2;
        }
        memcpy(out, pp, n);
        return (int)n;
    }
    return (int)payload_len;
}

bool vpn_pptp_supported(void)
{
#ifdef _WIN32
    return true; /* Windows 侧由 shell 通过 WFP/服务实现，核心只做控制通道 */
#elif defined(__ANDROID__)
    return false;
#else
    /* Linux：需要 CAP_NET_RAW */
    int s = socket(AF_INET, SOCK_RAW, 47);
    if (s < 0)
        return false;
    vpn_sock_t tmp = s;
    vpn_net_close(&tmp);
    return true;
#endif
}

/* ------------------------------------------------------------------ */
/* 控制通道                                                            */
/* ------------------------------------------------------------------ */
static int pptp_handle_packet(vpn_pptp *p, const uint8_t *pkt, size_t len)
{
    uint16_t type;
    const uint8_t *body;
    size_t blen;

    if (len < 12)
        return VPN_OK;
    if (vpn_be16(pkt + 2) != 0x0001) {
        VPN_WARN("PPTP: non-control message (PPTP Message Type=%u), dropped", vpn_be16(pkt + 2));
        return VPN_OK;
    }
    if (vpn_be32(pkt + 4) != PPTP_MAGIC) {
        VPN_WARN("PPTP: bad magic number, dropped");
        return VPN_OK;
    }

    type = vpn_be16(pkt + 8);
    body = pkt + 12;
    blen = len - 12;

    VPN_DEBUG("PPTP <- type=%u len=%zu head=%02x%02x %02x%02x %02x%02x%02x%02x %02x%02x %02x%02x",
              type, blen, pkt[0], pkt[1], pkt[2], pkt[3], pkt[4], pkt[5],
              pkt[6], pkt[7], pkt[8], pkt[9], pkt[10], pkt[11]);

    switch (type) {
    case PPTP_MSG_START_CTRL_CONN_REPLY: {
        /* RFC 2637 §3.1.2：Result Code 1 = OK（2 才是通用错误） */
        uint8_t result = blen >= 4 ? body[2] : 0xff;
        uint8_t err    = blen >= 4 ? body[3] : 0;

        if (result != 1 || blen < 16) {
            snprintf(p->reason, sizeof(p->reason),
                     "server rejected the PPTP control connection (result=%u err=%u)", result, err);
            VPN_ERROR("%s", p->reason);
            p->failed = true;
            break;
        }
        p->ctrl_open = true;
        if (blen >= 16 + 128) {
            char host[65], vendor[65];
            memcpy(host, body + 16, 64);
            host[64] = 0;
            memcpy(vendor, body + 80, 64);
            vendor[64] = 0;
            VPN_INFO("PPTP: control connection established (server \"%s\" / \"%s\")", host, vendor);
        } else {
            VPN_INFO("PPTP: control connection established");
        }
        break;
    }
    case PPTP_MSG_OUTGOING_CALL_REPLY: {
        /* RFC 2637 §3.1.5：Call ID(2) Peer Call ID(2) Result(1) Err(1)
         * Cause(2) Speed(4) RecvWindow(2) Delay(2) PhysChannel(4) */
        uint16_t srv_call  = blen >= 20 ? vpn_be16(body + 0) : 0;
        uint16_t peer_call = blen >= 20 ? vpn_be16(body + 2) : 0;
        uint8_t  result    = blen >= 20 ? body[4] : 0xff;
        uint8_t  err       = blen >= 20 ? body[5] : 0;
        uint16_t srv_recv  = blen >= 20 ? vpn_be16(body + 12) : 0;
        uint16_t delay     = blen >= 20 ? vpn_be16(body + 14) : 0;

        if (result != 1) {   /* 1 = OK，其余均为失败 */
            snprintf(p->reason, sizeof(p->reason),
                     "server rejected the PPTP call (result=%u err=%u)", result, err);
            VPN_ERROR("%s", p->reason);
            p->failed = true;
            break;
        }
        if (!srv_call) {
            snprintf(p->reason, sizeof(p->reason), "server call reply has no Call ID");
            VPN_ERROR("%s", p->reason);
            p->failed = true;
            break;
        }
        if (peer_call && peer_call != (uint16_t)p->p.call_id)
            VPN_DEBUG("PPTP: server filled in Peer Call ID=%u (local %u)",
                      peer_call, (unsigned)p->p.call_id);

        p->server_call_id = srv_call;
        p->peer_pkt_recv  = srv_recv;
        VPN_INFO("PPTP: call established (server call id=%u window=%u delay=%ums)",
                 p->server_call_id, srv_recv, (unsigned)delay * 10);

        /* Set-Link-Info：告知对端链路参数 */
        {
            uint8_t sli[12];
            memset(sli, 0, sizeof(sli));
            vpn_put_be32(sli + 4, 0xffffffff); /* Send ACCM */
            vpn_put_be32(sli + 8, 0xffffffff); /* Recv ACCM */
            pptp_send(p, PPTP_MSG_SET_LINK_INFO, 0, sli, sizeof(sli));
        }

        p->open = true;
        if (p->cbs.on_connected)
            p->cbs.on_connected(p->cbs.ctx);
        break;
    }
    case PPTP_MSG_CALL_DISCONNECT_NOTIFY:
    case PPTP_MSG_STOP_CTRL_CONN_REPLY:
        snprintf(p->reason, sizeof(p->reason), "server disconnected the PPTP session (type=%u)", type);
        p->open = false;
        if (p->cbs.on_closed)
            p->cbs.on_closed(p->cbs.ctx, p->reason);
        break;
    case PPTP_MSG_ECHO_REQ:
        VPN_DEBUG("PPTP: got Echo-Request, replying with Echo-Reply");
        pptp_send(p, PPTP_MSG_ECHO_REPLY, 0, NULL, 0);
        break;
    case PPTP_MSG_ECHO_REPLY:
        break;
    case PPTP_MSG_CALL_CLEAR_REQ:
        snprintf(p->reason, sizeof(p->reason), "server cleared the PPTP call (type=12)");
        p->open = false;
        if (p->cbs.on_closed)
            p->cbs.on_closed(p->cbs.ctx, p->reason);
        break;
    default:
        VPN_DEBUG("PPTP: unhandled control message type=%u", type);
        break;
    }
    return VPN_OK;
}

int vpn_pptp_run_once(vpn_pptp *p, int timeout_ms)
{
    int n;

    if (!p || p->ctrl == VPN_INVALID_SOCK)
        return VPN_ERR_INVALID;

    if (p->rxlen < sizeof(p->rx)) {
        n = vpn_net_read(p->ctrl, p->rx + p->rxlen,
                         sizeof(p->rx) - p->rxlen, timeout_ms);
        if (n == 0) {
            snprintf(p->reason, sizeof(p->reason), "control connection closed by the server");
            p->open = false;
            if (p->cbs.on_closed)
                p->cbs.on_closed(p->cbs.ctx, p->reason);
            return VPN_ERR_CLOSED;
        }
        if (n < 0 && n != VPN_ERR_TIMEOUT)
            return n;
        if (n > 0) {
            p->rxlen += (size_t)n;
            p->last_rx_ms = vpn_now_ms();
        }
    }

    /* TCP 是字节流：按 Length 前缀切出完整控制消息（一次可能读到多条或半条） */
    while (p->rxlen >= 12) {
        uint16_t plen = vpn_be16(p->rx);

        if (plen < 12 || plen > sizeof(p->rx)) {
            VPN_WARN("PPTP: invalid packet length %u, flushing receive buffer", plen);
            p->rxlen = 0;
            break;
        }
        if (p->rxlen < plen)
            break;                      /* 半包，等下一次读 */
        pptp_handle_packet(p, p->rx, plen);
        memmove(p->rx, p->rx + plen, p->rxlen - plen);
        p->rxlen -= plen;
    }

    /* GRE 数据面：非阻塞收一包，解出 PPP 帧交给上层 */
    if (p->gre != VPN_INVALID_SOCK && p->open) {
        uint8_t g[2048], ppp[2048];
        int m = vpn_net_read(p->gre, g, sizeof(g), 0);

        if (m > 0) {
            int k = vpn_pptp_gre_decapsulate(g, (size_t)m, p->p.call_id,
                                             ppp, sizeof(ppp));

            /* 前 10 个包用 INFO 打出 GRE 头关键字段：能直接看出是 call id
             * 不匹配、协议字段不对，还是根本没收对包 */
            {
                static unsigned long dbg_rx;

                if (dbg_rx < 3) {
                    size_t off = 0, avail = 0;

                    ++dbg_rx;
                    if (m >= 20 && (g[0] >> 4) == 4 && g[9] == 47)
                        off = (size_t)(g[0] & 0x0f) * 4;
                    avail = (size_t)m > off + 8 ? 8 : 0;
                    VPN_DEBUG("PPTP: GRE rx #%lu raw=%d iphdr=%zu flags=%02x%02x proto=%02x%02x "
                             "plen=%u call=%u expect=%u result=%d",
                             dbg_rx, m, off,
                             avail ? g[off] : 0, avail ? g[off + 1] : 0,
                             avail ? g[off + 2] : 0, avail ? g[off + 3] : 0,
                             avail ? vpn_be16(g + off + 4) : 0,
                             avail ? vpn_be16(g + off + 6) : 0,
                             (unsigned)(p->p.call_id & 0xffff), k);
                }
            }

            if (k > 0) {
                ++p->gre_rx;
                VPN_DEBUG("PPTP: GRE received a %d-byte PPP frame", k);
                if (p->cbs.on_ppp)
                    p->cbs.on_ppp(p->cbs.ctx, ppp, (size_t)k);
            } else {
                /* 只对「call id 属于本端却解不开」的情况告警：本机发出的包
                 * 被回环收到（call id 是服务器侧的）属于正常噪声 */
                size_t off = 0;

                if (m >= 20 && (g[0] >> 4) == 4 && g[9] == 47)
                    off = (size_t)(g[0] & 0x0f) * 4;
                if (off + 8 <= (size_t)m &&
                    vpn_be16(g + off + 6) == (uint16_t)p->p.call_id)
                    VPN_DEBUG("PPTP: GRE decapsulation failed (%d bytes, first 4 bytes %02x%02x%02x%02x)",
                              m, g[0], g[1], g[2], g[3]);
            }
        }
    }
    return VPN_OK;
}

vpn_pptp *vpn_pptp_new(const vpn_pptp_params *par, const vpn_pptp_cbs *cbs)
{
    vpn_pptp *p;

    if (!par || !cbs)
        return NULL;

    p = (vpn_pptp *)calloc(1, sizeof(*p));
    if (!p)
        return NULL;

    p->p = *par;
    p->cbs = *cbs;
    p->ctrl = VPN_INVALID_SOCK;
    p->gre = VPN_INVALID_SOCK;
    if (p->p.port == 0)
        p->p.port = PPTP_PORT_DEFAULT;
    if (p->p.connect_timeout_ms <= 0)
        p->p.connect_timeout_ms = 15000;
    if (p->p.io_timeout_ms <= 0)
        p->p.io_timeout_ms = 30000;
    p->p.call_id = (p->p.call_id & 0xffff) ? p->p.call_id : (vpn_rand_u32() & 0xffff);
    return p;
}

void vpn_pptp_free(vpn_pptp *p)
{
    if (!p)
        return;
    vpn_net_close(&p->ctrl);
    vpn_net_close(&p->gre);
    free(p);
}

/* 构造并发送 Start-Control-Connection-Request（body 需可重用以便重传） */
static int pptp_send_start_req(vpn_pptp *p, const uint8_t *body, size_t pos)
{
    return pptp_send(p, PPTP_MSG_START_CTRL_CONN_REQ, 0, body, pos);
}

static int pptp_send_outgoing_call(vpn_pptp *p)
{
    uint8_t ocr[168];
    size_t q = 0;

    vpn_put_be16(ocr + q, (uint16_t)p->p.call_id); q += 2;  /* Call ID */
    vpn_put_be16(ocr + q, 0); q += 2;                       /* Call Serial */
    vpn_put_be32(ocr + q, 50000); q += 4;                   /* Min BPS */
    vpn_put_be32(ocr + q, 100000000); q += 4;               /* Max BPS */
    vpn_put_be32(ocr + q, 1); q += 4;                       /* Bearer Type：analog */
    vpn_put_be16(ocr + q, 1); q += 2;                       /* Framing Type：async */
    vpn_put_be16(ocr + q, 64); q += 2;                      /* Recv Window */
    vpn_put_be16(ocr + q, 0); q += 2;                       /* Delay */
    vpn_put_be16(ocr + q, 0); q += 2;                       /* Phone Number Len */
    memset(ocr + q, 0, 64); q += 64;                        /* Phone Number */
    memset(ocr + q, 0, 64); q += 64;                        /* Sub-Address */

    return pptp_send(p, PPTP_MSG_OUTGOING_CALL_REQ, 0, ocr, q);
}

int vpn_pptp_open(vpn_pptp *p)
{
    uint8_t body[256];
    size_t pos = 0;
    int rc;
    int64_t deadline, last_tx;

    memset(body, 0, sizeof(body));   /* Host Name/Vendor 是定长 64 字节，必须先清零 */

    if (!p)
        return VPN_ERR_INVALID;

    if (!vpn_pptp_supported()) {
        VPN_ERROR("PPTP: cannot create a GRE raw socket on this platform (Android without root / CAP_NET_RAW missing)");
        return VPN_ERR_UNSUPPORTED;
    }

    VPN_WARN("PPTP: using an insecure protocol (MPPE can be cracked offline), prefer SSTP/L2TP");
    VPN_INFO("PPTP: connecting %s:%u", p->p.host, p->p.port);

    rc = vpn_net_tcp_connect(p->p.host, p->p.port, p->p.connect_timeout_ms, &p->ctrl);
    if (rc != VPN_OK)
        return rc;

    vpn_put_be16(body + pos, 0x0100); pos += 2;     /* Protocol Version 1.0 */
    vpn_put_be16(body + pos, 0x0000); pos += 2;     /* Reserved1：RFC 要求为 0 */
    vpn_put_be32(body + pos, 0x00000003); pos += 4; /* Framing：async + sync */
    vpn_put_be32(body + pos, 0x00000003); pos += 4; /* Bearer：analog + digital */
    vpn_put_be16(body + pos, 0x0000); pos += 2;     /* Max Channels */
    vpn_put_be16(body + pos, 0x0000); pos += 2;     /* Firmware Revision */
    snprintf((char *)body + pos, 64, "vpnclient"); pos += 64; /* Host Name */
    snprintf((char *)body + pos, 64, "vpnclient"); pos += 64; /* Vendor */

    /* 阶段一：Start-Control-Connection-Request -> Reply。
     * 必须等 Reply 到手才能发 Outgoing-Call-Request，否则服务器视为
     * 协议违规直接静默丢弃（旧实现就是这样卡死的）。 */
    rc = pptp_send_start_req(p, body, pos);
    if (rc != VPN_OK)
        return rc;

    deadline = vpn_now_ms() + p->p.connect_timeout_ms;
    last_tx = vpn_now_ms();
    while (!p->ctrl_open) {
        if (p->failed)
            return VPN_ERR_PROTO;
        if (vpn_now_ms() > deadline) {
            snprintf(p->reason, sizeof(p->reason), "timed out waiting for the PPTP control-connection reply");
            return VPN_ERR_TIMEOUT;
        }
        rc = vpn_pptp_run_once(p, 200);
        if (rc == VPN_ERR_CLOSED || rc == VPN_ERR_IO)
            return rc;
        if (!p->ctrl_open && vpn_now_ms() - last_tx >= 3000) {
            VPN_DEBUG("PPTP: resending Start-Control-Connection-Request");
            pptp_send_start_req(p, body, pos);
            last_tx = vpn_now_ms();
        }
    }

    /* 阶段二：Outgoing-Call-Request -> Reply */
    rc = pptp_send_outgoing_call(p);
    if (rc != VPN_OK)
        return rc;

    deadline = vpn_now_ms() + p->p.connect_timeout_ms;
    last_tx = vpn_now_ms();
    while (!p->open) {
        if (p->failed)
            return VPN_ERR_PROTO;
        if (vpn_now_ms() > deadline) {
            snprintf(p->reason, sizeof(p->reason), "timed out waiting for the PPTP call reply");
            return VPN_ERR_TIMEOUT;
        }
        rc = vpn_pptp_run_once(p, 200);
        if (rc == VPN_ERR_CLOSED || rc == VPN_ERR_IO)
            return rc;
        if (!p->open && vpn_now_ms() - last_tx >= 3000) {
            VPN_DEBUG("PPTP: resending Outgoing-Call-Request");
            pptp_send_outgoing_call(p);
            last_tx = vpn_now_ms();
        }
    }

    /* GRE(47) 数据面：PPP 帧全走这里，建不起来就没法传数据，直接失败 */
    rc = vpn_net_raw_gre_connect(p->p.host, &p->gre);
    if (rc != VPN_OK) {
        snprintf(p->reason, sizeof(p->reason),
                 "GRE(47) data path unavailable: run as administrator and allow GRE on the server/firewall");
        VPN_ERROR("%s", p->reason);
        return rc;
    }
    vpn_net_set_nonblock(p->gre, true);

    VPN_INFO("PPTP: control channel, call and GRE data path ready (server call id=%u)",
             p->server_call_id);
    return VPN_OK;
}

int vpn_pptp_send_ppp(vpn_pptp *p, const uint8_t *frame, size_t len)
{
    uint8_t buf[2048];
    int n, rc;

    if (!p || !p->open)
        return VPN_ERR_CLOSED;

    n = vpn_pptp_gre_encapsulate(p->server_call_id, ++p->gre_seq, frame, len,
                                 buf, sizeof(buf));
    if (n < 0)
        return VPN_ERR_INVALID;

    if (p->gre == VPN_INVALID_SOCK) {
        VPN_TRACE("PPTP: GRE data path not ready, dropping %zu bytes", len);
        return VPN_ERR_UNSUPPORTED;
    }

    /* RAW socket 上 select/poll 的可写事件并不可靠（Windows 尤其如此，
     * vpn_net_write_all 里的 wait_writable 可能等到 io 超时才返回），
     * 而 GRE 是无连接数据报：这里直接投递一次，缓冲满就丢弃靠 PPP 重传，
     * 绝不让主循环卡在发送上 */
    rc = vpn_net_raw_gre_send(p->gre, buf, (size_t)n);
    if (rc != VPN_OK) {
        static unsigned long fail_cnt;

        if ((++fail_cnt % 20) == 1)
            VPN_WARN("PPTP: GRE send failed (%s), check that the firewall/AV allows GRE(47)",
                     vpn_strerror(rc));
        return rc;
    }
    ++p->gre_tx;
    /* 前几个包用 INFO 打印：GUI 默认不显示 DEBUG，必须让用户能一眼
     * 看到「包真的发出去了」，否则无法区分「没发」和「发了没人回」 */
    /* 只把首个包打 INFO（含 GRE 头 hexdump，排障时一眼看出头格式），
     * 其余全部降到 DEBUG：一次连接几十上百个包，逐包 INFO 会把
     * 真正有用的阶段信息淹掉 */
    if (p->gre_tx == 1)
        VPN_INFO("PPTP: GRE first packet sent (%d bytes)%s", n,
                 vpn_hexdump(buf, (size_t)n < 16 ? (size_t)n : 16));
    else if ((p->gre_tx % 100) == 0)
        VPN_DEBUG("PPTP: GRE sent %lu / received %lu", p->gre_tx, p->gre_rx);
    return VPN_OK;
}

void vpn_pptp_close(vpn_pptp *p, const char *reason)
{
    if (!p)
        return;

    if (p->ctrl != VPN_INVALID_SOCK && p->open) {
        uint8_t body[2] = { 0, 0 };
        pptp_send(p, PPTP_MSG_CALL_CLEAR_REQ, 0, body, sizeof(body));
        pptp_send(p, PPTP_MSG_STOP_CTRL_CONN_REQ, 0, NULL, 0);
        VPN_INFO("PPTP: Call-Clear/Stop sent (%s)", reason ? reason : "-");
    }
    /* 断开时把 GRE 收发计数打出来：接收为 0 说明回包根本没进本机
     * （防火墙/安全软件拦入站 GRE，或对端未回），发送为 0 说明出不去 */
    if (p->gre != VPN_INVALID_SOCK)
        VPN_INFO("PPTP: GRE stats: sent %lu / received %lu packets%s", p->gre_tx, p->gre_rx,
                 p->gre_rx == 0 ? " (no replies arriving, allow inbound GRE/47)" : "");

    p->open = false;
    p->rxlen = 0;
    vpn_net_close(&p->ctrl);
    vpn_net_close(&p->gre);
}

bool vpn_pptp_is_open(const vpn_pptp *p) { return p && p->open; }
