/* test_l2tp_avp.c - L2TPv2 控制报文与 AVP（RFC 2661 §3.1） */
#include "test.h"

#include "vpncore/vpn_l2tp.h"

#include <stdint.h>

#define AVP_MESSAGE_TYPE     0
#define AVP_RESULT_CODE      1
#define AVP_PROTOCOL_VER     2
#define AVP_FRAMING_CAP      3
#define AVP_BEARER_CAP       4
#define AVP_TIE_BREAKER      5
#define AVP_HOST_NAME        7
#define AVP_ASSIGNED_TUNNEL  9
#define AVP_RECV_WINDOW      10
#define AVP_ASSIGNED_SESSION 14
#define AVP_CALL_SERIAL      15

typedef struct {
    uint16_t type;
    uint16_t len;
    const uint8_t *val;
} avp_view;

static uint16_t be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

/* 解析控制报文的 AVP 序列；返回 AVP 个数，header_ok 写包头校验结果 */
static int parse_ctrl(const uint8_t *pkt, int len, avp_view *out, int cap,
                      bool *header_ok)
{
    int count = 0;
    size_t pos = 12; /* T/L/S 位全开：12 字节头 */
    bool ok = true;

    if (len < 12)
        ok = false;
    if (ok && be16(pkt) != 0xC802)   /* T=1,L=1,S=1,Ver=2 */
        ok = false;
    if (ok && be16(pkt + 2) != (uint16_t)len)
        ok = false;

    while (ok && pos + 6 <= (size_t)len) {
        uint16_t flags = be16(pkt + pos);
        uint16_t alen = flags & 0x03ff;
        uint16_t type = be16(pkt + pos + 4);
        if (alen < 6 || pos + alen > (size_t)len) {
            ok = false;
            break;
        }
        if (count < cap) {
            out[count].type = type;
            out[count].len = (uint16_t)(alen - 6);
            out[count].val = pkt + pos + 6;
        }
        count++;
        pos += alen;
    }

    if (ok && pos != (size_t)len)
        ok = false;

    *header_ok = ok;
    return count;
}

static const avp_view *find_avp(const avp_view *avps, int n, uint16_t type)
{
    int i;
    for (i = 0; i < n; i++)
        if (avps[i].type == type)
            return &avps[i];
    return NULL;
}

TEST(l2tp_sccrq_structure)
{
    uint8_t pkt[512];
    avp_view avps[16];
    bool ok = false;
    int len, n, i, found = 0;
    const avp_view *v;

    len = vpn_l2tp_build_sccrq(pkt, sizeof(pkt), 0x1234, 8, "vpnclient-test");
    CHECK(len > 12);

    n = parse_ctrl(pkt, len, avps, 16, &ok);
    CHECK(ok == true);
    CHECK(n >= 7);
    (void)i;
    (void)found;

    CHECK_EQ_INT(be16(pkt + 4), 0);          /* tunnel id（SCCRQ 阶段为 0） */
    CHECK_EQ_INT(be16(pkt + 6), 0);          /* session id 必须为 0 */
    CHECK_EQ_INT(be16(pkt + 8), 0);          /* ns */
    CHECK_EQ_INT(be16(pkt + 10), 0);         /* nr */

    v = find_avp(avps, n, AVP_MESSAGE_TYPE);
    CHECK(v != NULL);
    if (v)
        CHECK_EQ_INT(be16(v->val), 1);       /* SCCRQ */

    v = find_avp(avps, n, AVP_PROTOCOL_VER);
    CHECK(v != NULL);
    if (v) {
        CHECK_EQ_INT(v->len, 2);
        CHECK_EQ_INT(v->val[0], 0x01);       /* L2TPv2 */
    }

    v = find_avp(avps, n, AVP_ASSIGNED_TUNNEL);
    CHECK(v != NULL);
    if (v)
        CHECK_EQ_INT(be16(v->val), 0x1234);

    v = find_avp(avps, n, AVP_RECV_WINDOW);
    CHECK(v != NULL);
    if (v)
        CHECK_EQ_INT(be16(v->val), 8);

    v = find_avp(avps, n, AVP_HOST_NAME);
    CHECK(v != NULL);
    if (v) {
        char name[32];
        size_t l = v->len < sizeof(name) - 1 ? v->len : sizeof(name) - 1;
        memcpy(name, v->val, l);
        name[l] = '\0';
        CHECK(strcmp(name, "vpnclient-test") == 0);
    }

    v = find_avp(avps, n, AVP_TIE_BREAKER);
    CHECK(v != NULL);
    if (v)
        CHECK_EQ_INT(v->len, 8);
}

TEST(l2tp_icrq_iccn)
{
    uint8_t pkt[256];
    avp_view avps[8];
    bool ok = false;
    int len, n;
    const avp_view *v;

    len = vpn_l2tp_build_icrq(pkt, sizeof(pkt), 0x0102, 0x0304);
    CHECK(len > 12);
    n = parse_ctrl(pkt, len, avps, 8, &ok);
    CHECK(ok == true);
    CHECK_EQ_INT(be16(pkt + 4), 0x0102);     /* tunnel id */
    v = find_avp(avps, n, AVP_MESSAGE_TYPE);
    CHECK(v != NULL);
    if (v)
        CHECK_EQ_INT(be16(v->val), 10);      /* ICRQ（RFC 2661 §3.3） */
    v = find_avp(avps, n, AVP_ASSIGNED_SESSION);
    CHECK(v != NULL);
    if (v)
        CHECK_EQ_INT(be16(v->val), 0x0304);

    len = vpn_l2tp_build_iccn(pkt, sizeof(pkt), 0x0102, 0x0304);
    CHECK(len > 12);
    n = parse_ctrl(pkt, len, avps, 8, &ok);
    CHECK(ok == true);
    v = find_avp(avps, n, AVP_MESSAGE_TYPE);
    CHECK(v != NULL);
    if (v)
        CHECK_EQ_INT(be16(v->val), 12);      /* ICCN */
}

TEST(l2tp_capacity_guard)
{
    uint8_t tiny[8];

    CHECK_EQ_INT(vpn_l2tp_build_sccrq(tiny, sizeof(tiny), 1, 4, "host"), -1);
    CHECK_EQ_INT(vpn_l2tp_build_icrq(tiny, sizeof(tiny), 1, 2), -1);
    CHECK_EQ_INT(vpn_l2tp_build_iccn(tiny, sizeof(tiny), 1, 2), -1);
}
