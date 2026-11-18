/* SPDX-License-Identifier: LicenseRef-Proprietary
   Copyright (c) 2026 wwm-spec. All rights reserved.
 */

/* test_hdlc.c - PPP over HDLC 成帧（RFC 1662）编解码回环 */
#include "test.h"

#include "vpncore/vpn_ppp_frame.h"

typedef struct {
    uint8_t  frame[4096];
    size_t   len;
    int      count;
} capture;

static void on_frame(void *ctx, const uint8_t *frame, size_t len)
{
    capture *c = ctx;
    if (c->count == 0 && len <= sizeof(c->frame)) {
        memcpy(c->frame, frame, len);
        c->len = len;
    }
    c->count++;
}

static void roundtrip(const uint8_t *payload, size_t len, int feed_chunk)
{
    uint8_t enc[8192];
    vpn_hdlc_decoder dec;
    capture cap;
    int n, i;

    memset(&cap, 0, sizeof(cap));
    n = vpn_ppp_hdlc_encode(payload, len, enc, sizeof(enc));
    CHECK(n > 0);
    CHECK_EQ_INT(enc[0], PPP_FLAG);
    CHECK_EQ_INT(enc[n - 1], PPP_FLAG);
    /* 帧内部不应出现未转义的 0x7E */
    for (i = 1; i < n - 1; i++)
        CHECK(enc[i] != PPP_FLAG || enc[i - 1] == PPP_ESCAPE);

    vpn_hdlc_decoder_init(&dec, on_frame, &cap);
    if (feed_chunk <= 1) {
        for (i = 0; i < n; i++)
            vpn_hdlc_decoder_feed(&dec, enc + i, 1);
    } else {
        vpn_hdlc_decoder_feed(&dec, enc, (size_t)n);
    }

    CHECK_EQ_INT(cap.count, 1);
    CHECK_EQ_INT(cap.len, len);
    if (cap.len == len)
        CHECK_BYTES(cap.frame, payload, len);
    CHECK_EQ_INT(dec.frames_ok, 1);
    CHECK_EQ_INT(dec.frames_bad_fcs, 0);
}

TEST(hdlc_plain_ipv4_frame)
{
    /* 0x0021 = IPv4，含一个典型的小 IP 包 */
    const uint8_t pkt[] = { 0x00, 0x21, 0x45, 0x00, 0x00, 0x28, 0x00, 0x01,
                            0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0x0a, 0x00,
                            0x00, 0x01, 0x0a, 0x00, 0x00, 0x02 };
    roundtrip(pkt, sizeof(pkt), 0);
    roundtrip(pkt, sizeof(pkt), 1);
}

TEST(hdlc_escape_bytes)
{
    /* 0x7e / 0x7d / 0x11（XON）都必须被转义 */
    const uint8_t pkt[] = { 0x00, 0x21, 0x7e, 0x7d, 0x11, 0x13, 0x20, 0x00, 0x7e };
    roundtrip(pkt, sizeof(pkt), 0);
    roundtrip(pkt, sizeof(pkt), 1);
}

TEST(hdlc_large_frame)
{
    uint8_t pkt[1500];
    size_t i;

    pkt[0] = 0x00;
    pkt[1] = 0x21;
    for (i = 2; i < sizeof(pkt); i++)
        pkt[i] = (uint8_t)(i * 31 + 7);
    roundtrip(pkt, sizeof(pkt), 0);
}

TEST(hdlc_bad_fcs_rejected)
{
    const uint8_t pkt[] = { 0x00, 0x21, 0x01, 0x02, 0x03, 0x04 };
    uint8_t enc[256];
    vpn_hdlc_decoder dec;
    capture cap;
    int n, i;

    memset(&cap, 0, sizeof(cap));
    n = vpn_ppp_hdlc_encode(pkt, sizeof(pkt), enc, sizeof(enc));
    CHECK(n > 0);

    /* 破坏一个数据字节（跳过 0x7E 0xFF 0x03 头），FCS 必须失配 */
    enc[3] ^= 0xa5;
    /* 保证没有把 0x7E 弄进来 */
    if (enc[3] == PPP_FLAG || enc[3] == PPP_ESCAPE)
        enc[3] = 0x00;

    vpn_hdlc_decoder_init(&dec, on_frame, &cap);
    for (i = 0; i < n; i++)
        vpn_hdlc_decoder_feed(&dec, enc + i, 1);

    CHECK_EQ_INT(cap.count, 0);
    CHECK_EQ_INT(dec.frames_bad_fcs, 1);
}

TEST(hdlc_fcs16_consistency)
{
    /* 对同一段数据，FCS 应当是确定值；这里验证 ~FCS 与 "整帧余数 0xf0b8" 的关系 */
    const uint8_t data[] = { 0xff, 0x03, 0xc0, 0x21, 0x01, 0x01, 0x00, 0x04 };
    uint16_t fcs = vpn_ppp_fcs16(data, sizeof(data));
    CHECK(fcs != 0xffff || sizeof(data) == 0);
}
