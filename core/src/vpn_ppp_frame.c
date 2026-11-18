/* vpn_ppp_frame.c - PPP over HDLC-like 成帧（RFC 1662），SSTP 用它承载 PPP */
#include "vpncore/vpn_ppp_frame.h"

#include <string.h>

static uint16_t fcs_table[256];
static int fcs_ready = 0;

static void fcs_init_table(void)
{
    for (int i = 0; i < 256; i++) {
        uint16_t v = (uint16_t)i;
        for (int b = 0; b < 8; b++)
            v = (uint16_t)((v & 1) ? ((v >> 1) ^ 0x8408) : (v >> 1));
        fcs_table[i] = v;
    }
    fcs_ready = 1;
}

uint16_t vpn_ppp_fcs16(const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    uint16_t fcs = 0xffff;

    if (!fcs_ready)
        fcs_init_table();

    for (size_t i = 0; i < len; i++)
        fcs = (uint16_t)((fcs >> 8) ^ fcs_table[(fcs ^ p[i]) & 0xff]);

    return (uint16_t)~fcs;
}

static inline int needs_escape(uint8_t b)
{
    return b < 0x20 || b == 0x7d || b == 0x7e;
}

int vpn_ppp_hdlc_encode(const uint8_t *frame, size_t len, uint8_t *out, size_t cap)
{
    size_t pos = 0;
    uint16_t fcs;
    uint8_t tail[2];

    if (!frame || !out || len < 2)
        return -1;

    if (pos >= cap)
        return -1;
    out[pos++] = PPP_FLAG;
    if (pos >= cap)
        return -1;
    out[pos++] = 0xff;
    if (pos >= cap)
        return -1;
    out[pos++] = 0x03;

    if (!fcs_ready)
        fcs_init_table();

    /* FCS 覆盖 Address(0xFF) + Control(0x03) + Protocol + Information（RFC 1662 §3.1） */
    fcs = 0xffff;
    fcs = (uint16_t)((fcs >> 8) ^ fcs_table[(fcs ^ 0xff) & 0xff]);
    fcs = (uint16_t)((fcs >> 8) ^ fcs_table[(fcs ^ 0x03) & 0xff]);

    for (size_t i = 0; i < len; i++) {
        uint8_t b = frame[i];
        fcs = (uint16_t)((fcs >> 8) ^ fcs_table[(fcs ^ b) & 0xff]);
        if (needs_escape(b)) {
            if (pos + 2 > cap)
                return -1;
            out[pos++] = PPP_ESCAPE;
            out[pos++] = (uint8_t)(b ^ 0x20);
        } else {
            if (pos + 1 > cap)
                return -1;
            out[pos++] = b;
        }
    }

    fcs = (uint16_t)~fcs;
    tail[0] = (uint8_t)(fcs & 0xff);
    tail[1] = (uint8_t)(fcs >> 8);

    for (int i = 0; i < 2; i++) {
        uint8_t b = tail[i];
        if (needs_escape(b)) {
            if (pos + 2 > cap)
                return -1;
            out[pos++] = PPP_ESCAPE;
            out[pos++] = (uint8_t)(b ^ 0x20);
        } else {
            if (pos + 1 > cap)
                return -1;
            out[pos++] = b;
        }
    }

    if (pos + 1 > cap)
        return -1;
    out[pos++] = PPP_FLAG;

    return (int)pos;
}

void vpn_hdlc_decoder_init(vpn_hdlc_decoder *d, vpn_hdlc_frame_cb cb, void *ctx)
{
    memset(d, 0, sizeof(*d));
    d->fcs = 0xffff;
    d->cb = cb;
    d->ctx = ctx;
    if (!fcs_ready)
        fcs_init_table();
}

static void decoder_deliver(vpn_hdlc_decoder *d)
{
    const uint8_t *f;
    size_t flen;
    const uint8_t *pos;
    size_t remaining;

    if (!d->in_frame || d->len < 4) {
        d->len = 0;
        d->fcs = 0xffff;
        d->in_frame = 0;
        return;
    }

    /* 整帧（含 FCS）FCS 计算结果应为 0xf0b8 */
    if (d->fcs != 0xf0b8) {
        d->frames_bad_fcs++;
        d->len = 0;
        d->fcs = 0xffff;
        d->in_frame = 0;
        return;
    }

    d->frames_ok++;
    d->in_frame = 0;

    pos = d->buf;
    remaining = d->len - 2; /* 去掉 FCS */

    /* ACFC：0xFF 0x03 */
    if (remaining >= 2 && pos[0] == 0xff && pos[1] == 0x03) {
        pos += 2;
        remaining -= 2;
    }

    if (remaining < 2) {
        d->len = 0;
        d->fcs = 0xffff;
        return;
    }

    /* 协议字段：PFC 压缩(1 字节)与未压缩(2 字节)都以协议号打头，直接上抛，
     * 由上层用 vpn_be16/单字节判断解析，避免在此处做二次猜测。 */
    f = pos;
    flen = remaining;

    if (d->cb && flen >= 2)
        d->cb(d->ctx, f, flen);

    d->len = 0;
    d->fcs = 0xffff;
}

void vpn_hdlc_decoder_feed(vpn_hdlc_decoder *d, const uint8_t *data, size_t len)
{
    if (!fcs_ready)
        fcs_init_table();

    for (size_t i = 0; i < len; i++) {
        uint8_t b = data[i];

        if (b == PPP_FLAG) {
            decoder_deliver(d);
            d->in_frame = 1;
            d->len = 0;
            d->fcs = 0xffff;
            d->escaped = 0;
            continue;
        }

        if (!d->in_frame)
            continue; /* 帧间填充字节 */

        if (b == PPP_ESCAPE) {
            d->escaped = 1;
            continue;
        }

        if (d->escaped) {
            b ^= 0x20;
            d->escaped = 0;
        }

        if (d->len >= sizeof(d->buf)) {
            d->frames_overflow++;
            d->in_frame = 0;
            d->len = 0;
            d->fcs = 0xffff;
            continue;
        }

        d->fcs = (uint16_t)((d->fcs >> 8) ^ fcs_table[(d->fcs ^ b) & 0xff]);
        d->buf[d->len++] = b;
    }
}
