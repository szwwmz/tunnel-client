/* SPDX-License-Identifier: LicenseRef-Proprietary
   Copyright (c) 2026 wwm-spec. All rights reserved.
 */

/* vpn_md4.c - MD4 (RFC 1320)，MS-CHAPv2 的 NT 密码哈希需要 */
#include "vpncore/vpn_crypto.h"

#include <string.h>

#define MD4_F(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define MD4_G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define MD4_H(x, y, z) ((x) ^ (y) ^ (z))
#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))
#define STEP(f, a, b, c, d, x, s) (a) = ROTL32((a) + f((b), (c), (d)) + (x), (s))

static void md4_block(uint32_t st[4], const uint8_t block[64])
{
    uint32_t x[16];
    uint32_t a = st[0], b = st[1], c = st[2], d = st[3];
    int i;

    for (i = 0; i < 16; i++)
        x[i] = (uint32_t)block[i * 4] | ((uint32_t)block[i * 4 + 1] << 8) |
               ((uint32_t)block[i * 4 + 2] << 16) | ((uint32_t)block[i * 4 + 3] << 24);

    STEP(MD4_F, a, b, c, d, x[0], 3);
    STEP(MD4_F, d, a, b, c, x[1], 7);
    STEP(MD4_F, c, d, a, b, x[2], 11);
    STEP(MD4_F, b, c, d, a, x[3], 19);
    STEP(MD4_F, a, b, c, d, x[4], 3);
    STEP(MD4_F, d, a, b, c, x[5], 7);
    STEP(MD4_F, c, d, a, b, x[6], 11);
    STEP(MD4_F, b, c, d, a, x[7], 19);
    STEP(MD4_F, a, b, c, d, x[8], 3);
    STEP(MD4_F, d, a, b, c, x[9], 7);
    STEP(MD4_F, c, d, a, b, x[10], 11);
    STEP(MD4_F, b, c, d, a, x[11], 19);
    STEP(MD4_F, a, b, c, d, x[12], 3);
    STEP(MD4_F, d, a, b, c, x[13], 7);
    STEP(MD4_F, c, d, a, b, x[14], 11);
    STEP(MD4_F, b, c, d, a, x[15], 19);

    STEP(MD4_G, a, b, c, d, x[0] + 0x5a827999u, 3);
    STEP(MD4_G, d, a, b, c, x[4] + 0x5a827999u, 5);
    STEP(MD4_G, c, d, a, b, x[8] + 0x5a827999u, 9);
    STEP(MD4_G, b, c, d, a, x[12] + 0x5a827999u, 13);
    STEP(MD4_G, a, b, c, d, x[1] + 0x5a827999u, 3);
    STEP(MD4_G, d, a, b, c, x[5] + 0x5a827999u, 5);
    STEP(MD4_G, c, d, a, b, x[9] + 0x5a827999u, 9);
    STEP(MD4_G, b, c, d, a, x[13] + 0x5a827999u, 13);
    STEP(MD4_G, a, b, c, d, x[2] + 0x5a827999u, 3);
    STEP(MD4_G, d, a, b, c, x[6] + 0x5a827999u, 5);
    STEP(MD4_G, c, d, a, b, x[10] + 0x5a827999u, 9);
    STEP(MD4_G, b, c, d, a, x[14] + 0x5a827999u, 13);
    STEP(MD4_G, a, b, c, d, x[3] + 0x5a827999u, 3);
    STEP(MD4_G, d, a, b, c, x[7] + 0x5a827999u, 5);
    STEP(MD4_G, c, d, a, b, x[11] + 0x5a827999u, 9);
    STEP(MD4_G, b, c, d, a, x[15] + 0x5a827999u, 13);

    STEP(MD4_H, a, b, c, d, x[0] + 0x6ed9eba1u, 3);
    STEP(MD4_H, d, a, b, c, x[8] + 0x6ed9eba1u, 9);
    STEP(MD4_H, c, d, a, b, x[4] + 0x6ed9eba1u, 11);
    STEP(MD4_H, b, c, d, a, x[12] + 0x6ed9eba1u, 15);
    STEP(MD4_H, a, b, c, d, x[2] + 0x6ed9eba1u, 3);
    STEP(MD4_H, d, a, b, c, x[10] + 0x6ed9eba1u, 9);
    STEP(MD4_H, c, d, a, b, x[6] + 0x6ed9eba1u, 11);
    STEP(MD4_H, b, c, d, a, x[14] + 0x6ed9eba1u, 15);
    STEP(MD4_H, a, b, c, d, x[1] + 0x6ed9eba1u, 3);
    STEP(MD4_H, d, a, b, c, x[9] + 0x6ed9eba1u, 9);
    STEP(MD4_H, c, d, a, b, x[5] + 0x6ed9eba1u, 11);
    STEP(MD4_H, b, c, d, a, x[13] + 0x6ed9eba1u, 15);
    STEP(MD4_H, a, b, c, d, x[3] + 0x6ed9eba1u, 3);
    STEP(MD4_H, d, a, b, c, x[11] + 0x6ed9eba1u, 9);
    STEP(MD4_H, c, d, a, b, x[7] + 0x6ed9eba1u, 11);
    STEP(MD4_H, b, c, d, a, x[15] + 0x6ed9eba1u, 15);

    st[0] += a;
    st[1] += b;
    st[2] += c;
    st[3] += d;
}

void vpn_md4_init(vpn_md4_ctx *c)
{
    c->state[0] = 0x67452301u;
    c->state[1] = 0xefcdab89u;
    c->state[2] = 0x98badcfeu;
    c->state[3] = 0x10325476u;
    c->count = 0;
    memset(c->buf, 0, sizeof(c->buf));
}

void vpn_md4_update(vpn_md4_ctx *c, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    size_t used = (size_t)(c->count & 63);

    c->count += len;

    if (used) {
        size_t need = 64 - used;
        if (len < need) {
            memcpy(c->buf + used, p, len);
            return;
        }
        memcpy(c->buf + used, p, need);
        md4_block(c->state, c->buf);
        p += need;
        len -= need;
    }

    while (len >= 64) {
        md4_block(c->state, p);
        p += 64;
        len -= 64;
    }

    if (len)
        memcpy(c->buf, p, len);
}

void vpn_md4_final(vpn_md4_ctx *c, uint8_t out[16])
{
    uint8_t pad[72];
    size_t used = (size_t)(c->count & 63);
    size_t padlen = (used < 56) ? (56 - used) : (120 - used);
    uint64_t bits = c->count * 8;
    int i;

    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;
    for (i = 0; i < 8; i++)
        pad[padlen + i] = (uint8_t)(bits >> (8 * i));

    vpn_md4_update(c, pad, padlen + 8);

    for (i = 0; i < 4; i++) {
        out[i * 4 + 0] = (uint8_t)(c->state[i]);
        out[i * 4 + 1] = (uint8_t)(c->state[i] >> 8);
        out[i * 4 + 2] = (uint8_t)(c->state[i] >> 16);
        out[i * 4 + 3] = (uint8_t)(c->state[i] >> 24);
    }
}
