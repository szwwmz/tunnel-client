/* SPDX-License-Identifier: LicenseRef-Proprietary
   Copyright (c) 2026 wwm-spec. All rights reserved.
 */

/* vpn_crypto.c - MS-CHAPv2 (RFC 2759) / MPPE 密钥 (RFC 3079) / 哈希封装 */
#include "vpncore/vpn_crypto.h"
#include "vpncore/vpn_error.h"
#include "vpncore/vpn_log.h"
#include "vpncore/vpn_platform.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

/* MS-CHAPv2 魔数（RFC 2759 §8） */
static const char MSCHAP_MAGIC1[] = "Magic server to client signing constant";
/* RFC 2759 §8：AuthenticatorResponse 还必须拼上 Magic2 */
static const char MSCHAP_MAGIC2[] = "Pad to make it do more than one iteration";
/* RFC 3079 §3.2 GetMasterKey 的固定串 */
static const uint8_t MPPE_MAGIC1[] = "This is the MPPE Master Key";
/* RFC 3079 §3.3：GetAsymmetricStartKey 用的两条 84 字节方向常量 */
static const char MPPE_MAGIC_SEND[] =
    "On the client side, this is the send key; on the server side, it is the receive key.";
static const char MPPE_MAGIC_RECV[] =
    "On the client side, this is the receive key; on the server side, it is the send key.";

/* ---------------- 通用哈希 ---------------- */
int vpn_sha1(const void *data, size_t len, uint8_t out[20])
{
    unsigned int outlen = 0;
    if (!EVP_Digest(data, len, out, &outlen, EVP_sha1(), NULL))
        return VPN_ERR_IO;
    return outlen == 20 ? VPN_OK : VPN_ERR_IO;
}

int vpn_md5(const void *data, size_t len, uint8_t out[16])
{
    unsigned int outlen = 0;
    if (!EVP_Digest(data, len, out, &outlen, EVP_md5(), NULL))
        return VPN_ERR_IO;
    return outlen == 16 ? VPN_OK : VPN_ERR_IO;
}

int vpn_hmac_sha1(const void *key, size_t keylen, const void *data, size_t len,
                  uint8_t out[20])
{
    unsigned int outlen = 0;
    if (!HMAC(EVP_sha1(), key, (int)keylen, (const unsigned char *)data, len, out, &outlen))
        return VPN_ERR_IO;
    return outlen == 20 ? VPN_OK : VPN_ERR_IO;
}

void vpn_rand_bytes(void *out, size_t len)
{
    if (RAND_bytes((unsigned char *)out, (int)len) != 1) {
        /* 极端情况下的兜底：时间 + 递增熵，保证流程不中断（并明确告警） */
        uint8_t *p = (uint8_t *)out;
        static uint32_t seed = 0x12345678u;
        int64_t now = vpn_now_ms();
        for (size_t i = 0; i < len; i++)
            p[i] = (uint8_t)(((uint64_t)now >> ((i % 8) * 8)) ^ (seed += 0x9e3779b9u));
        VPN_ERROR("RAND_bytes failed, falling back to weak randomness (reduced key and certificate strength)");
    }
}

uint32_t vpn_rand_u32(void)
{
    uint32_t v;
    vpn_rand_bytes(&v, sizeof(v));
    return v;
}

const char *vpn_crypto_version(void)
{
    return OpenSSL_version(OPENSSL_VERSION);
}

bool vpn_ct_equal(const void *a, const void *b, size_t len)
{
    const uint8_t *x = (const uint8_t *)a;
    const uint8_t *y = (const uint8_t *)b;
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++)
        diff |= (uint8_t)(x[i] ^ y[i]);
    return diff == 0;
}

/* ---------------- UTF-8 -> UTF-16LE ---------------- */
static int utf8_to_utf16le(const char *s, uint8_t *out, size_t cap, size_t *outlen)
{
    size_t pos = 0;
    const uint8_t *p = (const uint8_t *)s;

    while (*p) {
        uint32_t cp;
        int extra;

        if (p[0] < 0x80) { cp = p[0]; extra = 0; }
        else if ((p[0] & 0xe0) == 0xc0) { cp = p[0] & 0x1f; extra = 1; }
        else if ((p[0] & 0xf0) == 0xe0) { cp = p[0] & 0x0f; extra = 2; }
        else if ((p[0] & 0xf8) == 0xf0) { cp = p[0] & 0x07; extra = 3; }
        else return VPN_ERR_INVALID;

        for (int i = 1; i <= extra; i++) {
            if ((p[i] & 0xc0) != 0x80)
                return VPN_ERR_INVALID;
            cp = (cp << 6) | (p[i] & 0x3f);
        }
        p += extra + 1;

        if (cp >= 0x10000) {
            /* 代理对 */
            if (pos + 4 > cap)
                return VPN_ERR_NOMEM;
            cp -= 0x10000;
            uint16_t hi = (uint16_t)(0xd800 + (cp >> 10));
            uint16_t lo = (uint16_t)(0xdc00 + (cp & 0x3ff));
            out[pos++] = (uint8_t)(hi & 0xff);
            out[pos++] = (uint8_t)(hi >> 8);
            out[pos++] = (uint8_t)(lo & 0xff);
            out[pos++] = (uint8_t)(lo >> 8);
        } else {
            if (pos + 2 > cap)
                return VPN_ERR_NOMEM;
            out[pos++] = (uint8_t)(cp & 0xff);
            out[pos++] = (uint8_t)(cp >> 8);
        }
    }

    *outlen = pos;
    return VPN_OK;
}

static int nt_password_hash(const char *password, uint8_t out[16])
{
    uint8_t u16[512];
    size_t u16len = 0;
    vpn_md4_ctx ctx;

    if (utf8_to_utf16le(password ? password : "", u16, sizeof(u16), &u16len) != VPN_OK)
        return VPN_ERR_INVALID;

    vpn_md4_init(&ctx);
    vpn_md4_update(&ctx, u16, u16len);
    vpn_md4_final(&ctx, out);
    return VPN_OK;
}

/* ---------------- MS-CHAPv2 ---------------- */
static void challenge_hash(const uint8_t peer_chal[16], const uint8_t auth_chal[16],
                           const char *username, uint8_t out8[8])
{
    uint8_t buf[16 + 16 + 256];
    size_t pos = 0, ulen = strlen(username ? username : "");
    uint8_t digest[20];

    if (ulen > 255)
        ulen = 255;

    memcpy(buf + pos, peer_chal, 16);
    pos += 16;
    memcpy(buf + pos, auth_chal, 16);
    pos += 16;
    memcpy(buf + pos, username, ulen);
    pos += ulen;

    vpn_sha1(buf, pos, digest);
    memcpy(out8, digest, 8);
}

static void des_key_from_7(const uint8_t *seven, uint8_t key[8])
{
    /* 7 字节 -> 8 字节：每字节低 1 位是奇校验位，数据只占高 7 位 */
    key[0] = (uint8_t)(seven[0] & 0xfe);
    key[1] = (uint8_t)(((seven[0] << 7) | (seven[1] >> 1)) & 0xfe);
    key[2] = (uint8_t)(((seven[1] << 6) | (seven[2] >> 2)) & 0xfe);
    key[3] = (uint8_t)(((seven[2] << 5) | (seven[3] >> 3)) & 0xfe);
    key[4] = (uint8_t)(((seven[3] << 4) | (seven[4] >> 4)) & 0xfe);
    key[5] = (uint8_t)(((seven[4] << 3) | (seven[5] >> 5)) & 0xfe);
    key[6] = (uint8_t)(((seven[5] << 2) | (seven[6] >> 6)) & 0xfe);
    key[7] = (uint8_t)((seven[6] << 1) & 0xfe);

    /* 设置奇校验位 */
    for (int i = 0; i < 8; i++) {
        uint8_t b = key[i];
        int ones = 0;
        for (int j = 0; j < 8; j++)
            ones += (b >> j) & 1;
        if ((ones & 1) == 0)
            key[i] = (uint8_t)(b | 1);
    }
}

static void challenge_response(const uint8_t challenge[8], const uint8_t nt_hash[16],
                               uint8_t out[24])
{
    uint8_t z[24];
    uint8_t key[8];

    memcpy(z, nt_hash, 16);
    memset(z + 16, 0, 8);

    /* RFC 2759 §8：三段 DES 都以同一个 8 字节 Challenge 为明文，
     * 不做链式（chained）——链式是早年实现里常见的错误。 */
    for (int i = 0; i < 3; i++) {
        des_key_from_7(z + i * 7, key);
        vpn_des_encrypt_block(key, challenge, out + i * 8);
    }
}

int vpn_mschapv2_nt_response(const char *password, const uint8_t peer_challenge[16],
                             const uint8_t auth_challenge[16], const char *username,
                             uint8_t response_out[24], uint8_t nt_hash_out[16])
{
    uint8_t nt_hash[16];
    uint8_t chal[8];

    if (nt_password_hash(password, nt_hash) != VPN_OK)
        return VPN_ERR_INVALID;

    challenge_hash(peer_challenge, auth_challenge, username, chal);
    challenge_response(chal, nt_hash, response_out);

    if (nt_hash_out)
        memcpy(nt_hash_out, nt_hash, 16);
    return VPN_OK;
}

int vpn_mschapv2_authenticator_response(const uint8_t nt_hash[16],
                                        const uint8_t peer_challenge[16],
                                        const uint8_t auth_challenge[16],
                                        const char *username, char *out, size_t outlen)
{
    uint8_t buf[16 + 24 + 48 + 48];
    uint8_t digest[20];
    uint8_t pw_hash_hash[16];
    uint8_t nt_response[24];
    uint8_t chal[8];
    vpn_md4_ctx md4;
    size_t pos = 0;

    if (!out || outlen < 43)
        return VPN_ERR_INVALID;

    vpn_md4_init(&md4);
    vpn_md4_update(&md4, nt_hash, 16);
    vpn_md4_final(&md4, pw_hash_hash);

    challenge_hash(peer_challenge, auth_challenge, username, chal);
    challenge_response(chal, nt_hash, nt_response);

    /* AuthenticatorResponse 是两段哈希（RFC 2759 §8）：
     *   D = SHA1(PasswordHashHash || NTResponse || Magic1)
     *   AuthenticatorResponse = SHA1(D || Challenge || Magic2) */
    memcpy(buf + pos, pw_hash_hash, 16);
    pos += 16;
    memcpy(buf + pos, nt_response, 24);
    pos += 24;
    memcpy(buf + pos, MSCHAP_MAGIC1, sizeof(MSCHAP_MAGIC1) - 1);
    pos += sizeof(MSCHAP_MAGIC1) - 1;

    vpn_sha1(buf, pos, digest);

    pos = 0;
    memcpy(buf + pos, digest, 20);
    pos += 20;
    memcpy(buf + pos, chal, 8);
    pos += 8;
    memcpy(buf + pos, MSCHAP_MAGIC2, sizeof(MSCHAP_MAGIC2) - 1);
    pos += sizeof(MSCHAP_MAGIC2) - 1;

    vpn_sha1(buf, pos, digest);

    snprintf(out, outlen, "S=");
    for (int i = 0; i < 20; i++)
        snprintf(out + 2 + i * 2, outlen - 2 - i * 2, "%02X", digest[i]);
    return VPN_OK;
}

int vpn_mschapv2_mppe_keys(const uint8_t nt_hash[16], const uint8_t nt_response[24],
                           uint8_t send_key[16], uint8_t recv_key[16])
{
    uint8_t pw_hash_hash[16];
    uint8_t buf[16 + 24 + sizeof(MPPE_MAGIC1) + 16];
    uint8_t master[16];
    vpn_md4_ctx md4;
    size_t pos = 0;

    vpn_md4_init(&md4);
    vpn_md4_update(&md4, nt_hash, 16);
    vpn_md4_final(&md4, pw_hash_hash);

    /* MasterKey = SHA1(PasswordHashHash || NTResponse || Magic1)[0..15] */
    memcpy(buf + pos, pw_hash_hash, 16);
    pos += 16;
    memcpy(buf + pos, nt_response, 24);
    pos += 24;
    memcpy(buf + pos, MPPE_MAGIC1, sizeof(MPPE_MAGIC1) - 1);
    pos += sizeof(MPPE_MAGIC1) - 1;

    uint8_t digest[20];
    vpn_sha1(buf, pos, digest);
    memcpy(master, digest, 16);

    /* RFC 3079 §3.2/§3.4 GetAsymmetricStartKey（客户端视角）：
     *   MasterSendKey    = SHA1(MasterKey || SHSpad1(40*0x00) || Magic2(84B) || SHSpad2(40*0xF2))
     *   MasterReceiveKey = SHA1(MasterKey || SHSpad1(40*0x00) || Magic3(84B) || SHSpad2(40*0xF2))
     * 128 位密钥直接取摘要前 16 字节。
     * 这两个 master key 才是 MS-SSTP Crypto-Binding 的 HLAK 来源
     * （HLAK = MasterSendKey || MasterReceiveKey），并非 MPPE 会话密钥。 */
    for (int is_send = 1; is_send >= 0; is_send--) {
        const char *magic = is_send ? MPPE_MAGIC_SEND : MPPE_MAGIC_RECV;
        size_t magic_len = is_send ? sizeof(MPPE_MAGIC_SEND) - 1 : sizeof(MPPE_MAGIC_RECV) - 1;
        uint8_t kbuf[16 + 40 + 84 + 40];
        uint8_t kdig[20];
        size_t kpos = 0;

        memcpy(kbuf + kpos, master, 16);
        kpos += 16;
        memset(kbuf + kpos, 0x00, 40);   /* SHSpad1 */
        kpos += 40;
        memcpy(kbuf + kpos, magic, magic_len);
        kpos += magic_len;
        memset(kbuf + kpos, 0xf2, 40);   /* SHSpad2 */
        kpos += 40;

        vpn_sha1(kbuf, kpos, kdig);
        if (is_send)
            memcpy(send_key, kdig, 16);
        else
            memcpy(recv_key, kdig, 16);
    }
    return VPN_OK;
}
