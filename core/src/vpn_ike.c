/* SPDX-License-Identifier: LicenseRef-Proprietary
   Copyright (c) 2026 wwm-spec. All rights reserved.
 */

/* vpn_ike.c - IKEv1 (PSK) + ESP transport，用户态实现
 *
 * 覆盖 L2TP/IPsec：IKEv1 主模式 PSK + Quick Mode(ESP transport)
 * + ESP(AES-CBC-256/SHA1) + NAT-T(UDP 4500)。
 *
 * 不走内核 xfrm 的原因：Android 上应用无法下发 transport 模式 SA，也不能
 * 发送 IP 协议 50；全部走 UDP 500/4500 后纯用户态即可，三平台共用一份代码。
 */
#include "vpncore/vpn_ike.h"
#include "vpncore/vpn_net.h"
#include "vpncore/vpn_crypto.h"
#include "vpncore/vpn_error.h"
#include "vpncore/vpn_log.h"
#include "vpncore/vpn_platform.h"

#include <openssl/bn.h>
#include <openssl/evp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IKE_HDR_LEN 28
#define IKE_BLOCK   16
#define IKE_IV_LEN  16
#define IKE_KEY_LEN 32

#define PL_SA    1
#define PL_KE    4
#define PL_ID    5
#define PL_HASH  8
#define PL_NONCE 10

#define EX_MAIN 2
#define EX_QM   32

#define ENC_AES_CBC    7
#define HASH_SHA1      2
#define AUTH_PSK       1
#define GROUP_MODP1024 2
#define ESP_TRANS_AES  12

#define ESP_KEY_LEN (IKE_KEY_LEN + 20)

#define PL_VID   13
#define PL_NATD  20 /* NAT-D（RFC 3947） */

/* NAT-T 能力通告（draft-ietf-ipsec-nat-t-ike 系列的公开哈希值） */
static const uint8_t NATT_VID[16] = {
    0x4a, 0x13, 0x1c, 0x81, 0x07, 0x03, 0x58, 0x45,
    0x5c, 0x57, 0x28, 0xf2, 0x0e, 0x95, 0x45, 0x2f
};

struct vpn_ipsec {
    vpn_ike_params p;

    vpn_sock_t isk;
    vpn_sock_t esk;

    uint8_t local_ip[4];
    uint8_t peer_ip[4];

    uint8_t cky_i[8];
    uint8_t cky_r[8];
    uint8_t sa_i_body[256];
    size_t  sa_i_len;

    BIGNUM *dh_p;
    BIGNUM *dh_priv;
    uint8_t ke_i[128];
    uint8_t ke_r[128];
    uint8_t nonce_i[64];
    size_t  nonce_i_len;
    uint8_t nonce_r[64];
    size_t  nonce_r_len;   /* 对端 nonce 长度可变，绝不能截断成 20 字节 */
    uint8_t shared[128];

    uint8_t skeyid[20];
    uint8_t skeyid_d[20];
    uint8_t skeyid_a[20];
    uint8_t skeyid_e[20];
    uint8_t ike_enc_key[IKE_KEY_LEN];
    int     ike_enc_len;   /* 由对端选中的变换决定（AES: 16/24/32） */
    uint8_t id_r[16];      /* 对端 ID 载荷原文：HASH_R 必须逐字节一致 */
    size_t  id_r_len;
    uint8_t iv[IKE_IV_LEN];        /* 当前 CBC 链的 IV（IKEv1 不传 IV） */
    uint8_t phase1_iv[IKE_IV_LEN]; /* hash(KE_i|KE_r) 的前 16 字节 */
    bool    natt;          /* 宣布 NAT 存在 -> 对端浮动到 UDP/4500 */
    bool    ike4500;       /* 当前 IKE 走 4500（前置 4 字节 0） */

    uint32_t spi_in;
    uint32_t spi_out;
    uint32_t seq_out;
    uint32_t qm_mid;
    uint8_t  esp_enc_key[IKE_KEY_LEN];   /* 出方向：加密 */
    uint8_t  esp_auth_key[20];           /* 出方向：认证 */
    uint8_t  esp_dec_key[IKE_KEY_LEN];   /* 入方向：解密 */
    uint8_t  esp_dec_auth[20];           /* 入方向：认证 */
    int      esp_enc_len;                /* 出方向加密密钥长度 */
    int      esp_dec_len;                /* 入方向加密密钥长度 */
    bool     dec_use_spi_out;            /* 入方向密钥按 spi_out 派生（兼容性候选） */
    uint8_t  qm_nonce_i[64];
    size_t   qm_nonce_i_len;
    uint8_t  qm_nonce_r[64];
    size_t   qm_nonce_r_len;
    bool     up;

    /* ESP 传输通道：优先原始 ESP（IP 协议 50）。对端内核只有在检测到 NAT 时
     * 才会给 SA 打 XFRMA_ENCAP，所以同一网段直连时只能发协议 50；
     * 只有 raw socket 不可用（非 root/Android）时才退回 UDP/4500 封装。 */
    vpn_sock_t rsk;
    bool       esp_raw;
};

/* ---------------- 基础工具 ---------------- */
static uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

typedef struct {
    uint8_t *b;
    size_t   cap;
    size_t   off;
    size_t   prev;
} pbuild;

static void pb_init(pbuild *w, uint8_t *buf, size_t cap)
{
    w->b = buf;
    w->cap = cap;
    w->off = IKE_HDR_LEN;
    w->prev = 0;
}

static int pb_add(pbuild *w, uint8_t type, const void *body, size_t blen)
{
    size_t h;

    if (w->off + 4 + blen > w->cap)
        return VPN_ERR_NOMEM;
    h = w->off;
    w->b[h] = 0;
    w->b[h + 1] = 0;
    wr16(w->b + h + 2, (uint16_t)(4 + blen));
    if (blen && body)
        memcpy(w->b + h + 4, body, blen);
    if (w->prev)
        w->b[w->prev] = type;
    else
        w->b[16] = type;
    w->prev = h;
    w->off = h + 4 + blen;
    return VPN_OK;
}

static void ike_hdr(uint8_t *b, const uint8_t *cki, const uint8_t *ckr,
                    uint8_t exchange, uint8_t flags, uint32_t mid, size_t total)
{
    memcpy(b, cki, 8);
    memcpy(b + 8, ckr, 8);
    b[17] = 0x10;
    b[18] = exchange;
    b[19] = flags;
    wr32(b + 20, mid);
    wr32(b + 24, (uint32_t)total);
}

typedef struct {
    uint8_t        type;
    const uint8_t *body;
    size_t         len;
} payload_ref;

static int ike_parse(const uint8_t *pkt, size_t len, payload_ref *out, int max)
{
    size_t off = IKE_HDR_LEN;
    uint8_t np;
    int n = 0;

    if (len < IKE_HDR_LEN)
        return 0;
    np = pkt[16];
    while (np != 0 && off + 4 <= len && n < max) {
        size_t plen = rd16(pkt + off + 2);
        if (plen < 4 || off + plen > len)
            break;
        out[n].type = np;
        out[n].body = pkt + off + 4;
        out[n].len = plen - 4;
        n++;
        np = pkt[off];
        off += plen;
    }
    return n;
}

static const payload_ref *pl_find(const payload_ref *pl, int n, uint8_t type)
{
    int i;
    for (i = 0; i < n; i++)
        if (pl[i].type == type)
            return &pl[i];
    return NULL;
}

/* ---------------- IKE 报文加解密 ---------------- */
static int aes_cbc(const uint8_t *key, int keylen, int enc, uint8_t *buf, size_t len,
                   const uint8_t iv[16])
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *alg;
    int outl = 0, fin = 0, ok;

    if (keylen == 32)
        alg = EVP_aes_256_cbc();
    else if (keylen == 24)
        alg = EVP_aes_192_cbc();
    else
        alg = EVP_aes_128_cbc(); /* 对端常把 AES 降到 128，必须跟随 */
    if (!ctx)
        return VPN_ERR_NOMEM;
    ok = EVP_CipherInit_ex(ctx, alg, NULL, key, iv, enc) == 1;
    /* IKE/ESP 的填充是任意字节（IKE 补 0、ESP 补递增），不是 PKCS#7：
     * 必须关掉 OpenSSL 的分组填充，否则解密时 Final 会因校验填充失败。
     * 早期开着 padding，导致第 6 包（以及 ESP）解密必然报错。 */
    if (ok)
        ok = EVP_CIPHER_CTX_set_padding(ctx, 0) == 1;
    if (ok)
        ok = EVP_CipherUpdate(ctx, buf, &outl, buf, (int)len) == 1;
    if (ok)
        ok = EVP_CipherFinal_ex(ctx, buf + outl, &fin) == 1;
    EVP_CIPHER_CTX_free(ctx);
    return ok ? VPN_OK : VPN_ERR_PROTO;
}

/* IKEv1 的 IV 不上线传输（RFC 2409 附录 B）：
 *   阶段 1 第一条加密报文  IV = hash(g^xi | g^xr) 取前 block_size 字节
 *   同阶段后续报文        IV = 上一条报文密文的最后一个分组
 *   阶段 2 该 MID 首包    IV = hash(阶段 1 最后密文块 | MID 大端)
 * 早期版本自造随机 IV 并前置 16 字节，RouterOS 解密必然乱码，后续全部失败。 */
static int ike_encrypt(vpn_ipsec *ip, uint8_t *buf, size_t len, size_t cap)
{
    size_t plen = len - IKE_HDR_LEN;
    size_t pad = (IKE_BLOCK - (plen % IKE_BLOCK)) % IKE_BLOCK;

    if (len + pad > cap)
        return VPN_ERR_NOMEM;
    memset(buf + len, 0, pad);
    plen += pad;
    if (aes_cbc(ip->ike_enc_key, ip->ike_enc_len, 1, buf + IKE_HDR_LEN, plen, ip->iv) != VPN_OK)
        return VPN_ERR_PROTO;
    memcpy(ip->iv, buf + IKE_HDR_LEN + plen - IKE_BLOCK, IKE_BLOCK);
    wr32(buf + 24, (uint32_t)(IKE_HDR_LEN + plen));
    return (int)(IKE_HDR_LEN + plen);
}

static int ike_decrypt(vpn_ipsec *ip, uint8_t *buf, size_t len)
{
    uint8_t last[IKE_BLOCK];
    size_t clen;

    if (len < IKE_HDR_LEN + IKE_BLOCK)
        return VPN_ERR_PROTO;
    clen = len - IKE_HDR_LEN;
    if (clen % IKE_BLOCK)
        return VPN_ERR_PROTO;
    memcpy(last, buf + len - IKE_BLOCK, IKE_BLOCK);
    if (aes_cbc(ip->ike_enc_key, ip->ike_enc_len, 0, buf + IKE_HDR_LEN, clen, ip->iv) != VPN_OK)
        return VPN_ERR_PROTO;
    memcpy(ip->iv, last, IKE_BLOCK);
    wr32(buf + 24, (uint32_t)len);
    return (int)len;
}

/* ---------------- DH ---------------- */
static const char *MODP1024_P =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF";

static int dh_init(vpn_ipsec *ip, char *err, size_t errlen)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *g = BN_new();
    BIGNUM *pub = BN_new();
    int rc = VPN_ERR_NOMEM;

    if (!ctx || !g || !pub)
        goto done;
    if (!BN_hex2bn(&ip->dh_p, MODP1024_P) || !BN_set_word(g, 2))
        goto done;
    ip->dh_priv = BN_new();
    if (!ip->dh_priv || !BN_rand(ip->dh_priv, 1024, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY))
        goto done;
    if (!BN_mod_exp(pub, g, ip->dh_priv, ip->dh_p, ctx))
        goto done;
    if (BN_bn2binpad(pub, ip->ke_i, (int)sizeof(ip->ke_i)) != (int)sizeof(ip->ke_i))
        goto done;
    rc = VPN_OK;

done:
    BN_free(g);
    BN_free(pub);
    BN_CTX_free(ctx);
    if (rc != VPN_OK && err)
        snprintf(err, errlen, "DH initialization failed");
    return rc;
}

static int dh_shared(vpn_ipsec *ip, const uint8_t *peer_ke, size_t peer_len,
                     char *err, size_t errlen)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *pub = BN_bin2bn(peer_ke, (int)peer_len, NULL);
    BIGNUM *sh = BN_new();
    int rc = VPN_ERR_PROTO;

    if (!ctx || !pub || !sh || !ip->dh_priv || !ip->dh_p)
        goto done;
    if (!BN_mod_exp(sh, pub, ip->dh_priv, ip->dh_p, ctx))
        goto done;
    if (BN_bn2binpad(sh, ip->shared, (int)sizeof(ip->shared)) != (int)sizeof(ip->shared))
        goto done;
    rc = VPN_OK;

done:
    BN_free(pub);
    BN_free(sh);
    BN_CTX_free(ctx);
    if (rc != VPN_OK && err)
        snprintf(err, errlen, "DH exchange computation failed");
    return rc;
}

/* ---------------- 载荷构造 ---------------- */
static size_t build_sa_body(uint8_t *out, uint16_t proto_id, uint32_t spi,
                            uint16_t transform_id)
{
    size_t off, prop_off, tr_off;

    wr32(out, 1);     /* DOI: IPSEC */
    wr32(out + 4, 1); /* Situation: IDENTITY_ONLY */
    off = 8;

    prop_off = off;
    out[off] = 0;
    out[off + 1] = 0;
    wr16(out + off + 2, 0);
    out[off + 4] = 1;                    /* Proposal #1 */
    out[off + 5] = (uint8_t)proto_id;    /* 1=ISAKMP 3=ESP */
    out[off + 6] = (proto_id == 1) ? 0 : 4;
    out[off + 7] = 1;                    /* NumTransforms */
    off += 8;
    if (proto_id != 1) {
        wr32(out + off, spi);
        off += 4;
    }

    tr_off = off;
    out[off] = 0;
    out[off + 1] = 0;
    wr16(out + off + 2, 0);
    out[off + 4] = 1;                    /* Transform #1 */
    out[off + 5] = (uint8_t)transform_id;
    wr16(out + off + 6, 0);
    off += 8;

    /* 属性编号必须严格区分两套 DOI：
     * ISAKMP SA（RFC 2407 §4.5）：1 加密 / 2 哈希 / 3 认证方法 / 4 DH 组 /
     *                            10 生存类型 / 11 生存时长
     * IPsec SA（ESP，同节 4.5 IPsec 属性表）：1 生存类型 / 2 生存时长 /
     *                            4 封装模式(2=transport) / 5 认证算法 / 6 密钥长度
     * 早期版本两处都写成了 IKEv2 的编号（11/12/14），RouterOS 会把
     * "生存时长=1 秒" 当成协商结果或直接判定提议非法。 */
    if (proto_id == 1) {
        wr16(out + off, 0x8000 | 1);  wr16(out + off + 2, ENC_AES_CBC);    off += 4;
        wr16(out + off, 0x8000 | 2);  wr16(out + off + 2, HASH_SHA1);      off += 4;
        wr16(out + off, 0x8000 | 3);  wr16(out + off + 2, AUTH_PSK);       off += 4;
        wr16(out + off, 0x8000 | 4);  wr16(out + off + 2, GROUP_MODP1024); off += 4;
        wr16(out + off, 0x8000 | 10); wr16(out + off + 2, 1);              off += 4;
        wr16(out + off, 0x8000 | 11); wr16(out + off + 2, 28800);          off += 4;
    } else {
        wr16(out + off, 0x8000 | 1); wr16(out + off + 2, 1);            off += 4; /* 秒 */
        wr16(out + off, 0x8000 | 2); wr16(out + off + 2, 3600);         off += 4;
        wr16(out + off, 0x8000 | 4); wr16(out + off + 2, 2);            off += 4; /* transport */
        wr16(out + off, 0x8000 | 5); wr16(out + off + 2, HASH_SHA1);    off += 4; /* HMAC-SHA1 */
        wr16(out + off, 0x8000 | 6); wr16(out + off + 2, 256);          off += 4; /* AES-256 */
    }

    wr16(out + tr_off + 2, (uint16_t)(off - tr_off));
    wr16(out + prop_off + 2, (uint16_t)(off - prop_off));
    return off;
}

static size_t build_id_body(uint8_t *out, const uint8_t ip[4], uint8_t proto, uint16_t port)
{
    out[0] = 1; /* ID_IPV4_ADDR */
    out[1] = proto;
    wr16(out + 2, port);
    memcpy(out + 4, ip, 4);
    return 8;
}

/* ---------------- 密钥派生 ---------------- */
static void prf_expand(const uint8_t *key, size_t keylen, const uint8_t *seed,
                       size_t seedlen, uint8_t *out, size_t outlen)
{
    uint8_t t[20], prev[20];
    uint8_t *in;
    size_t prevlen = 0, done = 0;

    in = (uint8_t *)malloc(seedlen + 64);
    if (!in) {
        memset(out, 0, outlen);
        return;
    }
    while (done < outlen) {
        size_t n;
        memcpy(in, prev, prevlen);
        if (seedlen)
            memcpy(in + prevlen, seed, seedlen);
        vpn_hmac_sha1(key, keylen, in, prevlen + seedlen, t);
        memcpy(prev, t, sizeof(prev));
        prevlen = sizeof(prev);
        n = outlen - done > sizeof(t) ? sizeof(t) : outlen - done;
        memcpy(out + done, t, n);
        done += n;
    }
    free(in);
}

/* 调试用：VPN_IKE_TRACE=1 时把密钥材料打到 stderr，便于与独立实现比对 */
static void ike_trace(const char *tag, const uint8_t *b, size_t n)
{
    static int on = -1;
    char hex[2 * 300 + 1];
    size_t i;

    if (on < 0)
        on = getenv("VPN_IKE_TRACE") ? 1 : 0;
    if (!on)
        return;
    if (n > 300)
        n = 300;
    for (i = 0; i < n; i++)
        snprintf(hex + i * 2, 3, "%02x", b[i]);
    hex[n * 2] = 0;
    fprintf(stderr, "TRACE %-12s %s\n", tag, hex);
    fflush(stderr);
}

static void derive_skeyid(vpn_ipsec *ip)
{
    uint8_t seed[300], nonces[128], k2[20], digest[20];

    memcpy(nonces, ip->nonce_i, ip->nonce_i_len);
    memcpy(nonces + ip->nonce_i_len, ip->nonce_r, ip->nonce_r_len);
    /* SKEYID = prf(PSK, Ni | Nr)：PSK 是 HMAC 的密钥，nonce 才是数据。
     * 早期实现把两者写反了，导致 HASH_I/HASH_R 全错（表现为"PSK 不匹配"）。 */
    vpn_hmac_sha1(ip->p.psk, strlen(ip->p.psk), nonces, ip->nonce_i_len + ip->nonce_r_len,
                  ip->skeyid);

    memcpy(seed, ip->shared, 128);
    memcpy(seed + 128, ip->cky_i, 8);
    memcpy(seed + 136, ip->cky_r, 8);
    seed[144] = 0;
    vpn_hmac_sha1(ip->skeyid, 20, seed, 145, ip->skeyid_d);

    memcpy(seed, ip->skeyid_d, 20);
    memcpy(seed + 20, ip->shared, 128);
    memcpy(seed + 148, ip->cky_i, 8);
    memcpy(seed + 156, ip->cky_r, 8);
    seed[164] = 1;
    vpn_hmac_sha1(ip->skeyid, 20, seed, 165, ip->skeyid_a);

    memcpy(seed, ip->skeyid_a, 20);
    memcpy(seed + 20, ip->shared, 128);
    memcpy(seed + 148, ip->cky_i, 8);
    memcpy(seed + 156, ip->cky_r, 8);
    seed[164] = 2;
    vpn_hmac_sha1(ip->skeyid, 20, seed, 165, ip->skeyid_e);

    /* RFC 2409 附录 B：IKE 加密密钥直接取 SKEYID_e 的前 N 字节；
     * 只有算法要求超过 20 字节（AES-256）时才用 prf+ 续接
     * K1 = prf(SKEYID_e, 0x00)、K2 = prf(SKEYID_e, K1)…
     * 早期实现对 AES-128 也做了一次 prf 扩展，密钥全错，对端解密必然失败。 */
    if (ip->ike_enc_len > 20) {
        uint8_t prev[20];
        size_t made = 20;

        memcpy(ip->ike_enc_key, ip->skeyid_e, 20);
        seed[0] = 0;
        vpn_hmac_sha1(ip->skeyid_e, 20, seed, 1, prev);
        for (;;) {
            size_t take = (size_t)ip->ike_enc_len - made;

            if (take > sizeof(prev))
                take = sizeof(prev);
            memcpy(ip->ike_enc_key + made, prev, take);
            made += take;
            if (made >= (size_t)ip->ike_enc_len)
                break;
            vpn_hmac_sha1(ip->skeyid_e, 20, prev, sizeof(prev), k2);
            memcpy(prev, k2, sizeof(prev));
        }
    } else {
        memcpy(ip->ike_enc_key, ip->skeyid_e, (size_t)ip->ike_enc_len);
    }

    /* 阶段 1 初始 IV = hash(g^xi | g^xr) 前 16 字节 */
    memcpy(seed, ip->ke_i, 128);
    memcpy(seed + 128, ip->ke_r, 128);
    vpn_sha1(seed, 256, digest);
    memcpy(ip->phase1_iv, digest, IKE_IV_LEN);
    memcpy(ip->iv, ip->phase1_iv, IKE_IV_LEN);

    ike_trace("psk", (const uint8_t *)ip->p.psk, strlen(ip->p.psk));
    ike_trace("ni", ip->nonce_i, ip->nonce_i_len);
    ike_trace("nr", ip->nonce_r, ip->nonce_r_len);
    ike_trace("ke_i", ip->ke_i, 128);
    ike_trace("ke_r", ip->ke_r, 128);
    ike_trace("gxy", ip->shared, 128);
    ike_trace("skeyid", ip->skeyid, 20);
    ike_trace("skeyid_d", ip->skeyid_d, 20);
    ike_trace("skeyid_a", ip->skeyid_a, 20);
    ike_trace("skeyid_e", ip->skeyid_e, 20);
    ike_trace("enc_key", ip->ike_enc_key, (size_t)ip->ike_enc_len);
    ike_trace("iv", ip->iv, IKE_IV_LEN);
    ike_trace("cky_i", ip->cky_i, 8);
    ike_trace("cky_r", ip->cky_r, 8);
}

static void hash_id(vpn_ipsec *ip, bool initiator, const uint8_t *id, size_t idlen,
                    uint8_t out[20])
{
    uint8_t buf[800];
    size_t off = 0;

    if (initiator) {
        memcpy(buf + off, ip->ke_i, 128); off += 128;
        memcpy(buf + off, ip->ke_r, 128); off += 128;
        memcpy(buf + off, ip->cky_i, 8);  off += 8;
        memcpy(buf + off, ip->cky_r, 8);  off += 8;
    } else {
        memcpy(buf + off, ip->ke_r, 128); off += 128;
        memcpy(buf + off, ip->ke_i, 128); off += 128;
        memcpy(buf + off, ip->cky_r, 8);  off += 8;
        memcpy(buf + off, ip->cky_i, 8);  off += 8;
    }
    memcpy(buf + off, ip->sa_i_body, ip->sa_i_len); off += ip->sa_i_len;
    memcpy(buf + off, id, idlen); off += idlen;
    vpn_hmac_sha1(ip->skeyid, 20, buf, off, out);
}

/* NAT-D（RFC 3947）：MD5(CKY-I | CKY-R | IP | Port)，16 字节。
 *
 * 我们始终需要 UDP/4500 封装（用户态收不到 IP 协议 50），所以源地址那一份
 * 故意用"假外部地址"计算，让对端判定存在 NAT 并强制 NAT-T。真实 NAT 后的
 * 客户端产生的报文与这个形态完全一致，RouterOS/strongSwan 均按标准处理。
 * 对端地址那一份保持诚实。 */
static void natd_hash(vpn_ipsec *ip, const uint8_t ip4[4], uint16_t port, uint8_t out[16])
{
    uint8_t buf[22];

    memcpy(buf, ip->cky_i, 8);
    memcpy(buf + 8, ip->cky_r, 8);
    memcpy(buf + 16, ip4, 4);
    buf[20] = (uint8_t)(port >> 8);
    buf[21] = (uint8_t)port;
    vpn_md5(buf, sizeof(buf), out);
}

/* ---------------- 收发 ---------------- */
static int ike_send(vpn_ipsec *ip, const uint8_t *buf, size_t len)
{
    if (ip->ike4500) {
        uint8_t out[VPN_IKE_MAX_PKT + 4];

        if (4 + len > sizeof(out))
            return VPN_ERR_NOMEM;
        memset(out, 0, 4); /* Non-ESP Marker */
        memcpy(out + 4, buf, len);
        return vpn_net_write_all(ip->esk, out, 4 + len, 2000) < 0 ? VPN_ERR_IO : VPN_OK;
    }
    return vpn_net_write_all(ip->isk, buf, len, 2000) < 0 ? VPN_ERR_IO : VPN_OK;
}

static bool ike_msg_ok(const uint8_t *p, size_t len, uint32_t mid)
{
    return len >= IKE_HDR_LEN && rd32(p + 20) == mid && p[16] != 0 &&
           rd32(p + 24) <= len;
}

/* 同时守 500 与 4500：NAT 检测通过后对端会把 IKE 浮动到 4500，
 * 浮动发生的时间点各实现不一（有的从第 4 包起就换端口），所以两个都收。 */
static int ike_recv_msg(vpn_ipsec *ip, uint8_t *resp, size_t cap, uint32_t mid,
                        int timeout_ms)
{
    int64_t deadline = vpn_now_ms() + timeout_ms;

    while (vpn_now_ms() < deadline) {
        int n = vpn_net_read(ip->isk, resp, cap, 200);

        if (n > 0 && ike_msg_ok(resp, (size_t)n, mid))
            return n;
        if (n < 0 && n != VPN_ERR_TIMEOUT && n != VPN_ERR_CLOSED)
            return n;

        if (ip->esk != VPN_INVALID_SOCK) {
            uint8_t tmp[VPN_IKE_MAX_PKT];

            n = vpn_net_read(ip->esk, tmp, sizeof(tmp), 5); /* 0 是阻塞读，不能传 */
            if (n > 4 && tmp[0] == 0 && tmp[1] == 0 && tmp[2] == 0 && tmp[3] == 0 &&
                ike_msg_ok(tmp + 4, (size_t)n - 4, mid)) {
                if ((size_t)n - 4 > cap)
                    return VPN_ERR_NOMEM;
                memcpy(resp, tmp + 4, (size_t)n - 4);
                ip->ike4500 = true;
                VPN_DEBUG("IKE: peer floated to UDP/4500");
                return n - 4;
            }
        }
    }
    return VPN_ERR_TIMEOUT;
}

/* 从对端返回的 SA 载荷里取加密密钥长度（位）。
 * ISAKMP SA 用 attr 14(Field Size) 或 13(Key Length) 通告 AES 位数，
 * 不能假定一定是我们想要的 256 —— RouterOS/strongSwan 常直接降到 128。 */
static void sa_scan(const payload_ref *psa, int *keybits, int *group)
{
    const uint8_t *b = psa->body;
    size_t len = psa->len, off = 8; /* DOI + Situation */

    *keybits = 0;
    if (group)
        *group = 0;
    while (off + 8 <= len) {
        size_t plen = rd16(b + off + 2);
        size_t t;

        if (plen < 8 || off + plen > len)
            break;
        t = off + 8 + b[off + 6]; /* 跳过 Proposal 头与 SPI */
        while (t + 8 <= off + plen) {
            size_t tlen = rd16(b + t + 2);
            size_t a;

            if (tlen < 8 || t + tlen > off + plen)
                break;
            a = t + 8;
            while (a + 4 <= t + tlen) {
                uint16_t at = rd16(b + a);

                if (!(at & 0x8000)) {
                    uint16_t al = rd16(b + a + 2);

                    if (al < 4)
                        break;
                    a += al;
                    continue;
                }
                at = (uint16_t)(at & 0x7fff);
                if ((at == 13 || at == 14) && !*keybits)
                    *keybits = rd16(b + a + 2);
                if (group && at == 4 && !*group)
                    *group = rd16(b + a + 2);
                a += 4;
            }
            t += tlen;
        }
        off += plen;
    }
}

/* ---------------- 主模式 ---------------- */
static int mm_run(vpn_ipsec *ip, char *err, size_t errlen)
{
    uint8_t buf[VPN_IKE_MAX_PKT], resp[VPN_IKE_MAX_PKT];
    uint8_t id_body[8], hash[20], hash_r[20];
    pbuild w;
    payload_ref pl[16];
    const payload_ref *ke, *nonce, *pid, *phash;
    int rlen, n, rc, tmo;

    tmo = ip->p.timeout_ms > 0 ? ip->p.timeout_ms : 8000;

    vpn_rand_bytes(ip->cky_i, 8);
    memset(ip->cky_r, 0, 8);

    /* 1. SA + VID(NAT-T)：没有 VID 对端不会用 UDP 封装发 ESP，
     *    我们用户态又收不到 IP 协议 50，隧道必然起不来。 */
    ip->sa_i_len = build_sa_body(ip->sa_i_body, 1, 0, 1);
    pb_init(&w, buf, sizeof(buf));
    pb_add(&w, PL_SA, ip->sa_i_body, ip->sa_i_len);
    pb_add(&w, PL_VID, NATT_VID, sizeof(NATT_VID));
    ike_hdr(buf, ip->cky_i, ip->cky_r, EX_MAIN, 0, 0, w.off);
    if (ike_send(ip, buf, w.off) != VPN_OK)
        return VPN_ERR_IO;

    /* 2. SA（对端提议）：只含 SA 与若干 VID，不含 KE/NONCE */
    rlen = ike_recv_msg(ip, resp, sizeof(resp), 0, tmo);
    if (rlen < 0) {
        snprintf(err, errlen, "no IKE response: IPsec is disabled on the server or UDP/500 is blocked");
        return rlen;
    }
    memcpy(ip->cky_r, resp + 8, 8);
    n = ike_parse(resp, (size_t)rlen, pl, 16);
    {
        const payload_ref *psa = pl_find(pl, n, PL_SA);
        int kbits = 0, grp = 0;

        if (!psa) {
            snprintf(err, errlen, "peer rejected the proposal (AES-CBC/SHA1/MODP1024/PSK)");
            return VPN_ERR_PROTO;
        }
        sa_scan(psa, &kbits, &grp);
        if (kbits == 128 || kbits == 192 || kbits == 256)
            ip->ike_enc_len = kbits / 8;
        if (grp && grp != GROUP_MODP1024) {
            snprintf(err, errlen, "peer selected a DH group other than MODP1024 (%d)", grp);
            return VPN_ERR_UNSUPPORTED;
        }
        VPN_DEBUG("IKE: peer selected AES-%d / SHA1 / MODP1024", ip->ike_enc_len * 8);
    }

    /* 3. KE + NONCE + NAT-D ×2 + VID */
    ip->nonce_i_len = 20;
    vpn_rand_bytes(ip->nonce_i, ip->nonce_i_len);
    {
        static const uint8_t decoy_ip[4] = {192, 0, 2, 1}; /* TEST-NET-1 */
        uint8_t natd_src[16], natd_dst[16];

        if (ip->p.force_natt)
            natd_hash(ip, decoy_ip, 4500, natd_src); /* 让对端判定存在 NAT */
        else
            natd_hash(ip, ip->local_ip, 0, natd_src);
        natd_hash(ip, ip->peer_ip, 4500, natd_dst);

        pb_init(&w, buf, sizeof(buf));
        pb_add(&w, PL_KE, ip->ke_i, sizeof(ip->ke_i));
        pb_add(&w, PL_NONCE, ip->nonce_i, ip->nonce_i_len);
        pb_add(&w, PL_NATD, natd_src, sizeof(natd_src));
        pb_add(&w, PL_NATD, natd_dst, sizeof(natd_dst));
        pb_add(&w, PL_VID, NATT_VID, sizeof(NATT_VID));
        ip->natt = ip->p.force_natt;
    }
    ike_hdr(buf, ip->cky_i, ip->cky_r, EX_MAIN, 0, 0, w.off);
    if (ike_send(ip, buf, w.off) != VPN_OK)
        return VPN_ERR_IO;

    /* 4. KE + Nr（明文）。标准主模式第 4 包【不含】ID/HASH：
     *    RFC 2409 §5.1 是 6 条报文，ID/HASH 在加密的第 5、6 包。 */
    rlen = ike_recv_msg(ip, resp, sizeof(resp), 0, tmo);
    if (rlen < 0) {
        snprintf(err, errlen, "IKE main mode: timed out waiting for packet 4");
        return rlen;
    }
    n = ike_parse(resp, (size_t)rlen, pl, 16);
    ke = pl_find(pl, n, PL_KE);
    nonce = pl_find(pl, n, PL_NONCE);
    if (!ke || !nonce || ke->len != 128) {
        snprintf(err, errlen, "IKE packet 4 lacks KE/NONCE (DH group mismatch)");
        return VPN_ERR_PROTO;
    }
    memcpy(ip->ke_r, ke->body, 128);
    if (nonce->len < 8 || nonce->len > sizeof(ip->nonce_r)) {
        snprintf(err, errlen, "IKE packet 4 has a bad nonce length (%u)", (unsigned)nonce->len);
        return VPN_ERR_PROTO;
    }
    memcpy(ip->nonce_r, nonce->body, nonce->len);
    ip->nonce_r_len = nonce->len;
    rc = dh_shared(ip, ip->ke_r, 128, err, errlen);
    if (rc != VPN_OK)
        return rc;
    derive_skeyid(ip);

    /* 5. IDii + HASH_I（加密，IV = hash(KE_i|KE_r)） */
    build_id_body(id_body, ip->local_ip, 17, 1701);
    hash_id(ip, true, id_body, sizeof(id_body), hash);
    pb_init(&w, buf, sizeof(buf));
    pb_add(&w, PL_ID, id_body, sizeof(id_body));
    pb_add(&w, PL_HASH, hash, 20);
    ike_hdr(buf, ip->cky_i, ip->cky_r, EX_MAIN, 1, 0, w.off);
    memcpy(ip->iv, ip->phase1_iv, IKE_IV_LEN);
    n = ike_encrypt(ip, buf, w.off, sizeof(buf));
    if (n < 0)
        return n;
    rc = ike_send(ip, buf, (size_t)n);
    if (rc != VPN_OK)
        return rc;

    /* 6. IDir + HASH_R（加密，IV 继承第 5 包最后密文块） */
    rlen = ike_recv_msg(ip, resp, sizeof(resp), 0, tmo);
    if (rlen < 0) {
        snprintf(err, errlen, "IKE main mode: timed out waiting for packet 6 (dropped by the peer, PSK mismatch?)");
        return rlen;
    }
    ike_trace("mm6_raw", resp, (size_t)rlen);
    rlen = ike_decrypt(ip, resp, (size_t)rlen);
    if (rlen < 0) {
        snprintf(err, errlen, "IKE packet 6 decryption failed (rc=%d)", rlen);
        return VPN_ERR_AUTH;
    }
    ike_trace("mm6_plain", resp, (size_t)rlen);
    n = ike_parse(resp, (size_t)rlen, pl, 16);
    pid = pl_find(pl, n, PL_ID);
    phash = pl_find(pl, n, PL_HASH);
    if (!pid || !phash || phash->len != 20) {
        snprintf(err, errlen, "IKE packet 6 lacks ID/HASH");
        return VPN_ERR_PROTO;
    }
    if (pid->len < 8 || pid->len > sizeof(ip->id_r)) {
        snprintf(err, errlen, "IKE peer ID has a bad length (%u)", (unsigned)pid->len);
        return VPN_ERR_PROTO;
    }
    /* 逐字节保留对端 ID 原文：端口/协议字段各实现不同，重建会算出错哈希 */
    memcpy(ip->id_r, pid->body, pid->len);
    ip->id_r_len = pid->len;
    if (pid->body[0] == 1 && pid->len >= 8)
        memcpy(ip->peer_ip, pid->body + 4, 4);

    hash_id(ip, false, ip->id_r, ip->id_r_len, hash_r);
    if (memcmp(hash_r, phash->body, 20) != 0) {
        snprintf(err, errlen, "HASH_R verification failed (PSK mismatch)");
        return VPN_ERR_AUTH;
    }

    /* RFC 3947：阶段 1 认证完成后才浮动端口，Quick Mode 起走 UDP/4500 */
    if (ip->natt) {
        ip->ike4500 = true;
        VPN_INFO("IPsec: phase 1 done (HASH_R verified), IKE floated to UDP/4500");
    } else {
        VPN_INFO("IPsec: phase 1 done (HASH_R verified)");
    }
    return VPN_OK;
}

/* ---------------- Quick Mode ---------------- */
/* 单个方向的 ESP 密钥：KEYMAT = prf+(SKEYID_d, ESP | SPI | Ni | Nr)
 * 关键点：SPI 用"该 SA 接收方选择的那个"，因此
 *   入方向 SA（接收方=我们）  -> spi_in
 *   出方向 SA（接收方=对端）  -> spi_out
 * 密钥切分顺序固定为 加密密钥 然后 认证密钥。 */
static void esp_keys_for(vpn_ipsec *ip, uint32_t spi, int enc_len,
                         uint8_t enc[IKE_KEY_LEN], uint8_t auth[20])
{
    uint8_t seed[64];
    uint8_t keymat[ESP_KEY_LEN];
    size_t off = 0;

    if (enc_len > IKE_KEY_LEN)
        enc_len = IKE_KEY_LEN;
    seed[off++] = 3; /* ESP */
    wr32(seed + off, spi);
    off += 4;
    memcpy(seed + off, ip->qm_nonce_i, ip->qm_nonce_i_len); off += ip->qm_nonce_i_len;
    memcpy(seed + off, ip->qm_nonce_r, ip->qm_nonce_r_len); off += ip->qm_nonce_r_len;

    prf_expand(ip->skeyid_d, 20, seed, off, keymat, sizeof(keymat));
    memcpy(enc, keymat, (size_t)enc_len);
    memcpy(auth, keymat + enc_len, 20);
}

static void derive_esp_keys(vpn_ipsec *ip)
{
    esp_keys_for(ip, ip->spi_in, ip->esp_dec_len, ip->esp_dec_key, ip->esp_dec_auth);
    esp_keys_for(ip, ip->spi_out, ip->esp_enc_len, ip->esp_enc_key, ip->esp_auth_key);
    ip->dec_use_spi_out = false;
}

/* HASH(1)/(2)：M-ID + 若干完整 payload 块（含通用头） */
static void qm_hash12(vpn_ipsec *ip, uint8_t out[20], const uint8_t *buf,
                      const size_t *offs, const size_t *lens, int cnt)
{
    uint8_t tmp[1600];
    size_t off = 0;
    int i;

    wr32(tmp, ip->qm_mid);
    off = 4;
    for (i = 0; i < cnt; i++) {
        if (off + lens[i] > sizeof(tmp))
            break;
        memcpy(tmp + off, buf + offs[i], lens[i]);
        off += lens[i];
    }
    vpn_hmac_sha1(ip->skeyid_a, 20, tmp, off, out);
}

static int qm_run(vpn_ipsec *ip, char *err, size_t errlen)
{
    uint8_t buf[VPN_IKE_MAX_PKT], resp[VPN_IKE_MAX_PKT];
    uint8_t sa_body[256], id_local[8], id_peer[8], hash[20], h3seed[168];
    uint8_t placeholder[20];
    pbuild w;
    payload_ref pl[16];
    const payload_ref *psa, *pnonce, *phash;
    size_t o_sa, o_nonce, o_idci, o_idcr, sa_len, offs[5], lens[5];
    int rlen, n, rc, tmo, total;

    tmo = ip->p.timeout_ms > 0 ? ip->p.timeout_ms : 8000;
    ip->qm_mid = (uint32_t)vpn_now_ms();
    ip->qm_nonce_i_len = 20;
    vpn_rand_bytes(ip->qm_nonce_i, ip->qm_nonce_i_len);
    ip->spi_in = (uint32_t)((vpn_now_ms() * 2654435761u) | 1u);

    /* ---- QM 1 ---- */
    sa_len = build_sa_body(sa_body, 3, ip->spi_in, ESP_TRANS_AES);
    build_id_body(id_local, ip->local_ip, 17, 1701);
    build_id_body(id_peer, ip->peer_ip, 17, 1701);
    memset(placeholder, 0, sizeof(placeholder));

    pb_init(&w, buf, sizeof(buf));
    pb_add(&w, PL_HASH, placeholder, 20);
    o_sa = w.off;    pb_add(&w, PL_SA, sa_body, sa_len);
    o_nonce = w.off; pb_add(&w, PL_NONCE, ip->qm_nonce_i, ip->qm_nonce_i_len);
    o_idci = w.off;  pb_add(&w, PL_ID, id_local, sizeof(id_local));
    o_idcr = w.off;  pb_add(&w, PL_ID, id_peer, sizeof(id_peer));

    offs[0] = o_sa;    lens[0] = 4 + sa_len;
    offs[1] = o_nonce; lens[1] = 4 + 20;
    offs[2] = o_idci;  lens[2] = 4 + sizeof(id_local);
    offs[3] = o_idcr;  lens[3] = 4 + sizeof(id_peer);
    qm_hash12(ip, hash, buf, offs, lens, 4);
    memcpy(buf + IKE_HDR_LEN + 4, hash, 20); /* HASH 是第一个 payload 的 body */

    ike_hdr(buf, ip->cky_i, ip->cky_r, EX_QM, 1, ip->qm_mid, w.off);
    ike_trace("qm1", buf, (size_t)w.off);
    {
        /* 阶段 2 首包 IV = hash(阶段 1 最后密文块 | MID 大端) */
        uint8_t hz[IKE_IV_LEN + 4], dg[20];

        memcpy(hz, ip->iv, IKE_IV_LEN);
        wr32(hz + IKE_IV_LEN, ip->qm_mid);
        vpn_sha1(hz, sizeof(hz), dg);
        memcpy(ip->iv, dg, IKE_IV_LEN);
    }
    n = ike_encrypt(ip, buf, w.off, sizeof(buf));
    if (n < 0)
        return n;
    wr32(buf + 24, (uint32_t)n);
    if (ike_send(ip, buf, (size_t)n) != VPN_OK)
        return VPN_ERR_IO;

    /* ---- QM 2 ---- */
    rlen = ike_recv_msg(ip, resp, sizeof(resp), ip->qm_mid, tmo);
    if (rlen < 0) {
        snprintf(err, errlen, "Quick Mode response timed out (peer rejected the ESP proposal)");
        return rlen;
    }
    rlen = ike_decrypt(ip, resp, (size_t)rlen);
    if (rlen < 0)
        return VPN_ERR_PROTO;
    ike_trace("qm2_plain", resp, (size_t)rlen);
    n = ike_parse(resp, (size_t)rlen, pl, 16);
    psa = pl_find(pl, n, PL_SA);
    pnonce = pl_find(pl, n, PL_NONCE);
    phash = pl_find(pl, n, PL_HASH);
    if (!psa || !pnonce || !phash || psa->len < 20 || pnonce->len < 20) {
        snprintf(err, errlen, "malformed Quick Mode response");
        return VPN_ERR_PROTO;
    }
    ip->spi_out = rd32(psa->body + 16);

    /* ESP 加密密钥字节数由 SA 里选中的 AES 位数决定（attr 13/14），
     * 之前这两个字段从未赋值（恒为 0），导致 enc 密钥为空、auth 取到
     * keymat 偏移 0 的位置，ESP 报文被对端内核判为 ICV 失败
     * （XfrmInStateProtoError++）。 */
    {
        int kb = 0, grp = 0;

        sa_scan(psa, &kb, &grp);
        if (kb >= 128 && kb <= 256 && (kb % 64) == 0)
            ip->esp_enc_len = ip->esp_dec_len = kb / 8;
        else
            ip->esp_enc_len = ip->esp_dec_len = 32;  /* 默认 AES-256 */
        VPN_DEBUG("ESP: encryption key length %d bytes (negotiated %d bits)", ip->esp_enc_len, kb);
    }

    if (pnonce->len < 8 || pnonce->len > sizeof(ip->qm_nonce_r))
        return VPN_ERR_PROTO;
    memcpy(ip->qm_nonce_r, pnonce->body, pnonce->len);
    ip->qm_nonce_r_len = pnonce->len;

    /* HASH(2) = prf(SKEYID_a, M-ID | Ni_b | 去掉 HASH 后的完整报文)
     * 关键点（已用 strongSwan 侧 DBG3 打印的 Hash(2) 逐字节对拍确认）：
     *   Ni_b 是【裸 nonce 字节】，不能带 NONCE 载荷的 4 字节通用头；
     *   报文部分只取载荷本身（含各自通用头），不含解密补齐的尾部 padding。 */
    {
        uint8_t h2[20];
        uint8_t tmp[1600];
        size_t o = 0, i;

        wr32(tmp, ip->qm_mid);
        o = 4;
        memcpy(tmp + o, ip->qm_nonce_i, ip->qm_nonce_i_len);
        o += ip->qm_nonce_i_len;
        for (i = 0; i < (size_t)n && o + 4 + pl[i].len < sizeof(tmp); i++) {
            if (pl[i].type == PL_HASH)
                continue;
            memcpy(tmp + o, pl[i].body - 4, 4 + pl[i].len);
            o += 4 + pl[i].len;
        }
        vpn_hmac_sha1(ip->skeyid_a, 20, tmp, o, h2);
        ike_trace("qm2_in", tmp, o);
        if (memcmp(h2, phash->body, 20) != 0) {
            snprintf(err, errlen, "Quick Mode HASH verification failed");
            return VPN_ERR_AUTH;
        }
    }

    derive_esp_keys(ip);

    /* ---- QM 3 ----
     * HASH(3) = prf(SKEYID_a, 0 单字节 | M-ID | Ni_b | Nr_b)
     * 长度必须按实际 nonce 长度算（对端 nonce 可为 32 字节），不能写死 45。 */
    {
        size_t hl = 0;

        h3seed[hl++] = 0;
        wr32(h3seed + hl, ip->qm_mid);
        hl += 4;
        memcpy(h3seed + hl, ip->qm_nonce_i, ip->qm_nonce_i_len);
        hl += ip->qm_nonce_i_len;
        memcpy(h3seed + hl, ip->qm_nonce_r, ip->qm_nonce_r_len);
        hl += ip->qm_nonce_r_len;
        vpn_hmac_sha1(ip->skeyid_a, 20, h3seed, hl, hash);
    }

    pb_init(&w, buf, sizeof(buf));
    pb_add(&w, PL_HASH, hash, 20);
    ike_hdr(buf, ip->cky_i, ip->cky_r, EX_QM, 1, ip->qm_mid, w.off);
    n = ike_encrypt(ip, buf, w.off, sizeof(buf));
    if (n < 0)
        return n;
    wr32(buf + 24, (uint32_t)n);
    if (ike_send(ip, buf, (size_t)n) != VPN_OK)
        return VPN_ERR_IO;

    ip->up = true;
    (void)rc;
    (void)total;

    ike_trace("esp_enc_key", ip->esp_enc_key, (size_t)ip->esp_enc_len);
    ike_trace("esp_auth_key", ip->esp_auth_key, 20);
    ike_trace("esp_dec_key", ip->esp_dec_key, (size_t)ip->esp_dec_len);
    ike_trace("esp_dec_auth", ip->esp_dec_auth, 20);

    /* 选择 ESP 通道：优先 IP 协议 50（对端内核只有检测到 NAT 才会启用
     * UDP 封装，同网段/无 NAT 时 4500 上的 ESP 会被当 IKE 报文丢掉）。 */
    ip->esp_raw = false;
    if (ip->rsk < 0) {
        const char *mode = getenv("VPN_IPSEC_ENCAP");

        if (!mode || !*mode || (strcmp(mode, "raw") != 0 && strcmp(mode, "udp") != 0)) {
            if (vpn_net_raw_esp_connect(ip->p.host, &ip->rsk) == VPN_OK)
                ip->esp_raw = true;
        } else if (strcmp(mode, "raw") == 0) {
            if (vpn_net_raw_esp_connect(ip->p.host, &ip->rsk) != VPN_OK) {
                snprintf(err, errlen, "cannot create a raw ESP socket (needs root)");
                return VPN_ERR_IO;
            }
            ip->esp_raw = true;
        }
    } else {
        ip->esp_raw = true;
    }
    VPN_INFO("IPsec: ESP transport SA established (in=0x%08x out=0x%08x, AES-256/HMAC-SHA1, %s)",
             ip->spi_in, ip->spi_out, ip->esp_raw ? "IP protocol 50" : "UDP/4500 encapsulation");
    return VPN_OK;
}

/* ---------------- ESP ---------------- */
static int esp_send(vpn_ipsec *ip, const uint8_t *data, size_t len)
{
    uint8_t pkt[VPN_IKE_MAX_PKT];
    uint8_t plain[VPN_IKE_MAX_PKT];
    uint8_t iv[IKE_IV_LEN];
    size_t pad, plen, clen, esplen;
    size_t ulen;   /* 内层 UDP 长度（transport 模式） */

    if (!ip->up || len > 1400)
        return VPN_ERR_INVALID;

    /* transport 模式加密的是整个 IP 载荷 = UDP 头 + L2TP 报文。
     * 对端 policy 是 udp/1701，没有 UDP 头连 SA 都匹配不上（内核会直接丢）。 */
    ulen = 8 + len;
    wr16(plain, 1701);          /* 源端口 */
    wr16(plain + 2, 1701);      /* 目的端口 */
    wr16(plain + 4, (uint16_t)ulen);
    wr16(plain + 6, 0);         /* 校验和 0 = 未计算（IPv4 允许） */
    memcpy(plain + 8, data, len);

    pad = (IKE_BLOCK - ((ulen + 2) % IKE_BLOCK)) % IKE_BLOCK;
    plen = ulen + pad + 2;
    {
        size_t i;
        for (i = 0; i < pad; i++)
            plain[ulen + i] = (uint8_t)(i + 1);
    }
    plain[ulen + pad] = (uint8_t)pad;
    plain[ulen + pad + 1] = 17; /* next header: UDP */

    vpn_rand_bytes(iv, sizeof(iv));
    clen = plen;
    if (aes_cbc(ip->esp_enc_key, ip->esp_enc_len, 1, plain, clen, iv) != VPN_OK)
        return VPN_ERR_PROTO;

    wr32(pkt, ip->spi_out);
    wr32(pkt + 4, ++ip->seq_out);
    memcpy(pkt + 8, iv, IKE_IV_LEN);
    memcpy(pkt + 8 + IKE_IV_LEN, plain, clen);
    esplen = 8 + IKE_IV_LEN + clen;
    vpn_hmac_sha1(ip->esp_auth_key, 20, pkt, esplen, pkt + esplen);
    esplen += 12; /* HMAC-SHA1-96 */

    if (ip->esp_raw) {
        /* IP 协议 50：内核补 IP 头，不需要 4 字节 non-ESP marker */
        if (vpn_net_write_all(ip->rsk, pkt, esplen, 2000) < 0) {
            VPN_WARN("ESP: raw socket send failed (errno=%d)", vpn_net_error());
            return VPN_ERR_IO;
        }
        VPN_DEBUG("ESP -> protocol 50 spi=0x%08x seq=%u len=%zu",
                  ip->spi_out, ip->seq_out, esplen);
        return (int)len;
    }

    /* NAT-T：UDP/4500 + 4 字节 0 */
    {
        uint8_t out[VPN_IKE_MAX_PKT];
        if (4 + esplen > sizeof(out))
            return VPN_ERR_NOMEM;
        memset(out, 0, 4);
        memcpy(out + 4, pkt, esplen);
        if (vpn_net_write_all(ip->esk, out, 4 + esplen, 2000) < 0)
            return VPN_ERR_IO;
    }
    return (int)len;
}

static int esp_recv(vpn_ipsec *ip, uint8_t *buf, size_t cap, int timeout_ms)
{
    uint8_t pkt[VPN_IKE_MAX_PKT];
    uint8_t mac[20];
    uint32_t spi;
    uint8_t iv[IKE_IV_LEN];
    size_t clen, esplen;
    size_t off = 0;   /* ESP 头在缓冲区中的偏移 */
    int n;

    n = vpn_net_read(ip->esp_raw ? ip->rsk : ip->esk, pkt, sizeof(pkt), timeout_ms);
    if (n == VPN_ERR_TIMEOUT)
        return 0;
    if (n < 0)
        return n;

    if (ip->esp_raw) {
        /* 原始 socket 收到的数据带 IPv4 头（含选项），按 IHL 跳过 */
        size_t ihl;
        if (n < 20 || (pkt[0] >> 4) != 4)
            return 0;
        ihl = (size_t)(pkt[0] & 0x0f) * 4;
        if (ihl < 20 || (size_t)n < ihl + 8)
            return 0;
        if (pkt[9] != 50) {   /* 只接受 ESP */
            return 0;
        }
        off = ihl;
    } else {
        if ((size_t)n < 4 + 8 + IKE_IV_LEN + 12 + 2)
            return 0;
        if (pkt[0] || pkt[1] || pkt[2] || pkt[3])
            return 0; /* 不是 ESP（可能是 NAT-T keepalive） */
        off = 4;
    }

    esplen = (size_t)n - off;
    if (esplen < 8 + IKE_IV_LEN + 12 + 2)
        return 0;
    spi = rd32(pkt + off);
    if (spi != ip->spi_in)
        return 0;

    vpn_hmac_sha1(ip->esp_dec_auth, 20, pkt + off, esplen - 12, mac);
    if (memcmp(mac, pkt + off + esplen - 12, 12) != 0) {
        uint8_t alt_key[IKE_KEY_LEN], alt_auth[20], altmac[20];

        /* 兼容性试探：个别实现对两个方向只派生一份 KEYMAT */
        esp_keys_for(ip, ip->spi_out, ip->esp_dec_len, alt_key, alt_auth);
        vpn_hmac_sha1(alt_auth, 20, pkt + off, esplen - 12, altmac);
        if (memcmp(altmac, pkt + off + esplen - 12, 12) != 0) {
            VPN_WARN("ESP: HMAC verification failed, packet dropped");
            return 0;
        }
        if (!ip->dec_use_spi_out)
            VPN_WARN("ESP: peer derives the inbound key from spi_out (non-standard convention)");
        ip->dec_use_spi_out = true;
        memcpy(ip->esp_dec_key, alt_key, sizeof(alt_key));
        memcpy(ip->esp_dec_auth, alt_auth, sizeof(alt_auth));
    }

    memcpy(iv, pkt + off + 8, IKE_IV_LEN);
    clen = esplen - 8 - IKE_IV_LEN - 12;
    if (clen == 0 || clen % IKE_BLOCK)
        return 0;
    memcpy(pkt + off + 8, pkt + off + 8 + IKE_IV_LEN, clen);
    if (aes_cbc(ip->esp_dec_key, ip->esp_dec_len, 0, pkt + off + 8, clen, iv) != VPN_OK)
        return 0;

    {
        uint8_t *p = pkt + off + 8;
        size_t padlen, dlen;

        if (clen < 2)
            return 0;
        padlen = p[clen - 2];
        if (padlen + 2 > clen)
            return 0;
        dlen = clen - 2 - padlen;
        /* transport 模式：去掉内层 UDP 头，只把 L2TP 报文交给上层。
         * 若对端没做 transport 封装（罕见），按裸报文透传。 */
        if (dlen >= 8 && rd16(p) == 1701 && rd16(p + 2) == 1701) {
            p += 8;
            dlen -= 8;
        }
        if (dlen > cap)
            return VPN_ERR_NOMEM;
        memcpy(buf, p, dlen);
        return (int)dlen;
    }
}

/* ---------------- 对外 API ---------------- */
vpn_ipsec *vpn_ipsec_new(const vpn_ike_params *p, char *err, size_t errlen)
{
    vpn_ipsec *ip;
    uint16_t port;

    if (!p || p->host[0] == 0 || p->psk[0] == 0) {
        if (err)
            snprintf(err, errlen, "incomplete IPsec parameters (server address and PSK are required)");
        return NULL;
    }
    ip = (vpn_ipsec *)calloc(1, sizeof(*ip));
    if (!ip) {
        if (err)
            snprintf(err, errlen, "out of memory");
        return NULL;
    }
    ip->p = *p;
    ip->isk = -1;
    ip->esk = -1;
    ip->rsk = -1;

    port = p->port ? p->port : 500;
    if (vpn_net_udp_connect(p->host, port, &ip->isk) != VPN_OK) {
        if (err)
            snprintf(err, errlen, "cannot reach the IKE port %s:%u", p->host, port);
        free(ip);
        return NULL;
    }
    if (vpn_net_local_addr(ip->isk, ip->local_ip) != VPN_OK) {
        if (err)
            snprintf(err, errlen, "cannot determine the local egress address");
        vpn_net_close(&ip->isk);
        free(ip);
        return NULL;
    }
    if (vpn_net_peer_ipv4(ip->isk, ip->peer_ip) != VPN_OK) {
        if (err)
            snprintf(err, errlen, "cannot resolve the server address");
        vpn_net_close(&ip->isk);
        free(ip);
        return NULL;
    }
    if (p->local_id[0]) {
        /* 允许上层指定 ID：当前只支持 IPv4 形式 */
        unsigned a, b, c, d;
        if (sscanf(p->local_id, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
            ip->local_ip[0] = (uint8_t)a;
            ip->local_ip[1] = (uint8_t)b;
            ip->local_ip[2] = (uint8_t)c;
            ip->local_ip[3] = (uint8_t)d;
        }
    }
    return ip;
}

void vpn_ipsec_free(vpn_ipsec *ip)
{
    if (!ip)
        return;
    if (ip->isk >= 0)
        vpn_net_close(&ip->isk);
    if (ip->esk >= 0)
        vpn_net_close(&ip->esk);
    if (ip->rsk >= 0)
        vpn_net_close(&ip->rsk);
    BN_free(ip->dh_p);
    BN_free(ip->dh_priv);
    free(ip);
}

int vpn_ipsec_connect(vpn_ipsec *ip, char *err, size_t errlen)
{
    uint16_t natt;
    int rc;

    if (!ip)
        return VPN_ERR_INVALID;
    rc = dh_init(ip, err, errlen);
    if (rc != VPN_OK)
        return rc;

    natt = 4500;
    if (vpn_net_udp_connect(ip->p.host, natt, &ip->esk) != VPN_OK) {
        if (err)
            snprintf(err, errlen, "cannot reach the NAT-T port 4500");
        return VPN_ERR_IO;
    }

    ip->ike4500 = false;
    rc = mm_run(ip, err, errlen);
    if (rc != VPN_OK)
        return rc;

    rc = qm_run(ip, err, errlen);
    if (rc == VPN_ERR_TIMEOUT && ip->ike4500) {
        /* 对端没有按 RFC 3947 浮动端口：退回 500 再试一次 */
        VPN_WARN("IPsec: no Quick Mode response on UDP/4500, retrying on port 500");
        ip->ike4500 = false;
        rc = qm_run(ip, err, errlen);
    }
    return rc;
}

bool vpn_ipsec_up(const vpn_ipsec *ip) { return ip && ip->up; }

int vpn_ipsec_send(vpn_ipsec *ip, const uint8_t *data, size_t len)
{
    if (!ip)
        return VPN_ERR_INVALID;
    return esp_send(ip, data, len);
}

int vpn_ipsec_recv(vpn_ipsec *ip, uint8_t *buf, size_t cap, int timeout_ms)
{
    if (!ip)
        return VPN_ERR_INVALID;
    return esp_recv(ip, buf, cap, timeout_ms);
}

int vpn_ipsec_fd(const vpn_ipsec *ip)
{
    if (!ip)
        return -1;
    if (ip->esp_raw && ip->rsk >= 0)
        return ip->rsk;
    return ip->esk;
}

const char *vpn_ipsec_cipher(const vpn_ipsec *ip)
{
    return (ip && ip->up) ? "AES-256-CBC/HMAC-SHA1-96 (ESP transport)" : "not established";
}
