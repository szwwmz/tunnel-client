/* vpn_crypto.h - 认证/加密原语
 *
 * 仅收录 PPP 认证链必需且 OpenSSL 3.0 默认 provider 不提供的算法：
 *   - MD4      : MS-CHAPv2 NT-Response 需要（OpenSSL 3 已移入 legacy）
 *   - DES-ECB  : MS-CHAPv2 ChallengeResponse 需要（同上）
 * SHA1/HMAC/MD5/随机数 走 OpenSSL EVP，避免重复造轮子。
 */
#ifndef VPN_CRYPTO_H
#define VPN_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- MD4 (RFC 1320) ---------- */
typedef struct {
    uint32_t state[4];
    uint64_t count; /* bytes */
    uint8_t  buf[64];
} vpn_md4_ctx;

void vpn_md4_init(vpn_md4_ctx *c);
void vpn_md4_update(vpn_md4_ctx *c, const void *data, size_t len);
void vpn_md4_final(vpn_md4_ctx *c, uint8_t out[16]);

/* ---------- DES (ECB, 单块) ---------- */
void vpn_des_encrypt_block(const uint8_t key[8], const uint8_t in[8], uint8_t out[8]);

/* ---------- MS-CHAPv2 (RFC 2759) ---------- */
/* NT-Response: 24 字节；若 nt_hash_out 非空返回 NT 密码哈希(16B) */
int vpn_mschapv2_nt_response(const char *password,
                             const uint8_t peer_challenge[16],
                             const uint8_t auth_challenge[16],
                             const char *username,
                             uint8_t response_out[24],
                             uint8_t nt_hash_out[16]);

/* 计算 AuthenticatorResponse 期望值（"S=<HEX>"），与服务器返回比对 */
int vpn_mschapv2_authenticator_response(const uint8_t nt_hash[16],
                                        const uint8_t peer_challenge[16],
                                        const uint8_t auth_challenge[16],
                                        const char *username,
                                        char *out, size_t outlen);

/* RFC 3079 MPPE 密钥派生：MSK = send_key || recv_key（SSTP Crypto-Binding 用） */
int vpn_mschapv2_mppe_keys(const uint8_t nt_hash[16],
                           const uint8_t nt_response[24],
                           uint8_t send_key[16],
                           uint8_t recv_key[16]);

/* ---------- 通用哈希/HMAC（OpenSSL EVP 封装） ---------- */
int vpn_sha1(const void *data, size_t len, uint8_t out[20]);
int vpn_md5(const void *data, size_t len, uint8_t out[16]);
int vpn_hmac_sha1(const void *key, size_t keylen, const void *data, size_t len, uint8_t out[20]);
uint32_t vpn_rand_u32(void);
void vpn_rand_bytes(void *out, size_t len);
const char *vpn_crypto_version(void);

/* 常量时间比较（校验 MAC 用） */
bool vpn_ct_equal(const void *a, const void *b, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* VPN_CRYPTO_H */
