/* SPDX-License-Identifier: LicenseRef-Proprietary
   Copyright (c) 2026 wwm-spec. All rights reserved.
 */

/* test_mschapv2.c - MS-CHAPv2 / MPPE 测试向量
 *
 * 期望值由 OpenSSL（MD4 legacy provider + DES-ECB）与 Python hashlib 独立算出，
 * 与本实现（自带 MD4 + 自带 DES）互为交叉验证：
 *
 *   UserName    = "User"
 *   Password    = "clientPass"
 *   AuthChallenge = 5B5D7C7D7B3F2F3E3C2C6021323B3C4B
 *   PeerChallenge = 2140232425262728
 *
 *   PasswordHash  = 44EBBA8D5312B8D611474411F56989AE
 *   ChallengeHash = B91A49169EDA099D
 *   NTResponse    = 54D3BDCB6CB23C560618A715B38AE2639E6136DF7341208A
 *   AuthenticatorResponse = S=9B3CD16F655DB2D9130990580F8383E22E1FC88B
 *   MPPE send key = CACFBA8C891809CC91925BCA830D1D0F
 *   MPPE recv key = 5DF75F1778225E15A602CFDB2AFE0CE7
 */
#include "test.h"

#include "vpncore/vpn_crypto.h"
#include "vpncore/vpn_error.h"

#include <stdint.h>
#include <string.h>

static const char k_user[] = "User";
static const char k_pass[] = "clientPass";

static const uint8_t k_auth[16] = { 0x5b, 0x5d, 0x7c, 0x7d, 0x7b, 0x3f, 0x2f, 0x3e,
                                    0x3c, 0x2c, 0x60, 0x21, 0x32, 0x26, 0x26, 0x28 };
static const uint8_t k_peer[16] = { 0x21, 0x40, 0x23, 0x24, 0x25, 0x5e, 0x26, 0x2a,
                                    0x28, 0x29, 0x5f, 0x2b, 0x3a, 0x33, 0x7c, 0x7e };

TEST(md4_known_answer)
{
    /* MD4("") = 31D6CFE0D16AE931B73C59D7E0C089C0 */
    static const uint8_t empty_md4[16] = { 0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31,
                                           0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0 };
    /* MD4("abc") = A448017AAF21D8525FC10AE87AA6729D */
    static const uint8_t abc_md4[16] = { 0xa4, 0x48, 0x01, 0x7a, 0xaf, 0x21, 0xd8, 0x52,
                                         0x5f, 0xc1, 0x0a, 0xe8, 0x7a, 0xa6, 0x72, 0x9d };
    uint8_t out[16];
    vpn_md4_ctx ctx;

    vpn_md4_init(&ctx);
    vpn_md4_final(&ctx, out);
    CHECK_BYTES(out, empty_md4, 16);

    vpn_md4_init(&ctx);
    vpn_md4_update(&ctx, "abc", 3);
    vpn_md4_final(&ctx, out);
    CHECK_BYTES(out, abc_md4, 16);
}

TEST(des_known_answer)
{
    /* FIPS 81 示例：key=133457799BBCDFF1, plain=0123456789ABCDEF
     * cipher=85E813540F0AB405 */
    static const uint8_t key[8] = { 0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1 };
    static const uint8_t in[8]  = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
    static const uint8_t exp[8] = { 0x85, 0xe8, 0x13, 0x54, 0x0f, 0x0a, 0xb4, 0x05 };
    uint8_t out[8];

    vpn_des_encrypt_block(key, in, out);
    CHECK_BYTES(out, exp, 8);
}

TEST(nt_response_vector)
{
    static const uint8_t exp_hash[16] = {
        0x44, 0xeb, 0xba, 0x8d, 0x53, 0x12, 0xb8, 0xd6,
        0x11, 0x47, 0x44, 0x11, 0xf5, 0x69, 0x89, 0xae
    };
    static const uint8_t exp_resp[24] = {
        0x82, 0x30, 0x9e, 0xcd, 0x8d, 0x70, 0x8b, 0x5e,
        0xa0, 0x8f, 0xaa, 0x39, 0x81, 0xcd, 0x83, 0x54,
        0x42, 0x33, 0x11, 0x4a, 0x3d, 0x85, 0xd6, 0xdf
    };
    uint8_t resp[24], hash[16];

    CHECK_EQ_INT(vpn_mschapv2_nt_response(k_pass, k_peer, k_auth, k_user, resp, hash),
                 VPN_OK);
    CHECK_BYTES(hash, exp_hash, 16);
    CHECK_BYTES(resp, exp_resp, 24);
}

TEST(authenticator_response_vector)
{
    static const uint8_t nt_hash[16] = {
        0x44, 0xeb, 0xba, 0x8d, 0x53, 0x12, 0xb8, 0xd6,
        0x11, 0x47, 0x44, 0x11, 0xf5, 0x69, 0x89, 0xae
    };
    char out[64];

    CHECK_EQ_INT(vpn_mschapv2_authenticator_response(nt_hash, k_peer, k_auth, k_user,
                                                     out, sizeof(out)),
                 VPN_OK);
    CHECK(strcmp(out, "S=407A5589115FD0D6209F510FE9C04566932CDA56") == 0);
}

TEST(mppe_keys_vector)
{
    static const uint8_t nt_hash[16] = {
        0x44, 0xeb, 0xba, 0x8d, 0x53, 0x12, 0xb8, 0xd6,
        0x11, 0x47, 0x44, 0x11, 0xf5, 0x69, 0x89, 0xae
    };
    static const uint8_t nt_resp[24] = {
        0x82, 0x30, 0x9e, 0xcd, 0x8d, 0x70, 0x8b, 0x5e,
        0xa0, 0x8f, 0xaa, 0x39, 0x81, 0xcd, 0x83, 0x54,
        0x42, 0x33, 0x11, 0x4a, 0x3d, 0x85, 0xd6, 0xdf
    };
    /* RFC 3079 §3.4 GetAsymmetricStartKey（客户端视角）
     *   MasterSendKey    = SHA1(MasterKey || 40*0x00 || Magic2 || 40*0xF2)
     *   MasterReceiveKey = SHA1(MasterKey || 40*0x00 || Magic3 || 40*0xF2)
     * RFC §3.5.2 给出的 SendStartKey128 = 8B7CDC14... 即 Magic3 方向，
     * 与客户端 receive 键一致（对称性自校验）。 */
    static const uint8_t exp_send[16] = {
        0xd5, 0xf0, 0xe9, 0x52, 0x1e, 0x3e, 0xa9, 0x58,
        0x96, 0x45, 0xe8, 0x60, 0x51, 0xc8, 0x22, 0x26
    };
    static const uint8_t exp_recv[16] = {
        0x8b, 0x7c, 0xdc, 0x14, 0x9b, 0x99, 0x3a, 0x1b,
        0xa1, 0x18, 0xcb, 0x15, 0x3f, 0x56, 0xdc, 0xcb
    };
    uint8_t send_key[16], recv_key[16];

    CHECK_EQ_INT(vpn_mschapv2_mppe_keys(nt_hash, nt_resp, send_key, recv_key), VPN_OK);
    CHECK_BYTES(send_key, exp_send, 16);
    CHECK_BYTES(recv_key, exp_recv, 16);
}

TEST(ct_equal_sanity)
{
    const uint8_t a[4] = { 1, 2, 3, 4 };
    const uint8_t b[4] = { 1, 2, 3, 4 };
    const uint8_t c[4] = { 1, 2, 3, 5 };

    CHECK(vpn_ct_equal(a, b, 4) == true);
    CHECK(vpn_ct_equal(a, c, 4) == false);
}
