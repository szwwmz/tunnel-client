/* SPDX-License-Identifier: LicenseRef-Proprietary
   Copyright (c) 2026 wwm-spec. All rights reserved.
 */

/* test.h - 极简测试框架（无第三方依赖，GCC/Clang 下用 constructor 自动注册） */
#ifndef VPN_TEST_H
#define VPN_TEST_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern int g_test_checks;
extern int g_test_failures;

void test_register(const char *name, void (*fn)(void));

#if defined(__GNUC__) || defined(__clang__)
#define TEST(fn)                                                              \
    static void fn(void);                                                     \
    static void __attribute__((constructor)) test_reg_##fn(void)              \
    {                                                                         \
        test_register(#fn, fn);                                               \
    }                                                                         \
    static void fn(void)
#else
#error "测试框架依赖 constructor 属性，请在 GCC/Clang 下构建"
#endif

#define CHECK(cond)                                                           \
    do {                                                                      \
        g_test_checks++;                                                      \
        if (!(cond)) {                                                        \
            g_test_failures++;                                                \
            fprintf(stderr, "  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
        }                                                                     \
    } while (0)

#define CHECK_EQ_INT(a, b)                                                    \
    do {                                                                      \
        long long va_ = (long long)(a);                                       \
        long long vb_ = (long long)(b);                                       \
        g_test_checks++;                                                      \
        if (va_ != vb_) {                                                     \
            g_test_failures++;                                                \
            fprintf(stderr, "  FAIL %s:%d  %s(%lld) != %s(%lld)\n", __FILE__, \
                    __LINE__, #a, va_, #b, vb_);                              \
        }                                                                     \
    } while (0)

#define CHECK_BYTES(a, b, n)                                                  \
    do {                                                                      \
        g_test_checks++;                                                      \
        if (memcmp((a), (b), (n)) != 0) {                                     \
            g_test_failures++;                                                \
            fprintf(stderr, "  FAIL %s:%d  %s 前 %d 字节不一致\n", __FILE__,  \
                    __LINE__, #a, (int)(n));                                  \
        }                                                                     \
    } while (0)

/* 十六进制字面量 -> 字节数组（测试向量用） */
static inline void hex_to_bytes(const char *hex, uint8_t *out, size_t outlen)
{
    size_t i;
    for (i = 0; i < outlen; i++) {
        unsigned v = 0;
        sscanf(hex + i * 2, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

#endif /* VPN_TEST_H */
