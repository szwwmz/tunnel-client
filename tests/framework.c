/* SPDX-License-Identifier: LicenseRef-Proprietary
   Copyright (c) 2026 wwm-spec. All rights reserved.
 */

/* framework.c - 测试注册表与 main */
#include "test.h"

#include <stdlib.h>

#define MAX_TESTS 64

int g_test_checks;
int g_test_failures;

static struct {
    const char *name;
    void (*fn)(void);
} g_tests[MAX_TESTS];
static int g_count;

void test_register(const char *name, void (*fn)(void))
{
    if (g_count >= MAX_TESTS) {
        fprintf(stderr, "测试数量超过上限 %d\n", MAX_TESTS);
        abort();
    }
    g_tests[g_count].name = name;
    g_tests[g_count].fn = fn;
    g_count++;
}

int main(void)
{
    int i;

    for (i = 0; i < g_count; i++) {
        int before = g_test_failures;
        printf("[ RUN  ] %s\n", g_tests[i].name);
        g_tests[i].fn();
        printf("[ %s ] %s\n", g_test_failures == before ? " OK " : "FAIL", g_tests[i].name);
    }

    printf("\n%d 个断言，%d 个失败\n", g_test_checks, g_test_failures);
    return g_test_failures == 0 ? 0 : 1;
}
