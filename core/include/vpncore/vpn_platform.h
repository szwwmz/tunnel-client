/* SPDX-License-Identifier: LicenseRef-Proprietary
   Copyright (c) 2026 wwm-spec. All rights reserved.
 */

/* vpn_platform.h - 极薄的平台抽象（线程/互斥/时间）
 *
 * 目的：核心层在 Android(NDK/pthread)、Linux CLI、Windows(MSVC/CreateThread)
 * 三套工具链下都能直接编译，不引入额外依赖（不用 pthread-win32）。
 */
#ifndef VPN_PLATFORM_H
#define VPN_PLATFORM_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int64_t vpn_now_ms(void);
void    vpn_sleep_ms(int ms);

#ifdef _WIN32
#include <windows.h>
typedef struct { HANDLE h; } vpn_mutex;
typedef struct {
    void         *handle;    /* HANDLE */
    volatile int *finished;
    int           started;
} vpn_thread;
typedef unsigned long vpn_thread_ret;
#else
#include <pthread.h>
typedef struct { pthread_mutex_t m; } vpn_mutex;
typedef struct {
    pthread_t     t;
    volatile int *finished;
    int           started;
} vpn_thread;
typedef void *vpn_thread_ret;
#endif

int  vpn_mutex_init(vpn_mutex *m);
void vpn_mutex_destroy(vpn_mutex *m);
void vpn_mutex_lock(vpn_mutex *m);
void vpn_mutex_unlock(vpn_mutex *m);

typedef vpn_thread_ret (*vpn_thread_fn)(void *arg);

int  vpn_thread_start(vpn_thread *t, vpn_thread_fn fn, void *arg);
/* 等待线程结束；timeout_ms < 0 表示无限等待。返回 0 表示已结束 */
int  vpn_thread_join(vpn_thread *t, int timeout_ms);

/* 单调递增的任务 ID，用于日志关联 */
uint32_t vpn_next_task_id(void);

#ifdef __cplusplus
}
#endif

#endif /* VPN_PLATFORM_H */
