/* SPDX-License-Identifier: LicenseRef-Proprietary
   Copyright (c) 2026 wwm-spec. All rights reserved.
 */

#include "vpncore/vpn_platform.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#endif

int64_t vpn_now_ms(void)
{
#ifdef _WIN32
    static LARGE_INTEGER freq;
    LARGE_INTEGER now;
    if (freq.QuadPart == 0)
        QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&now);
    return (int64_t)(now.QuadPart * 1000 / freq.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}

void vpn_sleep_ms(int ms)
{
    if (ms <= 0)
        return;
#ifdef _WIN32
    Sleep((DWORD)ms);
#else
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
        /* 被信号打断：继续剩余时间 */
    }
#endif
}

int vpn_mutex_init(vpn_mutex *m)
{
#ifdef _WIN32
    m->h = CreateMutex(NULL, FALSE, NULL);
    return m->h ? 0 : -1;
#else
    return pthread_mutex_init(&m->m, NULL);
#endif
}

void vpn_mutex_destroy(vpn_mutex *m)
{
#ifdef _WIN32
    if (m->h) {
        CloseHandle(m->h);
        m->h = NULL;
    }
#else
    pthread_mutex_destroy(&m->m);
#endif
}

void vpn_mutex_lock(vpn_mutex *m)
{
#ifdef _WIN32
    WaitForSingleObject(m->h, INFINITE);
#else
    pthread_mutex_lock(&m->m);
#endif
}

void vpn_mutex_unlock(vpn_mutex *m)
{
#ifdef _WIN32
    ReleaseMutex(m->h);
#else
    pthread_mutex_unlock(&m->m);
#endif
}

/* ---- 线程：统一用 finished 标志轮询，避开 pthread_timedjoin_np 的可移植性问题 ---- */
typedef struct {
    vpn_thread_fn fn;
    void         *arg;
    volatile int *finished;
} thread_boot;

#ifdef _WIN32
static DWORD WINAPI thread_entry(LPVOID p)
#else
static void *thread_entry(void *p)
#endif
{
    thread_boot b = *(thread_boot *)p;
    free(p);
    b.fn(b.arg);
    __atomic_store_n(b.finished, 1, __ATOMIC_SEQ_CST);
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

int vpn_thread_start(vpn_thread *t, vpn_thread_fn fn, void *arg)
{
    thread_boot *b;
    volatile int *flag;

    if (!t)
        return -1;

    t->started = 0;
    t->finished = NULL;
    flag = (volatile int *)calloc(1, sizeof(int));
    b = (thread_boot *)malloc(sizeof(*b));
    if (!flag || !b) {
        free((void *)(uintptr_t)flag);
        free(b);
        return -1;
    }
    b->fn = fn;
    b->arg = arg;
    b->finished = flag;

#ifdef _WIN32
    {
        HANDLE h = CreateThread(NULL, 0, thread_entry, b, 0, NULL);
        if (!h) {
            free(b);
            free((void *)(uintptr_t)flag);
            return -1;
        }
        t->handle = (void *)h;
    }
#else
    if (pthread_create(&t->t, NULL, thread_entry, b) != 0) {
        free(b);
        free((void *)(uintptr_t)flag);
        return -1;
    }
#endif
    t->finished = flag;
    t->started = 1;
    return 0;
}

int vpn_thread_join(vpn_thread *t, int timeout_ms)
{
    if (!t || !t->started)
        return 0;

    int64_t deadline = (timeout_ms < 0) ? -1 : vpn_now_ms() + timeout_ms;
    while (!__atomic_load_n(t->finished, __ATOMIC_SEQ_CST)) {
        if (deadline >= 0 && vpn_now_ms() > deadline)
            return -1;
        vpn_sleep_ms(5);
    }

#ifdef _WIN32
    {
        HANDLE h = (HANDLE)t->handle;
        WaitForSingleObject(h, 1000);
        CloseHandle(h);
        t->handle = NULL;
    }
#else
    pthread_join(t->t, NULL);
#endif
    free((void *)t->finished);
    t->finished = NULL;
    t->started = 0;
    return 0;
}

uint32_t vpn_next_task_id(void)
{
    static volatile uint32_t counter = 0;
    return __atomic_add_fetch(&counter, 1, __ATOMIC_SEQ_CST);
}
