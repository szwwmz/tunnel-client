/* SPDX-License-Identifier: LicenseRef-Proprietary
   Copyright (c) 2026 wwm-spec. All rights reserved.
 */

#include "vpncore/vpn_log.h"
#include "vpncore/vpn_error.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#endif

static vpn_log_level g_level = VPN_LOG_INFO;
static vpn_log_cb    g_cb = NULL;
static void         *g_cb_user = NULL;

void vpn_log_set_level(vpn_log_level level) { g_level = level; }
vpn_log_level vpn_log_get_level(void) { return g_level; }

void vpn_log_set_callback(vpn_log_cb cb, void *user)
{
    g_cb = cb;
    g_cb_user = user;
}

static const char *level_tag(vpn_log_level lv)
{
    switch (lv) {
    case VPN_LOG_TRACE: return "TRACE";
    case VPN_LOG_DEBUG: return "DEBUG";
    case VPN_LOG_INFO:  return "INFO ";
    case VPN_LOG_WARN:  return "WARN ";
    case VPN_LOG_ERROR: return "ERROR";
    default:            return "?????";
    }
}

static void timestamp(char *buf, size_t len)
{
#ifdef _WIN32
    SYSTEMTIME st;
    GetLocalTime(&st);
    snprintf(buf, len, "%02d:%02d:%02d.%03d", st.wHour, st.wMinute, st.wSecond,
             st.wMilliseconds);
#else
    struct timespec ts;
    struct tm tmv;
    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tmv);
    snprintf(buf, len, "%02d:%02d:%02d.%03ld", tmv.tm_hour, tmv.tm_min, tmv.tm_sec,
             ts.tv_nsec / 1000000L);
#endif
}

void vpn_log_printf(vpn_log_level level, const char *file, int line,
                    const char *fmt, ...)
{
    char msg[1024];
    va_list ap;

    if (level < g_level)
        return;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    if (g_cb) {
        g_cb(level, msg, g_cb_user);
        return;
    }

    char ts[32];
    const char *base = file ? strrchr(file, '/') : NULL;
    base = base ? base + 1 : file;
    timestamp(ts, sizeof(ts));
    fprintf(stderr, "%s %s %s:%d %s\n", ts, level_tag(level), base ? base : "-", line, msg);
    fflush(stderr);
}

const char *vpn_strerror(int err)
{
    switch (err) {
    case VPN_OK:              return "success";
    case VPN_ERR_INVALID:     return "invalid argument";
    case VPN_ERR_NOMEM:       return "out of memory";
    case VPN_ERR_IO:          return "i/o error";
    case VPN_ERR_TIMEOUT:     return "timeout";
    case VPN_ERR_AUTH:        return "authentication failed";
    case VPN_ERR_TLS:         return "tls error";
    case VPN_ERR_PROTO:       return "protocol error";
    case VPN_ERR_CANCELLED:   return "cancelled";
    case VPN_ERR_UNSUPPORTED: return "not supported on this platform";
    case VPN_ERR_CONFIG:      return "invalid configuration";
    case VPN_ERR_CLOSED:      return "connection closed by peer";
    case VPN_ERR_BUSY:        return "resource busy";
    default:                  return "unknown error";
    }
}
