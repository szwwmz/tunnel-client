/* SPDX-License-Identifier: LicenseRef-Proprietary
   Copyright (c) 2026 wwm-spec. All rights reserved.
 */

/* vpn_log.h - 轻量日志
 *
 * 核心层不直接写文件/控制台，而是通过回调把日志抛给平台外壳：
 *   - Android: 回调 -> Logcat + 应用内日志页
 *   - Windows: 回调 -> 服务日志文件 + UI 查看器
 *   - CLI    : 内置默认回调 -> stderr
 */
#ifndef VPN_LOG_H
#define VPN_LOG_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    VPN_LOG_TRACE = 0,
    VPN_LOG_DEBUG = 1,
    VPN_LOG_INFO  = 2,
    VPN_LOG_WARN  = 3,
    VPN_LOG_ERROR = 4
} vpn_log_level;

typedef void (*vpn_log_cb)(vpn_log_level level, const char *message, void *user);

void vpn_log_set_level(vpn_log_level level);
vpn_log_level vpn_log_get_level(void);

/* cb 为 NULL 表示恢复默认（stderr）输出 */
void vpn_log_set_callback(vpn_log_cb cb, void *user);

void vpn_log_printf(vpn_log_level level, const char *file, int line,
                    const char *fmt, ...);

#define VPN_TRACE(...) vpn_log_printf(VPN_LOG_TRACE, __FILE__, __LINE__, __VA_ARGS__)
#define VPN_DEBUG(...) vpn_log_printf(VPN_LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define VPN_INFO(...)  vpn_log_printf(VPN_LOG_INFO,  __FILE__, __LINE__, __VA_ARGS__)
#define VPN_WARN(...)  vpn_log_printf(VPN_LOG_WARN,  __FILE__, __LINE__, __VA_ARGS__)
#define VPN_ERROR(...) vpn_log_printf(VPN_LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* VPN_LOG_H */
