/* vpn_capi.h - 稳定的 C ABI（供 Android JNI 与 Windows C# P/Invoke 使用）
 *
 * 设计取舍：
 *   - 只用 POD 结构与函数指针，不暴露内部结构，避免各语言侧跟着重构而破坏 ABI；
 *   - 字符串一律 UTF-8，Windows 侧负责与 UTF-16 互转；
 *   - TUN 有两种接法：
 *       tun_fd >= 0  -> 直接用文件描述符收发（Android VpnService 的 fd、Linux TUN）
 *       tun_fd == -1 -> 不转发 IP（仅连通性验证）
 *     Windows 的 Wintun 会话不是 fd，见 platform/windows/wintun_shim.c（C 侧包一层回调）。
 */
#ifndef VPN_CAPI_H
#define VPN_CAPI_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
#  define VPN_API __declspec(dllexport)
#elif defined(__GNUC__)
#  define VPN_API __attribute__((visibility("default")))
#else
#  define VPN_API
#endif

typedef void *vpn_handle;

/* 状态码与 core 内部 vpn_state 一致 */
enum {
    VPN_CAPI_STATE_IDLE = 0,
    VPN_CAPI_STATE_CONNECTING = 1,
    VPN_CAPI_STATE_AUTHENTICATING = 2,
    VPN_CAPI_STATE_CONNECTED = 3,
    VPN_CAPI_STATE_RECONNECTING = 4,
    VPN_CAPI_STATE_DISCONNECTED = 5,
    VPN_CAPI_STATE_FAILED = 6
};

typedef struct {
    int         proto;          /* 0=SSTP 1=L2TP 2=PPTP */
    const char *host;
    int         port;           /* 0 = 协议默认端口 */
    const char *username;
    const char *password;
    const char *psk;            /* L2TP/IPsec 预共享密钥 */
    int         auth;           /* 0=MSCHAPv2 1=CHAP 2=PAP 3=auto */
    int         cert_mode;      /* 0=verify 1=ignore */
    const char *ca_file;        /* 可空 */
    const char *ca_dir;         /* 可空 */
    const char *server_name;    /* 可空，空则用 host */
    int         verify_hostname;/* 0/1 */
    int         mtu;            /* 0 = 1400 */
    int         keepalive_s;    /* 0 = 关闭 */
    int         reconnect_delay_s;
    int         max_retries;    /* -1 = 无限 */
    int         connect_timeout_s;
    int         io_timeout_s;
    const char *local_ip;       /* 可空 */
    const char *dns1;           /* 可空 */
    const char *dns2;           /* 可空 */
    int         log_level;      /* 0=ERROR 1=WARN 2=INFO 3=DEBUG */
    int         tun_fd;         /* >=0 用该 fd 收发；-1 不转发 */
} vpn_capi_config;

typedef struct {
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t dropped;
    uint32_t reconnects;
    uint32_t rtt_ms;
    int64_t  connected_since_ms;
    int      state;
    char     local_ip[32];
    char     peer_ip[32];
    char     dns1[32];
    char     dns2[32];
    char     cipher[128];
    char     cert_fingerprint[96];
} vpn_capi_stats;

/* 自定义 TUN 回调（Windows/Wintun 等没有 fd 的平台用）；
 * 返回值：read 返回字节数或 <=0，write 返回 0/正数为成功 */
typedef struct {
    int  (*read)(void *ctx, uint8_t *buf, int cap, int timeout_ms);
    int  (*write)(void *ctx, const uint8_t *buf, int len);
    void (*destroy)(void *ctx);
    void *ctx;
} vpn_capi_tun;

typedef void (*vpn_capi_state_fn)(int state, const char *detail, void *user);
typedef void (*vpn_capi_stats_fn)(const vpn_capi_stats *stats, void *user);
typedef void (*vpn_capi_log_fn)(int level, const char *message, void *user);

/* 创建实例；失败返回 NULL 并把原因写入 err（UTF-8）。on_state 可空。 */
VPN_API vpn_handle vpn_capi_create(const vpn_capi_config *cfg,
                                   vpn_capi_state_fn on_state,
                                   vpn_capi_stats_fn on_stats,
                                   void *user,
                                   char *err, int errlen);

/* 带自定义 TUN 回调的创建（tun 可空 = 不转发）；成功时 tun 的所有权交给核心 */
VPN_API vpn_handle vpn_capi_create_ex(const vpn_capi_config *cfg,
                                      const vpn_capi_tun *tun,
                                      vpn_capi_state_fn on_state,
                                      vpn_capi_stats_fn on_stats,
                                      void *user,
                                      char *err, int errlen);

VPN_API int  vpn_capi_start(vpn_handle h);
VPN_API int  vpn_capi_wait(vpn_handle h, int timeout_ms);
VPN_API void vpn_capi_stop(vpn_handle h);
VPN_API void vpn_capi_destroy(vpn_handle h);

/* 运行期挂接 TUN（Android/Windows：PPP 拿到地址后才能建隧道）。
 * 仅在当前未挂接时成功；回调与 ctx 的所有权转移给核心（destroy 时释放）。 */
VPN_API int  vpn_capi_attach_tun(vpn_handle h, const vpn_capi_tun *tun);

/* fd 版：fd 所有权转移给核心（Android 请用 ParcelFileDescriptor.detachFd()） */
VPN_API int  vpn_capi_attach_tun_fd(vpn_handle h, int fd);
VPN_API void vpn_capi_detach_tun(vpn_handle h);

VPN_API int  vpn_capi_state(vpn_handle h);
VPN_API void vpn_capi_get_stats(vpn_handle h, vpn_capi_stats *out);

/* 取回 create 时传入的 user 指针（外壳用它释放回调上下文） */
VPN_API void *vpn_capi_user(vpn_handle h);

/* 进程级日志：在 create 之前调用 */
VPN_API void vpn_capi_set_log_level(int level);
VPN_API void vpn_capi_set_log_callback(vpn_capi_log_fn fn, void *user);

/* Android 专用：传入 VpnService.protect 的包装（fn(ctx, fd) 返回 0 = 成功）。
 * 必须在 vpn_capi_start 之前设置；桌面平台无需调用。 */
typedef int (*vpn_capi_protect_fn)(void *ctx, int fd);
VPN_API void vpn_capi_set_socket_protect(vpn_capi_protect_fn fn, void *ctx);

VPN_API const char *vpn_capi_state_name(int state);
VPN_API const char *vpn_capi_strerror(int code);

#ifdef __cplusplus
}
#endif

#endif /* VPN_CAPI_H */
