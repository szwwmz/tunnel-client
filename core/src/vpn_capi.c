/* vpn_capi.c - C ABI 薄封装：配置转换 + 回调转发 */
#include "vpncore/vpn_capi.h"

#include "vpncore/vpn_client.h"
#include "vpncore/vpn_config.h"
#include "vpncore/vpn_error.h"
#include "vpncore/vpn_log.h"
#include "vpncore/vpn_net.h"
#include "vpncore/vpn_tun.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    vpn_client *client;
    int        *fd; /* 传给 TUN ops 的描述符（由核心在 destroy 时关闭） */
    vpn_capi_state_fn on_state;
    vpn_capi_stats_fn on_stats;
    void *user;
} capi_ctx;

/* ---- TUN 回调适配（capi 的 int/uint8_t 签名 -> core 的 size_t/void* 签名） ---- */

typedef struct {
    /* 必须按值保存：调用方（GUI/C#/其他宿主）通常传栈上的临时结构体，
     * 只存指针会在其返回后变成悬垂指针，数据面第一次读 TUN 就崩溃。 */
    vpn_capi_tun cbs;
} tun_adapter;

static int adapt_read(void *ctx, void *buf, size_t cap, int timeout_ms)
{
    tun_adapter *a = ctx;
    if (!a->cbs.read)
        return 0;
    return a->cbs.read(a->cbs.ctx, (uint8_t *)buf, (int)cap, timeout_ms);
}

static int adapt_write(void *ctx, const void *buf, size_t len)
{
    tun_adapter *a = ctx;
    if (!a->cbs.write)
        return -1;
    return a->cbs.write(a->cbs.ctx, (const uint8_t *)buf, (int)len);
}

static void adapt_destroy(void *ctx)
{
    tun_adapter *a = ctx;
    if (a->cbs.destroy)
        a->cbs.destroy(a->cbs.ctx);
    free(a);
}

/* ---- 日志桥接 ---------------------------------------------------------- */

static vpn_capi_log_fn g_log_fn;
static void *g_log_user;

static void capi_log_bridge(vpn_log_level level, const char *message, void *user)
{
    (void)user;
    if (g_log_fn)
        g_log_fn((int)level, message, g_log_user);
}

VPN_API void vpn_capi_set_log_level(int level)
{
    vpn_log_set_level((vpn_log_level)level);
}

VPN_API void vpn_capi_set_socket_protect(vpn_capi_protect_fn fn, void *ctx)
{
    vpn_net_set_protect((vpn_protect_fn)fn, ctx);
}

VPN_API void vpn_capi_set_log_callback(vpn_capi_log_fn fn, void *user)
{
    g_log_fn = fn;
    g_log_user = user;
    vpn_log_set_callback(fn ? capi_log_bridge : NULL, NULL);
}

/* ---- 回调转发 ---------------------------------------------------------- */

static void capi_on_state(void *ctx, vpn_state state, const char *detail)
{
    capi_ctx *c = ctx;
    if (c->on_state)
        c->on_state((int)state, detail ? detail : "", c->user);
}

static void capi_on_stats(void *ctx, const vpn_stats *stats)
{
    capi_ctx *c = ctx;
    vpn_capi_stats out;

    if (!c->on_stats)
        return;
    memset(&out, 0, sizeof(out));
    out.rx_bytes = stats->rx_bytes;
    out.tx_bytes = stats->tx_bytes;
    out.rx_packets = stats->rx_packets;
    out.tx_packets = stats->tx_packets;
    out.dropped = stats->dropped;
    out.reconnects = stats->reconnects;
    out.rtt_ms = stats->rtt_ms;
    out.connected_since_ms = stats->connected_since_ms;
    out.state = (int)vpn_client_get_state(c->client);
    snprintf(out.local_ip, sizeof(out.local_ip), "%s", stats->local_ip);
    snprintf(out.peer_ip, sizeof(out.peer_ip), "%s", stats->peer_ip);
    snprintf(out.dns1, sizeof(out.dns1), "%s", stats->dns1);
    snprintf(out.dns2, sizeof(out.dns2), "%s", stats->dns2);
    snprintf(out.cipher, sizeof(out.cipher), "%s", stats->cipher);
    snprintf(out.cert_fingerprint, sizeof(out.cert_fingerprint), "%s",
             stats->cert_fingerprint);
    c->on_stats(&out, c->user);
}

/* ---- 配置转换 ---------------------------------------------------------- */

static void copy_str(char *dst, size_t cap, const char *src)
{
    if (!src) {
        dst[0] = '\0';
        return;
    }
    snprintf(dst, cap, "%s", src);
}

VPN_API vpn_handle vpn_capi_create_ex(const vpn_capi_config *cc,
                                      const vpn_capi_tun *tun_cbs,
                                      vpn_capi_state_fn on_state,
                                      vpn_capi_stats_fn on_stats,
                                      void *user,
                                      char *err, int errlen)
{
    vpn_config cfg;
    vpn_tun_ops tun;
    vpn_client_cbs cbs;
    capi_ctx *ctx;
    char verr[192];
    bool has_tun = false;

    if (!cc) {
        if (err && errlen > 0)
            snprintf(err, (size_t)errlen, "config is null");
        return NULL;
    }

    vpn_config_init(&cfg);
    cfg.proto = (vpn_proto)(cc->proto >= 0 && cc->proto <= 2 ? cc->proto : 0);
    copy_str(cfg.host, sizeof(cfg.host), cc->host);
    cfg.port = (uint16_t)(cc->port > 0 ? cc->port : 0);
    copy_str(cfg.username, sizeof(cfg.username), cc->username);
    copy_str(cfg.password, sizeof(cfg.password), cc->password);
    copy_str(cfg.psk, sizeof(cfg.psk), cc->psk);
    if (cc->auth >= 0 && cc->auth <= 3)
        cfg.auth = (vpn_auth_mode)cc->auth;
    cfg.cert_mode = cc->cert_mode == 1 ? VPN_CERT_IGNORE : VPN_CERT_VERIFY;
    copy_str(cfg.ca_file, sizeof(cfg.ca_file), cc->ca_file);
    copy_str(cfg.ca_dir, sizeof(cfg.ca_dir), cc->ca_dir);
    copy_str(cfg.server_name, sizeof(cfg.server_name), cc->server_name);
    cfg.verify_hostname = cc->verify_hostname ? true : false;
    if (cc->mtu > 0)
        cfg.mtu = (uint32_t)cc->mtu;
    if (cc->keepalive_s >= 0)
        cfg.keepalive_interval_s = cc->keepalive_s;
    if (cc->reconnect_delay_s > 0)
        cfg.reconnect_delay_s = cc->reconnect_delay_s;
    cfg.max_retries = cc->max_retries;
    if (cc->connect_timeout_s > 0)
        cfg.connect_timeout_s = cc->connect_timeout_s;
    if (cc->io_timeout_s > 0)
        cfg.io_timeout_s = cc->io_timeout_s;
    copy_str(cfg.local_ip, sizeof(cfg.local_ip), cc->local_ip);
    copy_str(cfg.dns1, sizeof(cfg.dns1), cc->dns1);
    copy_str(cfg.dns2, sizeof(cfg.dns2), cc->dns2);
    if (cc->log_level >= 0 && cc->log_level <= 3)
        cfg.log_level = cc->log_level;

    if (vpn_config_validate(&cfg, verr, sizeof(verr)) != VPN_OK) {
        if (err && errlen > 0)
            snprintf(err, (size_t)errlen, "%s", verr);
        return NULL;
    }

    ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        if (err && errlen > 0)
            snprintf(err, (size_t)errlen, "out of memory");
        return NULL;
    }

    memset(&tun, 0, sizeof(tun));
    if (tun_cbs && tun_cbs->read && tun_cbs->write) {
        tun_adapter *ad = calloc(1, sizeof(*ad));
        if (!ad) {
            free(ctx);
            if (err && errlen > 0)
                snprintf(err, (size_t)errlen, "out of memory");
            return NULL;
        }
        ad->cbs = *tun_cbs;
        tun.read = adapt_read;
        tun.write = adapt_write;
        tun.destroy = adapt_destroy;
        tun.ctx = ad;
    } else if (cc->tun_fd >= 0) {
        ctx->fd = malloc(sizeof(int));
        if (!ctx->fd) {
            free(ctx);
            if (err && errlen > 0)
                snprintf(err, (size_t)errlen, "out of memory");
            return NULL;
        }
        *ctx->fd = cc->tun_fd;
        if (vpn_tun_ops_from_fd(cc->tun_fd, true, &tun) != VPN_OK) {
            free(ctx->fd);
            free(ctx);
            if (err && errlen > 0)
                snprintf(err, (size_t)errlen, "invalid tun fd");
            return NULL;
        }
    }

    memset(&cbs, 0, sizeof(cbs));
    cbs.on_state = capi_on_state;
    cbs.on_stats = capi_on_stats;
    cbs.ctx = ctx;
    ctx->on_state = on_state;
    ctx->on_stats = on_stats;
    ctx->user = user;

    has_tun = (tun.read && tun.write) ? true : false;
    ctx->client = vpn_client_new(&cfg, has_tun ? &tun : NULL, &cbs);
    if (!ctx->client) {
        free(ctx->fd);
        free(ctx);
        if (err && errlen > 0)
            snprintf(err, (size_t)errlen, "invalid config");
        return NULL;
    }
    if (err && errlen > 0)
        err[0] = '\0';
    return (vpn_handle)ctx;
}

VPN_API vpn_handle vpn_capi_create(const vpn_capi_config *cc,
                                   vpn_capi_state_fn on_state,
                                   vpn_capi_stats_fn on_stats,
                                   void *user,
                                   char *err, int errlen)
{
    return vpn_capi_create_ex(cc, NULL, on_state, on_stats, user, err, errlen);
}

VPN_API int vpn_capi_start(vpn_handle h)
{
    capi_ctx *c = h;
    if (!c || !c->client)
        return VPN_ERR_INVALID;
    return vpn_client_start(c->client);
}

VPN_API int vpn_capi_wait(vpn_handle h, int timeout_ms)
{
    capi_ctx *c = h;
    if (!c || !c->client)
        return VPN_ERR_INVALID;
    return vpn_client_wait(c->client, timeout_ms);
}

VPN_API void vpn_capi_stop(vpn_handle h)
{
    capi_ctx *c = h;
    if (!c || !c->client)
        return;
    vpn_client_stop(c->client);
}

VPN_API void vpn_capi_destroy(vpn_handle h)
{
    capi_ctx *c = h;
    if (!c)
        return;
    if (c->client) {
        /* client 没释放成功说明工作线程还活着；此时连 capi_ctx 也不能放，
         * 否则线程里的 jni 回调会拿已释放的 ctx（同样崩在 native 层） */
        if (vpn_client_free(c->client) != VPN_OK) {
            VPN_ERROR("客户端线程未退出，跳过释放以免崩溃（内存故意泄漏）");
            c->client = NULL;
            return;
        }
        c->client = NULL;
    }
    free(c->fd);
    free(c);
}

VPN_API int vpn_capi_attach_tun(vpn_handle h, const vpn_capi_tun *tun)
{
    capi_ctx *c = h;
    vpn_tun_ops ops;
    tun_adapter *ad;

    if (!c || !c->client || !tun || !tun->read || !tun->write)
        return VPN_ERR_INVALID;

    ad = calloc(1, sizeof(*ad));
    if (!ad)
        return VPN_ERR_NOMEM;
    ad->cbs = *tun;

    memset(&ops, 0, sizeof(ops));
    ops.read = adapt_read;
    ops.write = adapt_write;
    ops.destroy = adapt_destroy;
    ops.ctx = ad;
    if (vpn_client_attach_tun(c->client, &ops) != VPN_OK) {
        free(ad);
        return VPN_ERR_BUSY;
    }
    return VPN_OK;
}

VPN_API int vpn_capi_attach_tun_fd(vpn_handle h, int fd)
{
    capi_ctx *c = h;
    vpn_tun_ops ops;

    if (!c || !c->client || fd < 0)
        return VPN_ERR_INVALID;
    if (vpn_tun_ops_from_fd(fd, true, &ops) != VPN_OK)
        return VPN_ERR_INVALID;
    return vpn_client_attach_tun(c->client, &ops);
}

VPN_API void vpn_capi_detach_tun(vpn_handle h)
{
    capi_ctx *c = h;
    if (c && c->client)
        vpn_client_detach_tun(c->client);
}

VPN_API int vpn_capi_state(vpn_handle h)
{
    capi_ctx *c = h;
    if (!c || !c->client)
        return VPN_CAPI_STATE_IDLE;
    return (int)vpn_client_get_state(c->client);
}

VPN_API void vpn_capi_get_stats(vpn_handle h, vpn_capi_stats *out)
{
    capi_ctx *c = h;
    vpn_stats st;

    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    if (!c || !c->client)
        return;

    vpn_client_get_stats(c->client, &st);
    out->rx_bytes = st.rx_bytes;
    out->tx_bytes = st.tx_bytes;
    out->rx_packets = st.rx_packets;
    out->tx_packets = st.tx_packets;
    out->dropped = st.dropped;
    out->reconnects = st.reconnects;
    out->rtt_ms = st.rtt_ms;
    out->connected_since_ms = st.connected_since_ms;
    out->state = (int)vpn_client_get_state(c->client);
    snprintf(out->local_ip, sizeof(out->local_ip), "%s", st.local_ip);
    snprintf(out->peer_ip, sizeof(out->peer_ip), "%s", st.peer_ip);
    snprintf(out->dns1, sizeof(out->dns1), "%s", st.dns1);
    snprintf(out->dns2, sizeof(out->dns2), "%s", st.dns2);
    snprintf(out->cipher, sizeof(out->cipher), "%s", st.cipher);
    snprintf(out->cert_fingerprint, sizeof(out->cert_fingerprint), "%s",
             st.cert_fingerprint);
}

VPN_API void *vpn_capi_user(vpn_handle h)
{
    capi_ctx *c = h;
    return c ? c->user : NULL;
}

VPN_API const char *vpn_capi_state_name(int state)
{
    return vpn_state_name((vpn_state)state);
}

VPN_API const char *vpn_capi_strerror(int code)
{
    return vpn_strerror(code);
}
