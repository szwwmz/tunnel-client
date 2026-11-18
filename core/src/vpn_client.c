/* vpn_client.c - 连接生命周期编排
 *
 * 结构：
 *   worker 线程
 *     └─ 循环 attempt()：open 传输层 -> 启动 PPP -> 事件循环（PPP tick / TUN 收发 /
 *        保活）-> 断开 -> 退避重连
 *
 * 线程模型：所有协议状态只在 worker 线程里改；状态/统计的读取由 lock 保护，
 * 回调在锁外触发，避免回调里再调 vpn_client_* 造成死锁。
 */
#include "vpncore/vpn_client.h"

#include "vpncore/vpn_buf.h"
#include "vpncore/vpn_error.h"
#include "vpncore/vpn_l2tp.h"
#include "vpncore/vpn_log.h"
#include "vpncore/vpn_net.h"
#include "vpncore/vpn_platform.h"
#include "vpncore/vpn_ppp.h"
#include "vpncore/vpn_pptp.h"
#include "vpncore/vpn_sstp.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define CLIENT_THREAD_RET  DWORD WINAPI
#else
#define CLIENT_THREAD_RET  void *
#endif

#define CLIENT_TUN_BUF 2048

struct vpn_client {
    vpn_config    cfg;
    vpn_tun_ops   tun;
    bool          has_tun;
    vpn_client_cbs cbs;

    vpn_mutex  lock;
    vpn_thread th;
    volatile int th_finished;
    volatile int stop_req;

    vpn_state state;
    char      detail[192];

    vpn_stats stats;
    int64_t   up_since_ms;

    /* worker 线程私有 */
    vpn_ppp  *ppp;
    vpn_sstp *sstp;
    vpn_l2tp *l2tp;
    vpn_pptp *pptp;
    bool      keys_pushed;
    int       last_error;

    /* 数据面发送连续性检测：WiFi 掉线 / 切换网络 / 隧道 socket 被路由
     * 吞掉时，UDP 是无连接的，send 会持续失败但不会"关连接"。累计到阈值
     * 就判定链路中断，让主循环退出、走正常重连，而不是一直假装已连接 */
    volatile int link_dead;
    volatile int send_fail;
};

/* ------------------------------------------------------------------ */
/* 状态 / 统计                                                         */
/* ------------------------------------------------------------------ */

const char *vpn_state_name(vpn_state st)
{
    switch (st) {
    case VPN_STATE_IDLE:           return "idle";
    case VPN_STATE_CONNECTING:     return "connecting";
    case VPN_STATE_AUTHENTICATING: return "authenticating";
    case VPN_STATE_CONNECTED:      return "connected";
    case VPN_STATE_RECONNECTING:   return "reconnecting";
    case VPN_STATE_DISCONNECTED:   return "disconnected";
    case VPN_STATE_FAILED:         return "failed";
    }
    return "unknown";
}

static void set_state(vpn_client *c, vpn_state st, const char *fmt, ...)
{
    char detail[sizeof(c->detail)];
    va_list ap;

    detail[0] = '\0';
    if (fmt) {
        va_start(ap, fmt);
        vsnprintf(detail, sizeof(detail), fmt, ap);
        va_end(ap);
    }

    vpn_mutex_lock(&c->lock);
    c->state = st;
    snprintf(c->detail, sizeof(c->detail), "%s", detail);
    vpn_mutex_unlock(&c->lock);

    if (st == VPN_STATE_CONNECTED)
        VPN_INFO("状态：%s（%s）", vpn_state_name(st), detail);
    else if (st == VPN_STATE_FAILED)
        VPN_ERROR("状态：%s（%s）", vpn_state_name(st), detail);
    else
        VPN_INFO("状态：%s（%s）", vpn_state_name(st), detail);

    if (c->cbs.on_state)
        c->cbs.on_state(c->cbs.ctx, st, detail);
}

static void publish_stats(vpn_client *c)
{
    vpn_stats snap;

    vpn_mutex_lock(&c->lock);
    snap = c->stats;
    vpn_mutex_unlock(&c->lock);

    if (c->cbs.on_stats)
        c->cbs.on_stats(c->cbs.ctx, &snap);
}

/* ------------------------------------------------------------------ */
/* PPP 回调                                                            */
/* ------------------------------------------------------------------ */

static void ppp_cb_send(void *ctx, const uint8_t *frame, size_t len)
{
    vpn_client *c = ctx;
    int rc = VPN_ERR_CLOSED;

    if (c->sstp)
        rc = vpn_sstp_send_ppp(c->sstp, frame, len);
    else if (c->l2tp)
        rc = vpn_l2tp_send_ppp(c->l2tp, frame, len);
    else if (c->pptp)
        rc = vpn_pptp_send_ppp(c->pptp, frame, len);

    if (rc == VPN_OK || rc == VPN_ERR_TIMEOUT) {
        c->send_fail = 0;
        return;
    }

    c->send_fail++;
    /* 限流：断网后每个包都会失败，不限流日志会被刷爆（前 3 次 + 每 200 次） */
    if (c->send_fail <= 3 || c->send_fail % 200 == 0) {
        int saved = vpn_net_last_send_errno();
        if (saved)
            VPN_WARN("PPP: 发送帧失败（%s，errno=%d），连续 %d 次",
                     vpn_strerror(rc), saved, c->send_fail);
        else
            VPN_WARN("PPP: 发送帧失败（%s），连续 %d 次", vpn_strerror(rc), c->send_fail);
    }

    /* 连续失败 10 次（约几十毫秒的上行量）就认为物理链路已断 */
    if (c->send_fail >= 10 && !c->link_dead) {
        c->link_dead = 1;
        VPN_ERROR("PPP: 连续 %d 次发送失败，判定链路中断，开始重连", c->send_fail);
    }
}

/* IPCP 给出的地址是主机字节序 */
static void ipv4_str(uint32_t ip, char *out, size_t cap)
{
    snprintf(out, cap, "%u.%u.%u.%u", (unsigned)((ip >> 24) & 0xff),
             (unsigned)((ip >> 16) & 0xff), (unsigned)((ip >> 8) & 0xff),
             (unsigned)(ip & 0xff));
}

static void ppp_cb_up(void *ctx, const ppp_net_info *info)
{
    vpn_client *c = ctx;
    char lip[32], pip[32];
    ipv4_str(info->local_ip, lip, sizeof(lip));
    ipv4_str(info->peer_ip, pip, sizeof(pip));

    vpn_mutex_lock(&c->lock);
    c->up_since_ms = vpn_now_ms();
    c->stats.connected_since_ms = c->up_since_ms;
    snprintf(c->stats.local_ip, sizeof(c->stats.local_ip), "%s", lip);
    snprintf(c->stats.peer_ip, sizeof(c->stats.peer_ip), "%s", pip);
    if (info->dns1)
        ipv4_str(info->dns1, c->stats.dns1, sizeof(c->stats.dns1));
    if (info->dns2)
        ipv4_str(info->dns2, c->stats.dns2, sizeof(c->stats.dns2));
    snprintf(c->stats.cipher, sizeof(c->stats.cipher), "%s",
             info->using_mschapv2 ? "MPPE-128 (MS-CHAPv2)" : "MPPE(未启用)");
    vpn_mutex_unlock(&c->lock);

    set_state(c, VPN_STATE_CONNECTED, "本机 %s  服务器 %s  DNS %s", lip, pip,
              c->stats.dns1[0] ? c->stats.dns1 : "-");
    publish_stats(c);
}

static vpn_tun_ops vpn_client_tun_snapshot(vpn_client *c)
{
    vpn_tun_ops ops;
    vpn_mutex_lock(&c->lock);
    ops = c->has_tun ? c->tun : (vpn_tun_ops){ 0 };
    vpn_mutex_unlock(&c->lock);
    return ops;
}

static void ppp_cb_ip(void *ctx, const uint8_t *pkt, size_t len)
{
    vpn_client *c = ctx;
    vpn_tun_ops t = vpn_client_tun_snapshot(c);
    int n;

    if (!t.write) {
        vpn_mutex_lock(&c->lock);
        c->stats.rx_packets++;
        c->stats.rx_bytes += len;
        c->stats.dropped++; /* 无 TUN（--no-tun）时丢弃载荷 */
        vpn_mutex_unlock(&c->lock);
        return;
    }

    n = t.write(t.ctx, pkt, len);
    vpn_mutex_lock(&c->lock);
    if (n < 0) {
        c->stats.dropped++;
    } else {
        c->stats.rx_packets++;
        c->stats.rx_bytes += len;
    }
    vpn_mutex_unlock(&c->lock);
}

static void ppp_cb_auth_failed(void *ctx, const char *reason)
{
    vpn_client *c = ctx;
    VPN_ERROR("认证失败：%s", reason ? reason : "未知原因");
    c->last_error = VPN_ERR_AUTH;
    set_state(c, VPN_STATE_FAILED, "认证失败：%s", reason ? reason : "未知原因");
}

static void ppp_cb_closed(void *ctx, const char *reason)
{
    (void)ctx;
    VPN_WARN("PPP 关闭：%s", reason ? reason : "-");
}

/* ------------------------------------------------------------------ */
/* 传输层回调                                                          */
/* ------------------------------------------------------------------ */

static void tp_cb_ppp(void *ctx, const uint8_t *frame, size_t len)
{
    vpn_client *c = ctx;
    if (c->ppp)
        vpn_ppp_input(c->ppp, frame, len, vpn_now_ms());
}

static void tp_cb_connected(void *ctx)
{
    vpn_client *c = ctx;
    set_state(c, VPN_STATE_AUTHENTICATING, "传输通道就绪，开始 PPP 协商");
}

static void tp_cb_closed(void *ctx, const char *reason)
{
    vpn_client *c = ctx;
    if (reason && *reason) {
        VPN_WARN("传输层断开：%s", reason);
        c->last_error = VPN_ERR_CLOSED;
    }
}

/* ------------------------------------------------------------------ */
/* worker                                                             */
/* ------------------------------------------------------------------ */

static int build_ppp_config(vpn_client *c, ppp_config *pc)
{
    memset(pc, 0, sizeof(*pc));
    pc->auth = c->cfg.auth;
    snprintf(pc->username, sizeof(pc->username), "%s", c->cfg.username);
    snprintf(pc->password, sizeof(pc->password), "%s", c->cfg.password);
    pc->mtu = c->cfg.mtu;
    pc->mru = c->cfg.mru;
    snprintf(pc->local_ip, sizeof(pc->local_ip), "%s", c->cfg.local_ip);
    snprintf(pc->dns1, sizeof(pc->dns1), "%s", c->cfg.dns1);
    snprintf(pc->dns2, sizeof(pc->dns2), "%s", c->cfg.dns2);
    return VPN_OK;
}

static int open_transport(vpn_client *c)
{
    const vpn_config *g = &c->cfg;

    switch (g->proto) {
    case VPN_PROTO_SSTP: {
        vpn_sstp_params sp;
        vpn_sstp_cbs cb;
        memset(&sp, 0, sizeof(sp));
        snprintf(sp.host, sizeof(sp.host), "%s", g->host);
        sp.port = g->port ? g->port : 443;
        sp.cert_mode = g->cert_mode;
        snprintf(sp.ca_file, sizeof(sp.ca_file), "%s", g->ca_file);
        snprintf(sp.ca_dir, sizeof(sp.ca_dir), "%s", g->ca_dir);
        /* server_name 为空时用 host 做 SNI / 主机名校验 */
        snprintf(sp.server_name, sizeof(sp.server_name), "%s",
                 g->server_name[0] ? g->server_name : g->host);
        sp.verify_hostname = g->verify_hostname;
        sp.connect_timeout_ms = g->connect_timeout_s * 1000;
        sp.io_timeout_ms = g->io_timeout_s * 1000;
        sp.use_crypto_binding = true;

        memset(&cb, 0, sizeof(cb));
        cb.on_ppp = tp_cb_ppp;
        cb.on_connected = tp_cb_connected;
        cb.on_closed = tp_cb_closed;
        cb.ctx = c;

        c->sstp = vpn_sstp_new(&sp, &cb);
        if (!c->sstp)
            return VPN_ERR_NOMEM;
        return vpn_sstp_open(c->sstp);
    }
    case VPN_PROTO_L2TP: {
        vpn_l2tp_params lp;
        vpn_l2tp_cbs cb;
        memset(&lp, 0, sizeof(lp));
        snprintf(lp.host, sizeof(lp.host), "%s", g->host);
        lp.port = L2TP_PORT_DEFAULT;   /* 固定 UDP/1701，不接受自定义端口 */
        lp.use_ipsec = g->psk[0] != '\0';
        snprintf(lp.psk, sizeof(lp.psk), "%s", g->psk);
        lp.connect_timeout_ms = g->connect_timeout_s * 1000;
        lp.io_timeout_ms = g->io_timeout_s * 1000;
        snprintf(lp.tunnel_name, sizeof(lp.tunnel_name), "vpnclient");
        lp.recv_window = 4;

        memset(&cb, 0, sizeof(cb));
        cb.on_ppp = tp_cb_ppp;
        cb.on_connected = tp_cb_connected;
        cb.on_closed = tp_cb_closed;
        cb.ctx = c;

        c->l2tp = vpn_l2tp_new(&lp, &cb);
        if (!c->l2tp)
            return VPN_ERR_NOMEM;
        return vpn_l2tp_open(c->l2tp);
    }
    case VPN_PROTO_PPTP: {
        vpn_pptp_params pp;
        vpn_pptp_cbs cb;
        if (!vpn_pptp_supported()) {
            VPN_ERROR("当前平台不支持 PPTP（需要 GRE/RAW socket 权限）");
            return VPN_ERR_UNSUPPORTED;
        }
        memset(&pp, 0, sizeof(pp));
        snprintf(pp.host, sizeof(pp.host), "%s", g->host);
        pp.port = PPTP_PORT_DEFAULT;   /* 固定 TCP/1723，不接受自定义端口 */
        pp.connect_timeout_ms = g->connect_timeout_s * 1000;
        pp.io_timeout_ms = g->io_timeout_s * 1000;

        memset(&cb, 0, sizeof(cb));
        cb.on_ppp = tp_cb_ppp;
        cb.on_connected = tp_cb_connected;
        cb.on_closed = tp_cb_closed;
        cb.ctx = c;

        c->pptp = vpn_pptp_new(&pp, &cb);
        if (!c->pptp)
            return VPN_ERR_NOMEM;
        return vpn_pptp_open(c->pptp);
    }
    }
    return VPN_ERR_CONFIG;
}

static void close_transport(vpn_client *c)
{
    if (c->sstp) {
        vpn_sstp_close(c->sstp, "客户端断开");
        vpn_sstp_free(c->sstp);
        c->sstp = NULL;
    }
    if (c->l2tp) {
        vpn_l2tp_close(c->l2tp, "客户端断开");
        vpn_l2tp_free(c->l2tp);
        c->l2tp = NULL;
    }
    if (c->pptp) {
        vpn_pptp_close(c->pptp, "客户端断开");
        vpn_pptp_free(c->pptp);
        c->pptp = NULL;
    }
    if (c->ppp) {
        vpn_ppp_close(c->ppp, "连接结束");
        vpn_ppp_free(c->ppp);
        c->ppp = NULL;
    }
    c->keys_pushed = false;
}

/* 一次完整的连接尝试；返回 VPN_OK 表示正常结束（被 stop 或对方关闭） */
static int client_attempt(vpn_client *c)
{
    ppp_config pc;
    ppp_callbacks pcb;
    int rc;
    int64_t next_keepalive = 0;
    int64_t next_stats = 0;
    uint8_t ipbuf[CLIENT_TUN_BUF];
    vpn_tun_ops tun_snap;

    c->last_error = VPN_OK;
    c->send_fail = 0;
    c->link_dead = 0;
    set_state(c, VPN_STATE_CONNECTING, "连接 %s（%s:%u）", c->cfg.host,
              vpn_proto_name(c->cfg.proto),
              (unsigned)(c->cfg.port ? c->cfg.port
                                     : vpn_proto_default_port(c->cfg.proto)));

    rc = open_transport(c);
    if (rc != VPN_OK) {
        VPN_ERROR("建立传输通道失败：%s", vpn_strerror(rc));
        c->last_error = rc;
        close_transport(c);
        return rc;
    }

    build_ppp_config(c, &pc);
    memset(&pcb, 0, sizeof(pcb));
    pcb.send = ppp_cb_send;
    pcb.up = ppp_cb_up;
    pcb.ip = ppp_cb_ip;
    pcb.auth_failed = ppp_cb_auth_failed;
    pcb.closed = ppp_cb_closed;
    pcb.ctx = c;

    c->ppp = vpn_ppp_new(&pc, &pcb);
    if (!c->ppp) {
        close_transport(c);
        return VPN_ERR_NOMEM;
    }
    vpn_ppp_start(c->ppp, vpn_now_ms());

    /* 事件循环 */
    while (!c->stop_req) {
        int64_t now;
        bool open;

        /* 每轮重新取 TUN 快照。Windows/Linux 是连接前就把 TUN 传进来，
         * 但 Android 必须先完成 PPP 拿到地址才能 Builder.establish()，
         * 也就是 TUN 在连接成功之后才 attach。只在循环外取一次的话，
         * 这一整轮会话的 tun_snap.read 恒为 NULL —— 上行一个包都不读，
         * 表现为"连接成功但完全不通"（下行也没人发，所以收发都是 0）。 */
        tun_snap = vpn_client_tun_snapshot(c);

        /* 2ms 轮询：20ms 时单包往返会把 RTT 抬到上百毫秒 */
        if (c->sstp)
            rc = vpn_sstp_run_once(c->sstp, 2);
        else if (c->l2tp)
            rc = vpn_l2tp_run_once(c->l2tp, 2);
        else
            rc = vpn_pptp_run_once(c->pptp, 2);

        if (rc != VPN_OK && rc != VPN_ERR_TIMEOUT) {
            VPN_WARN("传输层读失败：%s", vpn_strerror(rc));
            break;
        }

        now = vpn_now_ms();
        vpn_ppp_tick(c->ppp, now);

        /* 统计上抛：每秒一次。
         * 原来只在 PPP up 那一刻 publish 过一次，之后再也不发，
         * 界面上的收发字节/包数就永远停在 0，看着像"应用卡死了" */
        if (now >= next_stats) {
            next_stats = now + 1000;
            publish_stats(c);
        }

        if (vpn_ppp_is_up(c->ppp)) {
            /* SSTP Crypto-Binding 需要 MS-CHAPv2 派生的 MPPE 密钥 */
            if (c->sstp && !c->keys_pushed) {
                uint8_t ksend[16], krecv[16];
                if (vpn_ppp_mppe_keys(c->ppp, ksend, krecv)) {
                    vpn_sstp_set_mppe_keys(c->sstp, ksend, krecv);
                    c->keys_pushed = true;
                    memset(ksend, 0, sizeof(ksend));
                    memset(krecv, 0, sizeof(krecv));
                }
            }

            /* TUN -> PPP：每轮批量取包（最多 32 个），避免单包往返拖慢吞吐 */
            if (tun_snap.read) {
                for (int burst = 0; burst < 32; burst++) {
                    int n = tun_snap.read(tun_snap.ctx, ipbuf, sizeof(ipbuf), 0);

                    if (n == VPN_ERR_TIMEOUT)
                        break;
                    if (n <= 0) {
                        VPN_DEBUG("tun 读取返回 %d（%s）", n, vpn_strerror(n));
                        break;
                    }
                    VPN_TRACE("tun 收到 %d 字节 IP 包", n);
                    if (vpn_ppp_send_ip(c->ppp, ipbuf, (size_t)n) != VPN_OK) {
                        vpn_mutex_lock(&c->lock);
                        c->stats.dropped++;
                        vpn_mutex_unlock(&c->lock);
                        break;
                    }
                    vpn_mutex_lock(&c->lock);
                    c->stats.tx_packets++;
                    c->stats.tx_bytes += (uint64_t)n;
                    vpn_mutex_unlock(&c->lock);
                }
            }
        }

        /* 传输层保活（与 PPP LCP Echo 相互独立） */
        if (c->cfg.keepalive_interval_s > 0 && vpn_ppp_is_up(c->ppp)) {
            if (next_keepalive == 0)
                next_keepalive = now + (int64_t)c->cfg.keepalive_interval_s * 1000;
            else if (now >= next_keepalive) {
                if (c->sstp)
                    vpn_sstp_send_echo(c->sstp);
                else if (c->l2tp)
                    vpn_l2tp_send_hello(c->l2tp);
                next_keepalive = now + (int64_t)c->cfg.keepalive_interval_s * 1000;
            }
        }

        /* 数据面持续发不出去 —— 上层是看不出来的（UDP 无连接状态），
         * 必须自己判定，否则断网后界面一直显示"已连接" */
        if (c->link_dead) {
            VPN_WARN("链路已判定中断，退出本次会话并重连");
            if (c->last_error == VPN_OK)
                c->last_error = VPN_ERR_IO;
            break;
        }

        open = c->sstp ? vpn_sstp_is_open(c->sstp)
                       : (c->l2tp ? vpn_l2tp_is_open(c->l2tp) : vpn_pptp_is_open(c->pptp));
        if (!open) {
            VPN_WARN("传输通道已关闭");
            if (c->last_error == VPN_OK)
                c->last_error = VPN_ERR_CLOSED;
            break;
        }
    }

    close_transport(c);
    return VPN_OK;
}

static CLIENT_THREAD_RET client_worker(void *arg)
{
    vpn_client *c = arg;
    int retries = 0;

    while (!c->stop_req) {
        int rc = client_attempt(c);

        if (c->stop_req)
            break;

        if (rc == VPN_ERR_AUTH || rc == VPN_ERR_UNSUPPORTED || rc == VPN_ERR_CONFIG) {
            /* 这些错误重试没有意义 */
            set_state(c, VPN_STATE_FAILED, "%s", vpn_strerror(rc));
            break;
        }

        /* 自动重连开关：关闭时断开即结束（默认开启，见 vpn_config_init） */
        if (!c->cfg.auto_reconnect) {
            set_state(c, VPN_STATE_DISCONNECTED, "已断开（自动重连已关闭）");
            break;
        }

        retries++;
        if (c->cfg.max_retries >= 0 && retries > c->cfg.max_retries) {
            set_state(c, VPN_STATE_FAILED, "连接失败（%s），已达重试上限 %d 次",
                      vpn_strerror(rc), c->cfg.max_retries);
            break;
        }

        vpn_mutex_lock(&c->lock);
        c->stats.reconnects = (uint32_t)retries;
        vpn_mutex_unlock(&c->lock);

        set_state(c, VPN_STATE_RECONNECTING, "第 %d 次重连，%d 秒后重试", retries,
                  c->cfg.reconnect_delay_s);

        /* 分片睡眠，保证 stop 能及时生效 */
        {
            int left = c->cfg.reconnect_delay_s * 1000;
            while (left > 0 && !c->stop_req) {
                int slice = left > 100 ? 100 : left;
                vpn_sleep_ms(slice);
                left -= slice;
            }
        }
    }

    if (c->stop_req || c->last_error == VPN_OK)
        set_state(c, VPN_STATE_DISCONNECTED, "已断开");
    else
        set_state(c, VPN_STATE_FAILED, "%s", vpn_strerror(c->last_error));
    c->th_finished = 1;
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

/* ------------------------------------------------------------------ */
/* 对外 API                                                            */
/* ------------------------------------------------------------------ */

vpn_client *vpn_client_new(const vpn_config *cfg, const vpn_tun_ops *tun,
                           const vpn_client_cbs *cbs)
{
    vpn_client *c;
    char err[192];

    if (!cfg) {
        VPN_ERROR("vpn_client_new: cfg 为空");
        return NULL;
    }
    if (vpn_config_validate(cfg, err, sizeof(err)) != VPN_OK) {
        VPN_ERROR("配置无效：%s", err);
        return NULL;
    }

    c = calloc(1, sizeof(*c));
    if (!c)
        return NULL;

    c->cfg = *cfg;
    if (tun && tun->read && tun->write) {
        c->tun = *tun;
        c->has_tun = true;
    }
    if (cbs)
        c->cbs = *cbs;

    c->state = VPN_STATE_IDLE;
    c->last_error = VPN_OK;
    snprintf(c->detail, sizeof(c->detail), "未开始");
    vpn_mutex_init(&c->lock);

    if (vpn_config_port_needs_hint(cfg))
        VPN_WARN("端口 %u 不是 443：SSTP 可能被中间设备识别/拦截，穿透性下降",
                 (unsigned)cfg->port);

    /* L2TP/PPTP 用固定标准端口（UDP/1701、TCP/1723），不允许自定义：
     * 归一化为 0（=协议默认），调用方传什么都不会被采用 */
    if (c->cfg.proto != VPN_PROTO_SSTP && c->cfg.port) {
        if (c->cfg.port != vpn_proto_default_port(c->cfg.proto))
            VPN_WARN("%s 端口固定为 %s/%u，已忽略指定的 %u",
                     vpn_proto_name(c->cfg.proto),
                     c->cfg.proto == VPN_PROTO_L2TP ? "UDP" : "TCP",
                     (unsigned)vpn_proto_default_port(c->cfg.proto),
                     (unsigned)c->cfg.port);
        c->cfg.port = 0;
    }

    return c;
}

/* 请求停止并等线程退出；0=确已退出，-1=超时仍在跑 */
static int client_stop_wait(vpn_client *c)
{
    if (!c)
        return 0;
    c->stop_req = 1;
    if (c->th.started) {
        /* 事件循环是 2ms 一轮，正常情况下几十毫秒内就能退出；
         * 超时说明卡在阻塞的 connect/读操作里，再给一次机会 */
        if (vpn_thread_join(&c->th, 3000) != 0) {
            VPN_WARN("工作线程 3 秒内未退出，继续等待（可能卡在握手超时）");
            if (vpn_thread_join(&c->th, 15000) != 0)
                return -1;
        }
    }
    vpn_mutex_lock(&c->lock);
    c->state = VPN_STATE_DISCONNECTED;
    vpn_mutex_unlock(&c->lock);
    return 0;
}

void vpn_client_stop(vpn_client *c)
{
    (void)client_stop_wait(c);
}

int vpn_client_free(vpn_client *c)
{
    if (!c)
        return VPN_OK;
    if (client_stop_wait(c) != 0) {
        /* 工作线程还在跑（多半卡在 TCP 握手 / connect 超时里）。
         * 此时 free 掉 c，线程下一次用到它就是野指针 —— SIGSEGV，
         * Java 的 UncaughtExceptionHandler 根本抓不到，表现就是
         * "用着用着直接退出，重开什么日志都没有"。
         * 宁可泄漏这一块内存（几十 KB，进程马上就结束了），也不能崩。 */
        return VPN_ERR_BUSY;
    }
    if (c->has_tun && c->tun.destroy)
        c->tun.destroy(c->tun.ctx);
    vpn_mutex_destroy(&c->lock);
    free(c);
    return VPN_OK;
}

int vpn_client_start(vpn_client *c)
{
    if (!c)
        return VPN_ERR_INVALID;
    if (c->th.started)
        return VPN_OK;

    c->stop_req = 0;
    c->th_finished = 0;
    if (vpn_thread_start(&c->th, client_worker, c) != 0) {
        VPN_ERROR("启动工作线程失败");
        return VPN_ERR_IO;
    }
    return VPN_OK;
}



int vpn_client_wait(vpn_client *c, int timeout_ms)
{
    int64_t deadline;
    if (!c)
        return VPN_ERR_INVALID;

    deadline = vpn_now_ms() + (timeout_ms < 0 ? 0 : timeout_ms);
    for (;;) {
        vpn_state st;
        vpn_mutex_lock(&c->lock);
        st = c->state;
        vpn_mutex_unlock(&c->lock);

        if (st == VPN_STATE_CONNECTED)
            return VPN_OK;
        if (st == VPN_STATE_FAILED)
            return c->last_error != VPN_OK ? c->last_error : VPN_ERR_AUTH;
        if (st == VPN_STATE_DISCONNECTED && c->th_finished)
            return c->last_error != VPN_OK ? c->last_error : VPN_ERR_CLOSED;

        if (timeout_ms >= 0 && vpn_now_ms() >= deadline)
            return VPN_ERR_TIMEOUT;
        if (timeout_ms < 0 && c->th_finished)
            return VPN_ERR_CLOSED;
        vpn_sleep_ms(50);
    }
}

vpn_state vpn_client_get_state(vpn_client *c)
{
    vpn_state st;
    if (!c)
        return VPN_STATE_IDLE;
    vpn_mutex_lock(&c->lock);
    st = c->state;
    vpn_mutex_unlock(&c->lock);
    return st;
}

int vpn_client_attach_tun(vpn_client *c, const vpn_tun_ops *tun)
{
    int rc = VPN_OK;

    if (!c || !tun || !tun->read || !tun->write)
        return VPN_ERR_INVALID;

    vpn_mutex_lock(&c->lock);
    if (c->has_tun) {
        rc = VPN_ERR_BUSY;
    } else {
        c->tun = *tun;
        c->has_tun = true;
        VPN_INFO("已挂接 TUN（IP 转发开启）");
    }
    vpn_mutex_unlock(&c->lock);
    return rc;
}

void vpn_client_detach_tun(vpn_client *c)
{
    vpn_tun_ops old;

    if (!c)
        return;
    vpn_mutex_lock(&c->lock);
    old = c->tun;
    memset(&c->tun, 0, sizeof(c->tun));
    c->has_tun = false;
    vpn_mutex_unlock(&c->lock);

    if (old.destroy)
        old.destroy(old.ctx);
}

void vpn_client_get_stats(vpn_client *c, vpn_stats *out)
{
    if (!c || !out)
        return;
    vpn_mutex_lock(&c->lock);
    *out = c->stats;
    vpn_mutex_unlock(&c->lock);
}

int vpn_client_connect_blocking(vpn_client *c, int timeout_ms)
{
    int rc = vpn_client_start(c);
    if (rc != VPN_OK)
        return rc;
    return vpn_client_wait(c, timeout_ms);
}
