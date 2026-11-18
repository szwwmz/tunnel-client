/* main.c - Linux CLI 外壳（SSTP / L2TP / PPTP 客户端）
 *
 * 只做平台相关的事：参数解析、密码输入、TUN 设备与路由、信号与日志输出。
 * 所有协议逻辑都在 libvpncore 里，Android/Windows 外壳复用同一套核心。
 */
#define _DEFAULT_SOURCE

#include "vpncore/vpn_client.h"
#include "vpncore/vpn_config.h"
#include "vpncore/vpn_error.h"
#include "vpncore/vpn_log.h"
#include "vpncore/vpn_net.h"
#include "vpncore/vpn_platform.h"
#include "vpncore/vpn_tun.h"

#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CLI_VERSION "1.0.0"

static volatile sig_atomic_t g_stop;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static void usage(const char *argv0)
{
    printf(
"跨平台 VPN 客户端 %s（SSTP / L2TP over IPsec / PPTP）\n"
"\n"
"用法：%s --server HOST [选项]\n"
"\n"
"必填：\n"
"  -s, --server HOST        服务器地址（域名或 IP）\n"
"  -u, --user NAME          用户名\n"
"  -p, --password PASS      密码（省略则交互输入）\n"
"\n"
"协议：\n"
"      --proto P             sstp | l2tp | pptp（默认 sstp）\n"
"      --port N              端口：仅 SSTP 可自定义（默认 443）；\n"
"                            L2TP 固定 UDP/1701、PPTP 固定 TCP/1723，该参数被忽略\n"
"      --psk KEY             L2TP/IPsec 预共享密钥（由平台 IPsec 使用）\n"
"      --auth M              mschapv2 | chap | pap | auto（默认 auto）\n"
"\n"
"证书（SSTP）：\n"
"      --cert verify|ignore  证书策略（默认 verify）\n"
"      --ca-file PATH        自定义 CA（PEM）\n"
"      --ca-dir PATH         CA 目录\n"
"      --server-name NAME    SNI / 证书校验名（默认同 --server）\n"
"      --no-verify-hostname  只校验证书链，不校验主机名\n"
"\n"
"网络：\n"
"      --mtu N               链路 MTU（默认 1400）\n"
"      --dev NAME            TUN 设备名（默认 tun%%d，需要 root）\n"
"      --no-tun              不创建 TUN，仅验证协议连通性\n"
"      --route CIDR          额外路由，可重复（如 10.0.0.0/8）\n"
"      --no-default-route    不安装默认路由（仅走 --route 指定的网段）\n"
"      --keepalive N         保活间隔秒（0 关闭，默认 30）\n"
"      --reconnect-delay N   重连间隔秒（默认 5）\n"
"      --max-retries N       最大重连次数（-1 无限，默认 -1）\n"
"      --no-reconnect        断开后不自动重连（默认自动重连开启）\n"
"      --timeout N           连接超时秒（默认 20）\n"
"\n"
"输出：\n"
"  -v, --verbose             调试日志（hexdump 级）\n"
"  -q, --quiet               只输出错误\n"
"      --stats-interval N    统计打印间隔秒（0 关闭，默认 5）\n"
"  -h, --help / -V, --version\n"
"\n"
"示例：\n"
"  %s -s vpn.example.com -u alice -p secret\n"
"  %s -s vpn.example.com --proto sstp --port 992 --cert ignore --dev tun9\n"
"  %s -s 1.2.3.4 --proto l2tp -u alice -p secret --route 192.168.88.0/24\n",
        CLI_VERSION, argv0, argv0, argv0, argv0);
}

/* 支持 --key=value 与 --key value */
static const char *opt_value(int argc, char **argv, int *i, const char *name)
{
    size_t n = strlen(name);

    if (strncmp(argv[*i], name, n) != 0)
        return NULL;
    if (argv[*i][n] == '=') {
        (*i)++;
        return argv[*i - 1] + n + 1;
    }
    if (argv[*i][n] != '\0')
        return NULL;
    if (*i + 1 >= argc) {
        fprintf(stderr, "参数 %s 缺少取值\n", name);
        exit(2);
    }
    (*i)++;
    return argv[*i];
}

static int read_password(char *out, size_t cap)
{
    char *p = getpass("密码：");
    if (!p)
        return -1;
    snprintf(out, cap, "%s", p);
    return 0;
}

/* "10.0.0.0/8" -> 网络地址 + 掩码（均为网络字节序） */
static int parse_cidr(const char *s, uint32_t *dst, uint32_t *mask)
{
    char buf[64];
    char *slash;
    int prefix;
    uint32_t net;

    snprintf(buf, sizeof(buf), "%s", s);
    slash = strchr(buf, '/');
    if (slash) {
        *slash = '\0';
        prefix = atoi(slash + 1);
    } else {
        prefix = 32;
    }
    if (prefix < 0 || prefix > 32)
        return -1;
    if (vpn_ip_parse(buf, &net) != 0) {
        /* 不带点分网络地址时按 0.0.0.0 处理 */
        net = 0;
    }
    if (dst)
        *dst = net;
    if (mask)
        *mask = prefix == 0 ? 0 : htonl(0xffffffffu << (32 - prefix));
    return 0;
}

/* 从 /proc/net/route 找默认路由的网关与接口（用于给服务器 IP 打洞） */
static int default_gateway(char *dev_out, size_t devlen, uint32_t *gw_be)
{
#if defined(__linux__)
    FILE *f = fopen("/proc/net/route", "r");
    char line[512];

    if (!f)
        return -1;
    if (!fgets(line, sizeof(line), f)) { /* 表头 */
        fclose(f);
        return -1;
    }
    while (fgets(line, sizeof(line), f)) {
        char iface[64];
        unsigned long dest = 0, gw = 0, flags = 0;
        if (sscanf(line, "%63s %lx %lx %lx", iface, &dest, &gw, &flags) != 4)
            continue;
        if (dest == 0 && gw != 0) {
            snprintf(dev_out, devlen, "%s", iface);
            *gw_be = (uint32_t)gw; /* 内核以主机序打印，直接写入 s_addr 即正确字节序 */
            fclose(f);
            return 0;
        }
    }
    fclose(f);
#else
    (void)dev_out; (void)devlen; (void)gw_be;
#endif
    return -1;
}

static const char *human_bytes(uint64_t v, char *buf, size_t cap)
{
    if (v >= 1024ull * 1024 * 1024)
        snprintf(buf, cap, "%.2f GiB", (double)v / (1024.0 * 1024 * 1024));
    else if (v >= 1024ull * 1024)
        snprintf(buf, cap, "%.2f MiB", (double)v / (1024.0 * 1024));
    else if (v >= 1024)
        snprintf(buf, cap, "%.2f KiB", (double)v / 1024.0);
    else
        snprintf(buf, cap, "%llu B", (unsigned long long)v);
    return buf;
}

static void print_stats(const vpn_stats *st)
{
    char rx[32], tx[32];
    int64_t up = 0;

    if (st->connected_since_ms)
        up = (vpn_now_ms() - st->connected_since_ms) / 1000;

    printf("[统计] 在线 %llds  RX %s/%llu 包  TX %s/%llu 包  丢弃 %llu  重连 %u\n",
           (long long)up, human_bytes(st->rx_bytes, rx, sizeof(rx)),
           (unsigned long long)st->rx_packets,
           human_bytes(st->tx_bytes, tx, sizeof(tx)),
           (unsigned long long)st->tx_packets, (unsigned long long)st->dropped,
           st->reconnects);
    fflush(stdout);
}

static void cb_state(void *ctx, vpn_state state, const char *detail)
{
    (void)ctx;
    if (state == VPN_STATE_CONNECTED)
        printf("[状态] %s  %s\n", vpn_state_name(state), detail ? detail : "");
    else
        fprintf(stderr, "[状态] %s  %s\n", vpn_state_name(state), detail ? detail : "");
    fflush(stdout);
    fflush(stderr);
}

static void cb_stats(void *ctx, const vpn_stats *stats)
{
    (void)ctx;
    (void)stats;
}

int main(int argc, char **argv)
{
    vpn_config cfg;
    vpn_client_cbs cbs;
    vpn_client *client = NULL;
    vpn_tun_ops tun;
    bool has_tun = false;
    char tun_name[64] = {0};
    char dev_name[64] = "tun%d";
    bool no_tun = false;
    int stats_interval = 5;
    int wait_timeout_s = 60;
    int i;
    int rc;
    struct sigaction sa;

    vpn_config_init(&cfg);

    for (i = 1; i < argc; i++) {
        const char *v;

        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(argv[0]);
            return 0;
        }
        if (!strcmp(argv[i], "-V") || !strcmp(argv[i], "--version")) {
            printf("vpnclient %s\n", CLI_VERSION);
            return 0;
        }
        if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose")) {
            cfg.log_level = VPN_LOG_DEBUG;
            continue;
        }
        if (!strcmp(argv[i], "-q") || !strcmp(argv[i], "--quiet")) {
            cfg.log_level = VPN_LOG_ERROR;
            continue;
        }
        if (!strcmp(argv[i], "--no-tun")) {
            no_tun = true;
            continue;
        }
        if (!strcmp(argv[i], "--no-default-route")) {
            cfg.use_default_route = false;
            continue;
        }
        if (!strcmp(argv[i], "--no-verify-hostname")) {
            cfg.verify_hostname = false;
            continue;
        }
        if (!strcmp(argv[i], "--no-reconnect")) {
            cfg.auto_reconnect = false;
            continue;
        }

        if ((v = opt_value(argc, argv, &i, "-s")) || (v = opt_value(argc, argv, &i, "--server"))) {
            snprintf(cfg.host, sizeof(cfg.host), "%s", v);
        } else if ((v = opt_value(argc, argv, &i, "-u")) || (v = opt_value(argc, argv, &i, "--user"))) {
            snprintf(cfg.username, sizeof(cfg.username), "%s", v);
        } else if ((v = opt_value(argc, argv, &i, "-p")) || (v = opt_value(argc, argv, &i, "--password"))) {
            snprintf(cfg.password, sizeof(cfg.password), "%s", v);
        } else if ((v = opt_value(argc, argv, &i, "--proto"))) {
            if (vpn_proto_from_name(v, &cfg.proto) != VPN_OK) {
                fprintf(stderr, "未知协议：%s\n", v);
                return 2;
            }
        } else if ((v = opt_value(argc, argv, &i, "--port"))) {
            cfg.port = (uint16_t)atoi(v);
        } else if ((v = opt_value(argc, argv, &i, "--psk"))) {
            snprintf(cfg.psk, sizeof(cfg.psk), "%s", v);
        } else if ((v = opt_value(argc, argv, &i, "--auth"))) {
            if (!strcmp(v, "mschapv2"))
                cfg.auth = VPN_AUTH_MSCHAPV2;
            else if (!strcmp(v, "chap"))
                cfg.auth = VPN_AUTH_CHAP;
            else if (!strcmp(v, "pap"))
                cfg.auth = VPN_AUTH_PAP;
            else
                cfg.auth = VPN_AUTH_AUTO;
        } else if ((v = opt_value(argc, argv, &i, "--cert"))) {
            if (!strcmp(v, "ignore")) {
                cfg.cert_mode = VPN_CERT_IGNORE;
                fprintf(stderr, "警告：已关闭证书校验，连接可能被中间人攻击\n");
            } else {
                cfg.cert_mode = VPN_CERT_VERIFY;
            }
        } else if ((v = opt_value(argc, argv, &i, "--ca-file"))) {
            snprintf(cfg.ca_file, sizeof(cfg.ca_file), "%s", v);
        } else if ((v = opt_value(argc, argv, &i, "--ca-dir"))) {
            snprintf(cfg.ca_dir, sizeof(cfg.ca_dir), "%s", v);
        } else if ((v = opt_value(argc, argv, &i, "--server-name"))) {
            snprintf(cfg.server_name, sizeof(cfg.server_name), "%s", v);
        } else if ((v = opt_value(argc, argv, &i, "--mtu"))) {
            cfg.mtu = (uint32_t)atoi(v);
        } else if ((v = opt_value(argc, argv, &i, "--dev"))) {
            snprintf(dev_name, sizeof(dev_name), "%s", v);
        } else if ((v = opt_value(argc, argv, &i, "--route"))) {
            if (cfg.route_count >= VPN_MAX_ROUTES) {
                fprintf(stderr, "--route 数量超过上限 %d\n", VPN_MAX_ROUTES);
                return 2;
            }
            snprintf(cfg.routes[cfg.route_count], 32, "%s", v);
            cfg.route_count++;
        } else if ((v = opt_value(argc, argv, &i, "--keepalive"))) {
            cfg.keepalive_interval_s = atoi(v);
        } else if ((v = opt_value(argc, argv, &i, "--reconnect-delay"))) {
            cfg.reconnect_delay_s = atoi(v);
        } else if ((v = opt_value(argc, argv, &i, "--max-retries"))) {
            cfg.max_retries = atoi(v);
        } else if ((v = opt_value(argc, argv, &i, "--timeout"))) {
            cfg.connect_timeout_s = atoi(v);
        } else if ((v = opt_value(argc, argv, &i, "--stats-interval"))) {
            stats_interval = atoi(v);
        } else {
            fprintf(stderr, "未知参数：%s（--help 查看用法）\n", argv[i]);
            return 2;
        }
    }

    if (!cfg.host[0]) {
        fprintf(stderr, "缺少 --server\n");
        return 2;
    }
    if (!cfg.username[0]) {
        fprintf(stderr, "缺少 --user\n");
        return 2;
    }
    if (!cfg.password[0] && read_password(cfg.password, sizeof(cfg.password)) != 0) {
        fprintf(stderr, "无法读取密码\n");
        return 2;
    }

    vpn_log_set_level(cfg.log_level);

    if (cfg.proto == VPN_PROTO_PPTP) {
        fprintf(stderr,
                "警告：PPTP（MPPE）已被证明不安全，GRE(47) 也常被运营商拦截。\n"
                "      仅在兼容老设备时使用，敏感场景请改用 SSTP 或 L2TP/IPsec。\n");
    }
    if (vpn_config_port_needs_hint(&cfg)) {
        printf("提示：端口 %u 不是 443，可能被防火墙/DPI 识别，穿透性下降\n",
               (unsigned)cfg.port);
    }

    vpn_net_init();

    if (!no_tun) {
        rc = vpn_tun_open(dev_name, cfg.mtu, tun_name, sizeof(tun_name), &tun);
        if (rc != VPN_OK) {
            fprintf(stderr, "创建 TUN 失败（%s）：需要 root/CAP_NET_ADMIN，"
                            "或使用 --no-tun 只做连通性验证\n", vpn_strerror(rc));
            return 3;
        }
        has_tun = true;
        printf("TUN 设备：%s（MTU %u）\n", tun_name, (unsigned)cfg.mtu);
    }

    memset(&cbs, 0, sizeof(cbs));
    cbs.on_state = cb_state;
    cbs.on_stats = cb_stats;

    client = vpn_client_new(&cfg, has_tun ? &tun : NULL, &cbs);
    if (!client) {
        fprintf(stderr, "初始化客户端失败（检查配置）\n");
        if (has_tun && tun.destroy)
            tun.destroy(tun.ctx);
        return 3;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    wait_timeout_s = cfg.connect_timeout_s + 40;
    rc = vpn_client_connect_blocking(client, wait_timeout_s * 1000);
    if (rc != VPN_OK) {
        fprintf(stderr, "连接失败：%s\n", vpn_strerror(rc));
        vpn_client_free(client); /* 内部会 stop + 销毁 TUN */
        vpn_net_cleanup();
        return 4;
    }

    {
        vpn_stats st;
        char srv_dev[64];
        uint32_t srv_gw = 0;
        bool have_gw = default_gateway(srv_dev, sizeof(srv_dev), &srv_gw) == 0;

        vpn_client_get_stats(client, &st);
        printf("\n已连接：本机 %s  服务器 %s  DNS %s / %s\n", st.local_ip, st.peer_ip,
               st.dns1[0] ? st.dns1 : "-", st.dns2[0] ? st.dns2 : "-");
        if (st.cipher[0])
            printf("加密：%s\n", st.cipher);
        if (st.cert_fingerprint[0])
            printf("服务器证书 SHA-256：%s\n", st.cert_fingerprint);

        if (has_tun && st.local_ip[0]) {
            uint32_t lip = 0, pip = 0;
            vpn_ip_parse(st.local_ip, &lip);
            if (st.peer_ip[0])
                vpn_ip_parse(st.peer_ip, &pip);

            rc = vpn_tun_configure(tun_name, lip, pip, 0xffffffffu, cfg.mtu);
            if (rc != VPN_OK) {
                fprintf(stderr, "配置 TUN 地址失败（%s），请手动执行：\n"
                                "  ip addr add %s peer %s dev %s\n  ip link set %s up\n",
                        vpn_strerror(rc), st.local_ip, st.peer_ip, tun_name, tun_name);
            }

            /* 先给服务器 IP 打洞，避免默认路由切到 TUN 后控制报文绕回隧道 */
            if ((cfg.use_default_route || cfg.route_count > 0) && have_gw) {
                struct sockaddr_storage ss;
                socklen_t sslen = 0;
                if (vpn_net_resolve(cfg.host,
                                    cfg.port ? cfg.port : vpn_proto_default_port(cfg.proto),
                                    &ss, &sslen) == VPN_OK &&
                    ss.ss_family == AF_INET) {
                    struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
                    if (vpn_tun_add_route_via(srv_dev, sin->sin_addr.s_addr,
                                              0xffffffffu, srv_gw) == VPN_OK)
                        printf("已为服务器地址添加 /32 直连路由（经 %s）\n", srv_dev);
                    else
                        fprintf(stderr, "警告：服务器 /32 路由添加失败，默认路由切换后可能回路\n");
                }
            }

            if (cfg.use_default_route) {
                if (vpn_tun_add_route(tun_name, 0, 0) == VPN_OK)
                    printf("默认路由已切换到 %s\n", tun_name);
                else
                    fprintf(stderr, "警告：默认路由添加失败，请手动 ip route add default dev %s\n",
                            tun_name);
            }
            for (i = 0; i < cfg.route_count; i++) {
                uint32_t dst = 0, mask = 0;
                if (parse_cidr(cfg.routes[i], &dst, &mask) == 0)
                    vpn_tun_add_route(tun_name, dst, mask);
                else
                    fprintf(stderr, "路由格式错误：%s\n", cfg.routes[i]);
            }
        }
        print_stats(&st);
    }

    printf("\n按 Ctrl-C 断开...\n");
    fflush(stdout);

    {
        int64_t next_stats = stats_interval > 0
                                 ? vpn_now_ms() + (int64_t)stats_interval * 1000 : 0;
        while (!g_stop) {
            vpn_sleep_ms(200);
            if (next_stats && vpn_now_ms() >= next_stats) {
                vpn_stats st;
                vpn_client_get_stats(client, &st);
                print_stats(&st);
                next_stats = vpn_now_ms() + (int64_t)stats_interval * 1000;
            }
            if (vpn_client_get_state(client) == VPN_STATE_FAILED)
                break;
        }
    }

    vpn_client_stop(client);
    {
        vpn_stats st;
        vpn_client_get_stats(client, &st);
        printf("\n已断开。累计 RX %llu 包 / %llu 字节，TX %llu 包 / %llu 字节，重连 %u 次\n",
               (unsigned long long)st.rx_packets, (unsigned long long)st.rx_bytes,
               (unsigned long long)st.tx_packets, (unsigned long long)st.tx_bytes,
               st.reconnects);
        if (has_tun)
            printf("提示：TUN %s 的路由/地址随进程退出失效，如需保留请自行管理\n", tun_name);
    }

    vpn_client_free(client);
    vpn_net_cleanup();
    return 0;
}
