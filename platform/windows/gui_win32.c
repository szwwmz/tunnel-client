/* SPDX-License-Identifier: LicenseRef-Proprietary
   Copyright (c) 2026 wwm-spec. All rights reserved.
 */

/* gui_win32.c - Windows 图形界面（纯 Win32 + Wintun，无需 .NET 运行时）
 *
 * 线程模型：
 *   - 核心（capi）内部有自己的 worker 线程，start 立即返回；
 *   - 界面用定时器（200ms）轮询状态/统计，日志走环形缓冲 + 临界区，
 *     避免在核心回调线程里直接操作控件。
 *
 * 与 MikroTik 联调时：
 *   - 服务器填 RouterOS 地址，协议选 SSTP/L2TP，勾"接管全部流量"可测实际转发；
 *   - 日志区会打印 TLS 版本、证书指纹、PPP 协商与地址分配结果。
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include <windowsx.h>
#include <shellapi.h>
#include <commctrl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vpncore/vpn_capi.h"
#include "vpncore/vpn_error.h"
#include "vpncore/vpn_tun.h"
#include "vpncore/vpn_net.h"

#define APP_NAME_W    L"tunnel-client"
#define APP_VERSION_W L"1.4.0"
#define APP_AUTHOR_W  L"wwm"
#define APP_MAIL_W    L"szwwmz@gmail.com"
#define APP_CLASS_W   L"VpnClientWnd"

/* ---------------- 多语言 ----------------
 * 界面文案走 STR_TAB（[字符串 ID][语言]），运行期 g_lang 决定取哪一列。
 * 连接日志不在此列：日志统一英文（与 core 一致），避免同一份日志混两种语言。 */
enum { LANG_ZH = 0, LANG_EN = 1 };
static int g_lang = LANG_ZH;

enum {
    S_APP_NAME, S_ABOUT_TITLE, S_ABOUT,
    S_PROTO, S_SERVER, S_PORT, S_USER, S_PASS, S_CERT, S_CERT_VERIFY, S_CERT_IGNORE,
    S_ROUTE_ALL, S_ROUTE_PRIV, S_BTN_CONNECT, S_BTN_DISCONNECT,
    S_LOG_TITLE, S_LOG_HINT, S_LOG_CLEAR, S_LOG_COPY,
    S_BANNER_META, S_FOOTER, S_CARD_NOTE,
    S_TRAY_SHOW, S_TRAY_CONNECT, S_TRAY_DISCONNECT, S_TRAY_ABOUT, S_TRAY_EXIT,
    S_LANG_MENU, S_LANG_ZH, S_LANG_EN,
    S_ST_CONNECTING, S_ST_AUTH, S_ST_CONNECTED, S_ST_RECONNECTING,
    S_ST_DISCONNECTED, S_ST_FAILED, S_ST_IDLE,
    S_MSG_NEED_HOST, S_MSG_TITLE, S_CLOSE_TITLE, S_CLOSE_BODY,
    S_COUNT
};

/* 版本说明：中文保留完整历史，英文只列当前版本要点（历史全文见中文版） */
#define ABOUT_ZH_TEXT \
    L"tunnel-client v" APP_VERSION_W L"\n" \
    L"作者：wwm      联系：szwwmz@gmail.com      协议：SSTP / L2TP / PPTP\n" \
    L"\n" \
    L"v1.4.0\n" \
    L"  · Windows 界面支持中英双语：点标题栏右上角「中文 / EN」或托盘菜单\n" \
    L"    随时切换，选择写入 vpn-gui.ini（lang=zh|en），下次启动保持\n" \
    L"  · 连接日志、错误提示统一为英文，便于检索与上报\n" \
    L"  · 修复 CALL_CONNECTED 原地构造时 memcpy 源目标重叠（未定义行为）\n" \
    L"  · 修复 L2TP/IPsec 长域名被静默截断（IKE host 64 -> 256 字节）\n" \
    L"\n" \
    L"v1.3.0\n" \
    L"  · 版本号与 Android / Linux 对齐，三平台同一版本\n" \
    L"  · Android 端补齐应用图标并完成功能对齐（协议选择、路由/DNS 开关、\n" \
    L"    调试开关、日志区、配置保存、单实例），Windows 端功能不变\n" \
    L"\n" \
    L"v1.2.3\n" \
    L"  · 修复可多开：单实例判定挪到提权之前，之前 UAC 重启出来的进程\n" \
    L"    跳过判定，双击几次就开几个窗口；再次启动会把已有窗口拉到前台\n" \
    L"    并激活（含最小化到托盘的情形），本进程直接退出\n" \
    L"\n" \
    L"v1.2.2\n" \
    L"  · 日志再精简：LCP 保活回包（Echo-Request/Reply/Discard）改到调试级，\n" \
    L"    不再每 5 秒刷一条；IPCP 服务器拒绝选项也降为调试（属正常协商）\n" \
    L"  · 连接后日志稳定在十几行，长时间挂着也不会持续增长\n" \
    L"\n" \
    L"v1.2.1\n" \
    L"  · 修复 PPTP 一直停在 LCP 协商：GRE 头补上序列号（flags 0x2001 -> 0x3001），\n" \
    L"    与 RouterOS / Windows RAS 的头格式一致，此前对端收包即丢弃\n" \
    L"  · 日志默认精简：只保留连接各阶段的关键节点，逐包诊断默认关闭\n" \
    L"  · 新增 debug 开关：vpn-gui.ini 里 debug=1 才输出逐包调试日志（默认 0）\n" \
    L"  · 日志区支持右键“清除日志/复制全部”\n" \
    L"  · 修正日志级别标签错位（WARN 曾显示成[调试]）\n" \
    L"\n" \
    L"v1.2.0\n" \
    L"  · 新增“接管私有网段”：把 10.0.0.0/8、172.16.0.0/12、192.168.0.0/16 指向 VPN；\n" \
    L"    路由 metric = 6000（远大于本机直连路由），同前缀时本机路由优先，\n" \
    L"    更具体的前缀按最长匹配也先走本机，因此不影响本地网络互访\n" \
    L"  · 断开或退出时自动撤销已下发路由，不再残留 0.0.0.0/0\n" \
    L"  · 连接信息新增 routepriv 记忆项\n" \
    L"\n" \
    L"v1.1.0\n" \
    L"  · 常驻托盘：点关闭最小化，双击恢复，托盘菜单可连接/断开/退出\n" \
    L"  · 卡片式界面、状态圆点、深色日志区、悬停高亮按钮\n" \
    L"  · 配置自动保存 vpn-gui.ini（密码混淆），下次启动自动回填\n" \
    L"  · 内嵌图标与 EXE 版本信息，单实例运行\n" \
    L"\n" \
    L"v1.0.x\n" \
    L"  · SSTP 客户端（MS-CHAPv2 + Crypto-Binding + IPCP + Wintun 转发）\n" \
    L"  · L2TP / PPTP 基础支持，DNS 由服务器下发并写入网卡"

#define ABOUT_EN_TEXT \
    L"tunnel-client v" APP_VERSION_W L"\n" \
    L"Author: wwm      Contact: szwwmz@gmail.com      Protocols: SSTP / L2TP / PPTP\n" \
    L"\n" \
    L"v1.4.0\n" \
    L"  - Bilingual UI (Chinese/English): switch from the banner chip in the\n" \
    L"    top-right corner or the tray menu; the choice is saved to\n" \
    L"    vpn-gui.ini (lang=zh|en) and restored on next start\n" \
    L"  - Connection logs and error messages are now English-only\n" \
    L"  - Fixed undefined behaviour (in-place memcpy overlap) when building\n" \
    L"    CALL_CONNECTED\n" \
    L"  - Fixed silent truncation of L2TP/IPsec host names longer than 63\n" \
    L"    characters (IKE host field 64 -> 256 bytes)\n" \
    L"\n" \
    L"Older entries are listed in the Chinese release notes."

static const wchar_t *const STR_TAB[S_COUNT][2] = {
    [S_APP_NAME]        = { L"tunnel-client", L"tunnel-client" },
    [S_ABOUT_TITLE]     = { L"版本说明", L"Release notes" },
    [S_ABOUT]           = { ABOUT_ZH_TEXT, ABOUT_EN_TEXT },
    [S_PROTO]           = { L"协议", L"Protocol" },
    [S_SERVER]          = { L"服务器", L"Server" },
    [S_PORT]            = { L"端口", L"Port" },
    [S_USER]            = { L"用户名", L"User" },
    [S_PASS]            = { L"密码", L"Password" },
    [S_CERT]            = { L"证书", L"Cert" },
    [S_CERT_VERIFY]     = { L"校验", L"Verify" },
    [S_CERT_IGNORE]     = { L"忽略", L"Ignore" },
    [S_ROUTE_ALL]       = { L"接管全部流量", L"Route all traffic" },
    [S_ROUTE_PRIV]      = { L"接管私有网段", L"Route private ranges" },
    [S_BTN_CONNECT]     = { L"连接", L"Connect" },
    [S_BTN_DISCONNECT]  = { L"断开", L"Disconnect" },
    [S_LOG_TITLE]       = { L"运行日志", L"Log" },
    [S_LOG_HINT]        = { L"同步写入 exe 目录 vpn-gui.log", L"also written to vpn-gui.log next to the exe" },
    [S_LOG_CLEAR]       = { L"清除日志", L"Clear log" },
    [S_LOG_COPY]        = { L"复制全部", L"Copy all" },
    [S_CARD_NOTE]       = { L"私有网段：10.0.0.0/8、172.16.0.0/12、192.168.0.0/16"
                            L"    ·    优先级低于本机既有路由，不影响本地网络互访",
                            L"Private ranges 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16"
                            L"    ·    lower priority than existing routes, LAN access unaffected" },
    [S_BANNER_META]     = { L"SSTP / L2TP / PPTP      v%ls      作者 %ls",
                            L"SSTP / L2TP / PPTP      v%ls      by %ls" },
    [S_FOOTER]          = { L"tunnel-client v%ls    ·    作者 %ls <" APP_MAIL_W L">",
                            L"tunnel-client v%ls    ·    by %ls <" APP_MAIL_W L">" },
    [S_TRAY_SHOW]       = { L"显示主界面", L"Show window" },
    [S_TRAY_CONNECT]    = { L"连接", L"Connect" },
    [S_TRAY_DISCONNECT] = { L"断开", L"Disconnect" },
    [S_TRAY_ABOUT]      = { L"版本说明", L"Release notes" },
    [S_TRAY_EXIT]       = { L"退出", L"Exit" },
    [S_LANG_MENU]       = { L"语言 / Language", L"Language / 语言" },
    [S_LANG_ZH]         = { L"中文", L"中文 (Chinese)" },
    [S_LANG_EN]         = { L"English", L"English" },
    [S_ST_CONNECTING]   = { L"连接中", L"Connecting" },
    [S_ST_AUTH]         = { L"认证中", L"Authenticating" },
    [S_ST_CONNECTED]    = { L"已连接", L"Connected" },
    [S_ST_RECONNECTING] = { L"重连中", L"Reconnecting" },
    [S_ST_DISCONNECTED] = { L"已断开", L"Disconnected" },
    [S_ST_FAILED]       = { L"连接失败", L"Failed" },
    [S_ST_IDLE]         = { L"未连接", L"Not connected" },
    [S_MSG_NEED_HOST]   = { L"请填写服务器地址", L"Please enter the server address" },
    [S_MSG_TITLE]       = { L"提示", L"Notice" },
    [S_CLOSE_TITLE]     = { L"tunnel-client 仍在运行", L"tunnel-client is still running" },
    [S_CLOSE_BODY]      = { L"已最小化到托盘，双击图标可恢复窗口；托盘菜单可退出。",
                            L"Minimized to the tray. Double-click the icon to restore it; use the tray menu to exit." },
};

#define T(id) (STR_TAB[(id)][g_lang])

/* 统计行用窄字符格式化，避免多一次宽窄转换 */
static const char *stat_ip_fmt(void)
{
    return g_lang == LANG_EN ? "IP  %s      GW  %s      DNS  %s"
                             : "IP  %s      网关  %s      DNS  %s";
}

static const char *stat_traffic_fmt(void)
{
    return g_lang == LANG_EN ? "RX %.1f KB    TX %.1f KB    reconnects %lu"
                             : "收 %.1f KB    发 %.1f KB    重连 %lu";
}

#define IDC_PROTO      1001
#define IDC_HOST       1002
#define IDC_PORT       1003
#define IDC_USER       1004
#define IDC_PASS       1005
#define IDC_CERT       1006
#define IDC_MTU        1007
#define IDC_ROUTEALL   1008
#define IDC_ROUTEPRIV  1009
#define IDC_LOG        1012

#define IDI_APP        101

#define IDM_SHOW       2001
#define IDM_CONNECT    2002
#define IDM_DISCONNECT 2003
#define IDM_EXIT       2004
#define IDM_ABOUT      2005
#define IDM_LANG_ZH    2006
#define IDM_LANG_EN    2007
#define IDM_LOG_CLEAR  2010
#define IDM_LOG_COPY   2011

#define WM_TRAY        (WM_APP + 1)
#define TIMER_UI       1

/* 布局（客户区像素） */
#define WIN_W          780
#define WIN_H          700
#define BANNER_H       78
#define CARD_X         20
#define CARD_Y         94
#define CARD_W         740
#define CARD_H         214
#define LOG_X          20
#define LOG_Y          340
#define LOG_W          740
#define LOG_H          300
#define ROW1_Y         112
#define ROW2_Y         152
#define ROW3_Y         186
#define CTL_H          26

/* 配色 */
#define C_BG           RGB(0xF0, 0xF3, 0xF8)
#define C_CARD         RGB(0xFF, 0xFF, 0xFF)
#define C_BORDER       RGB(0xD8, 0xDF, 0xE9)
#define C_TEXT         RGB(0x24, 0x2F, 0x3D)
#define C_SUBTEXT      RGB(0x5B, 0x6A, 0x7D)
#define C_PRIMARY      RGB(0x2B, 0x6C, 0xB8)
#define C_PRIMARY_HI   RGB(0x35, 0x7F, 0xD1)
#define C_NEUTRAL      RGB(0xE8, 0xED, 0xF3)
#define C_NEUTRAL_HI   RGB(0xDA, 0xE1, 0xEA)
#define C_LOGBG        RGB(0x1B, 0x1F, 0x27)
#define C_LOGTX        RGB(0xC8, 0xD2, 0xDC)
#define C_GREEN        RGB(0x2F, 0xBF, 0x71)
#define C_YELLOW       RGB(0xF0, 0xB4, 0x29)
#define C_RED          RGB(0xE5, 0x48, 0x4D)
#define C_GRAY         RGB(0x9A, 0xA5, 0xB1)

#define LOG_RING 128
#define LOG_LINE 512

static HWND g_hwnd, g_hProto, g_hHost, g_hPort, g_hPortLabel, g_hUser, g_hPass, g_hCert;
static HWND g_hMtu, g_hRouteAll, g_hRoutePriv, g_hLog;
static HINSTANCE g_inst;

/* 字体与画刷 */
static HFONT g_font, g_font_small, g_font_bold, g_font_title, g_font_mono;
static HBRUSH g_br_card, g_br_log;
static HICON g_icon_big;

/* 自绘按钮 */
typedef struct {
    RECT rc;
    const wchar_t *text;
    int primary;      /* 1=主色按钮 */
    int enabled;
} gui_btn;
static gui_btn g_btn_conn, g_btn_disc;
static int g_hover = -1, g_press = -1;

/* 自绘状态（初值由 lang_apply() 按当前语言填入） */
static wchar_t g_status_text[512] = L"";
static wchar_t g_stat_line[512] = L"";
static wchar_t g_stat2_line[512] = L"";

/* 语言切换：标题栏右上角两枚胶囊的热区，draw_banner() 负责更新 */
static RECT g_lang_zh_rc = { 660, 50, 706, 72 };
static RECT g_lang_en_rc = { 712, 50, 758, 72 };

/* 需要跟随语言切换的静态文本控件（标签），on_create 里登记 */
#define MAX_LABELS 12
static struct { HWND h; int id; } g_labels[MAX_LABELS];
static int g_label_n;

static void lang_apply(void);

/* 自绘输入框底纹（控件本身无边框），记录矩形供 WM_PAINT 使用 */
#define MAX_FIELDS 8
static RECT g_fields[MAX_FIELDS];
static int g_field_n;
static int g_port_field_idx = -1;   /* 端口框在 g_fields 里的下标，隐藏时跳过绘制 */
static COLORREF g_stat_color = C_GRAY;
static int g_ui_running;

/* 托盘 */
static NOTIFYICONDATAW g_nid;
static int g_tray_added;
static int g_allow_close;   /* 1 = 真正退出 */

static char g_host[256], g_user[128], g_pass[128], g_dns[64];
static int g_mtu;

static vpn_handle g_h;
static vpn_tun_ops g_tun;
static int g_has_tun;
static char g_tun_name[128];
static char g_last_ip[32];
static int g_net_configured;
static int g_was_connected;
static unsigned long g_last_state;

/* 配置字符串放在静态区：capi 只保存指针，不能指向栈上的临时缓冲 */
static char g_host[256], g_user[128], g_pass[128], g_dns[64];
static int g_mtu;

/* ---------------- 日志环形缓冲 ---------------- */

static CRITICAL_SECTION g_log_cs;
static char g_log[LOG_RING][LOG_LINE];
static int g_log_w, g_log_r;

/* 同步写盘的日志文件：GUI 无控制台，进程异常退出时界面日志会全部丢失 */
static FILE *g_flog;

static void log_file_open(void)
{
    wchar_t wpath[MAX_PATH];
    char dir[MAX_PATH * 4], path[MAX_PATH * 4];
    wchar_t *slash;

    if (!GetModuleFileNameW(NULL, wpath, MAX_PATH))
        return;
    slash = wcsrchr(wpath, L'\\');
    if (slash)
        slash[1] = 0;
    if (WideCharToMultiByte(CP_UTF8, 0, wpath, -1, dir, sizeof(dir), NULL, NULL) <= 0)
        return;
    snprintf(path, sizeof(path), "%svpn-gui.log", dir);
    g_flog = fopen(path, "a");
    if (g_flog)
        fprintf(g_flog, "===== start =====\n");
}

static void log_fmt(const char *fmt, ...)
{
    va_list ap;
    char tmp[LOG_LINE];

    va_start(ap, fmt);
    vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    tmp[sizeof(tmp) - 1] = 0;

    EnterCriticalSection(&g_log_cs);
    snprintf(g_log[g_log_w % LOG_RING], LOG_LINE, "%s", tmp);
    g_log_w++;
    if (g_flog) {
        fprintf(g_flog, "%s\n", tmp);
        fflush(g_flog);
    }
    LeaveCriticalSection(&g_log_cs);
}

/* 崩溃兜底：把异常码与地址落盘，避免"程序自己消失"无从查证 */
static LONG WINAPI crash_filter(EXCEPTION_POINTERS *ep)
{
    if (g_flog && ep && ep->ExceptionRecord) {
        fprintf(g_flog, "[崩溃] 异常码 0x%08lX 发生地址 %p\n",
                (unsigned long)ep->ExceptionRecord->ExceptionCode,
                ep->ExceptionRecord->ExceptionAddress);
        fflush(g_flog);
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

static void on_log(int level, const char *msg, void *user)
{
    /* 必须与 vpn_log_level 枚举顺序一致（0=TRACE 1=DEBUG 2=INFO
     * 3=WARN 4=ERROR），旧表按相反顺序写，导致 WARN 显示成[调试]、
     * DEBUG 显示成[警告] */
    /* 日志统一英文（与 core 输出一致），不随界面语言切换 */
    static const char *tag[] = { "TRACE", "DEBUG", "INFO", "WARN", "ERROR" };
    (void)user;
    log_fmt("[%s] %s", (level >= 0 && level <= 4) ? tag[level] : "LOG", msg ? msg : "");
}

static void on_state(int state, const char *detail, void *user)
{
    (void)user;
    log_fmt("[STATE] %s%s%s", vpn_capi_state_name(state),
            (detail && detail[0]) ? " - " : "", detail ? detail : "");
}

/* ---------------- 控件辅助 ---------------- */

static void get_text(HWND h, char *out, int outn)
{
    wchar_t w[512];
    GetWindowTextW(h, w, 512);
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out, outn, NULL, NULL);
    out[outn - 1] = 0;
}

static void u8_to_w(const char *s, wchar_t *out, int outn)
{
    if (!out || outn <= 0)
        return;
    out[0] = 0;
    if (!s)
        return;
    MultiByteToWideChar(CP_UTF8, 0, s, -1, out, outn);
    out[outn - 1] = 0;
}

static const wchar_t *state_name(int state)
{
    switch (state) {
    case VPN_CAPI_STATE_CONNECTING:
        return T(S_ST_CONNECTING);
    case VPN_CAPI_STATE_AUTHENTICATING:
        return T(S_ST_AUTH);
    case VPN_CAPI_STATE_CONNECTED:
        return T(S_ST_CONNECTED);
    case VPN_CAPI_STATE_RECONNECTING:
        return T(S_ST_RECONNECTING);
    case VPN_CAPI_STATE_DISCONNECTED:
        return T(S_ST_DISCONNECTED);
    case VPN_CAPI_STATE_FAILED:
        return T(S_ST_FAILED);
    default:
        return T(S_ST_IDLE);
    }
}

static COLORREF state_color(int state)
{
    switch (state) {
    case VPN_CAPI_STATE_CONNECTED:
        return C_GREEN;
    case VPN_CAPI_STATE_CONNECTING:
    case VPN_CAPI_STATE_AUTHENTICATING:
    case VPN_CAPI_STATE_RECONNECTING:
        return C_YELLOW;
    case VPN_CAPI_STATE_FAILED:
        return C_RED;
    default:
        return C_GRAY;
    }
}

static void tray_tip(const wchar_t *s);
static void update_status(void);
static void config_save(void);

/* ---------------- 语言切换 ---------------- */

static void lbl_add(HWND h, int id)
{
    if (h && g_label_n < MAX_LABELS) {
        g_labels[g_label_n].h = h;
        g_labels[g_label_n].id = id;
        g_label_n++;
    }
}

/* 无连接时的状态/统计行（随语言变化） */
static void reset_status_lines(void)
{
    char line[512];

    wcscpy(g_status_text, T(S_ST_IDLE));
    snprintf(line, sizeof(line), stat_ip_fmt(), "-", "-", "-");
    u8_to_w(line, g_stat_line, 512);
    snprintf(line, sizeof(line), stat_traffic_fmt(), 0.0, 0.0, 0UL);
    u8_to_w(line, g_stat2_line, 512);
}

static void tray_tip_status(void)
{
    wchar_t tip[256];

    swprintf(tip, 256, L"%ls - %ls", T(S_APP_NAME), g_status_text);
    tray_tip(tip);
}

/* 把当前语言应用到所有控件与自绘文本 */
static void lang_apply(void)
{
    wchar_t title[256];
    int i, sel;

    for (i = 0; i < g_label_n; i++)
        SetWindowTextW(g_labels[i].h, T(g_labels[i].id));

    if (g_hCert) {
        sel = (int)SendMessageW(g_hCert, CB_GETCURSEL, 0, 0);
        SendMessageW(g_hCert, CB_RESETCONTENT, 0, 0);
        SendMessageW(g_hCert, CB_ADDSTRING, 0, (LPARAM)T(S_CERT_VERIFY));
        SendMessageW(g_hCert, CB_ADDSTRING, 0, (LPARAM)T(S_CERT_IGNORE));
        SendMessageW(g_hCert, CB_SETCURSEL, sel < 0 ? 1 : sel, 0);
    }
    if (g_hRouteAll)
        SetWindowTextW(g_hRouteAll, T(S_ROUTE_ALL));
    if (g_hRoutePriv)
        SetWindowTextW(g_hRoutePriv, T(S_ROUTE_PRIV));

    g_btn_conn.text = T(S_BTN_CONNECT);
    g_btn_disc.text = T(S_BTN_DISCONNECT);

    if (g_hwnd) {
        swprintf(title, 256, L"%ls v%ls  -  SSTP / L2TP / PPTP",
                 T(S_APP_NAME), APP_VERSION_W);
        SetWindowTextW(g_hwnd, title);
    }

    if (g_h)
        update_status();
    else {
        reset_status_lines();
        tray_tip_status();
    }
    if (g_hwnd)
        InvalidateRect(g_hwnd, NULL, TRUE);
}

/* 切换语言：立即生效并写入 ini */
static void set_language(int lang)
{
    if (lang != LANG_ZH && lang != LANG_EN)
        return;
    if (lang == g_lang)
        return;
    g_lang = lang;
    config_save();
    lang_apply();
}

/* ---------------- 日志控件右键菜单 ---------------- */

static WNDPROC g_log_orig_proc;

static void log_copy_all(HWND h)
{
    int n = GetWindowTextLengthW(h);
    HGLOBAL g;
    wchar_t *buf;

    if (n <= 0)
        return;
    g = GlobalAlloc(GMEM_MOVEABLE, (SIZE_T)(n + 1) * sizeof(wchar_t));
    if (!g)
        return;
    buf = (wchar_t *)GlobalLock(g);
    if (!buf) {
        GlobalFree(g);
        return;
    }
    GetWindowTextW(h, buf, n + 1);
    GlobalUnlock(g);
    if (OpenClipboard(h)) {
        EmptyClipboard();
        if (!SetClipboardData(CF_UNICODETEXT, g))
            GlobalFree(g);
        CloseClipboard();
        return;
    }
    GlobalFree(g);
}

/* EDIT 控件默认的右键菜单只有复制/全选，这里换成自己的菜单，
 * 增加“清除日志”，避免长日志只能重启程序才能清空 */
static LRESULT CALLBACK log_ctrl_proc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    /* 只在 WM_CONTEXTMENU 里弹菜单：EDIT 在 WM_RBUTTONUP 阶段不弹，
     * 两处都处理会导致右键出现两个菜单 */
    if (msg == WM_CONTEXTMENU) {
        POINT pt;
        HMENU m;
        BOOL ok = FALSE;

        if (lp != (LPARAM)-1) {
            pt.x = GET_X_LPARAM(lp);
            pt.y = GET_Y_LPARAM(lp);
        } else {
            RECT r;

            GetCursorPos(&pt);
            GetWindowRect(h, &r);
            if (!PtInRect(&r, pt)) {
                pt.x = r.left + 16;
                pt.y = r.top + 16;
            }
        }
        m = CreatePopupMenu();
        if (!m)
            return 0;
        AppendMenuW(m, MF_STRING, IDM_LOG_CLEAR, T(S_LOG_CLEAR));
        AppendMenuW(m, MF_STRING, IDM_LOG_COPY, T(S_LOG_COPY));
        SetForegroundWindow(h);
        ok = TrackPopupMenu(m, TPM_LEFTALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD,
                            pt.x, pt.y, 0, h, NULL);
        DestroyMenu(m);
        if (ok == IDM_LOG_CLEAR)
            SetWindowTextW(h, L"");
        else if (ok == IDM_LOG_COPY)
            log_copy_all(h);
        return 0;
    }
    if (msg == WM_KEYDOWN && wp == VK_ESCAPE)
        return 0;
    return CallWindowProcW(g_log_orig_proc, h, msg, wp, lp);
}

static void log_line_ui(const wchar_t *line)
{
    int len;

    if (!g_hLog)
        return;
    len = GetWindowTextLengthW(g_hLog);
    SendMessageW(g_hLog, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessageW(g_hLog, EM_REPLACESEL, FALSE, (LPARAM)line);
    SendMessageW(g_hLog, EM_REPLACESEL, FALSE, (LPARAM)L"\r\n");
}

static void pump_log_to_ui(void)
{
    wchar_t w[LOG_LINE];
    int count = 0;

    for (;;) {
        char line[LOG_LINE];

        EnterCriticalSection(&g_log_cs);
        if (g_log_r >= g_log_w) {
            LeaveCriticalSection(&g_log_cs);
            break;
        }
        snprintf(line, sizeof(line), "%s", g_log[g_log_r % LOG_RING]);
        g_log_r++;
        LeaveCriticalSection(&g_log_cs);

        MultiByteToWideChar(CP_UTF8, 0, line, -1, w, LOG_LINE);
        log_line_ui(w);
        if (++count >= 32) /* 每次最多刷 32 行，避免日志洪水卡死 UI */
            break;
    }
}

/* ---------------- TUN 回调包装（GUI 持有 wintun 会话） ---------------- */

static int tun_read_cb(void *ctx, uint8_t *buf, int cap, int timeout_ms)
{
    (void)ctx;
    if (!g_has_tun || !g_tun.read)
        return 0;
    return g_tun.read(g_tun.ctx, buf, (size_t)cap, timeout_ms);
}

static int tun_write_cb(void *ctx, const uint8_t *buf, int len)
{
    (void)ctx;
    if (!g_has_tun || !g_tun.write)
        return -1;
    return g_tun.write(g_tun.ctx, buf, (size_t)len);
}

/* ---------------- 配置文件（exe 同目录 vpn-gui.ini） ---------------- */

/* 每种协议各记一个端口：只有 SSTP 的端口是可随意改（伪装 443 提穿透），
 * L2TP/PPTP 的服务端固定监听 UDP/1701、TCP/1723，沿用 SSTP 端口必然连不上 */
static int g_proto_port[3] = { 443, 1701, 1723 };   /* 索引同协议枚举：SSTP/L2TP/PPTP */
static int g_port_owner = 0;                        /* 端口输入框当前值归属的协议 */

static int g_cfg_proto = 0, g_cfg_port = 443, g_cfg_cert = 1, g_cfg_mtu = 1400;
static int g_cfg_routeall, g_cfg_routepriv, g_cfg_vpndns = 1;
/* 调试日志开关：ini 里 debug=0/1，默认 0。开启后才会出现逐包诊断，
 * 平时只保留连接过程的关键节点，避免日志被噪声淹没 */
static int g_cfg_debug = 0;
static char g_cfg_host[256], g_cfg_user[128], g_cfg_pass[128];

/* L2TP/PPTP 端口写死，只有 SSTP 允许改 */
static int proto_fixed_port(int proto)
{
    if (proto == 1)
        return 1701;   /* L2TP  UDP/1701 */
    if (proto == 2)
        return 1723;   /* PPTP  TCP/1723 */
    return 0;          /* SSTP  可配置 */
}

static void update_port_edit_state(void)
{
    int sel = g_hProto ? (int)ComboBox_GetCurSel(g_hProto) : 0;
    int sstp = (sel == 0);

    /* L2TP/PPTP 端口固定，输入框连同标签一起隐藏，不给用户改的机会 */
    if (g_hPortLabel)
        ShowWindow(g_hPortLabel, sstp ? SW_SHOW : SW_HIDE);
    if (g_hPort) {
        ShowWindow(g_hPort, sstp ? SW_SHOW : SW_HIDE);
        EnableWindow(g_hPort, sstp);
    }
}

/* 切换协议时保存 SSTP 自定义端口、载入新协议端口 */
static void proto_port_sync(int new_proto)
{
    char buf[32];
    wchar_t w[32];
    int p, fixed;

    if (new_proto < 0 || new_proto > 2)
        new_proto = 0;

    if (g_hPort && g_port_owner == 0) {   /* 只有 SSTP 的值值得保留 */
        get_text(g_hPort, buf, sizeof(buf));
        p = atoi(buf);
        if (p > 0 && p < 65536)
            g_proto_port[0] = p;
    }

    g_port_owner = new_proto;
    fixed = proto_fixed_port(new_proto);
    if (fixed)
        g_proto_port[new_proto] = fixed;

    snprintf(buf, sizeof(buf), "%d", g_proto_port[new_proto]);
    u8_to_w(buf, w, 32);
    if (g_hPort)
        SetWindowTextW(g_hPort, w);
    update_port_edit_state();
}

static void exe_dir(wchar_t *dir, int n)
{
    wchar_t *p;

    GetModuleFileNameW(NULL, dir, n);
    dir[n - 1] = 0;
    p = wcsrchr(dir, L'\\');
    if (p)
        p[1] = 0;
}

static void app_path(const wchar_t *name, wchar_t *out, int n)
{
    wchar_t dir[MAX_PATH];

    exe_dir(dir, MAX_PATH);
    _snwprintf(out, (size_t)n, L"%ls%ls", dir, name);
    out[n - 1] = 0;
}

static int hex_val(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* 密码做轻量混淆（异或 + 十六进制），避免明文躺在 ini 里 */
static void obf_enc(const char *in, char *out, int n)
{
    static const char hx[] = "0123456789abcdef";
    int i, o = 0;

    if (n <= 0)
        return;
    for (i = 0; in && in[i] && o + 3 < n; i++) {
        unsigned char c = (unsigned char)in[i] ^ 0x5A;
        out[o++] = hx[c >> 4];
        out[o++] = hx[c & 15];
    }
    out[o] = 0;
}

static void obf_dec(const char *in, char *out, int n)
{
    int i, o = 0;

    if (n <= 0)
        return;
    out[0] = 0;
    if (!in)
        return;
    for (i = 0; in[i] && in[i + 1] && o + 1 < n; i += 2) {
        int hi = hex_val((unsigned char)in[i]);
        int lo = hex_val((unsigned char)in[i + 1]);
        if (hi < 0 || lo < 0)
            break;
        out[o++] = (char)((unsigned char)((hi << 4) | lo) ^ 0x5A);
    }
    out[o] = 0;
}

static char *str_trim(char *s)
{
    char *e;

    while (*s == ' ' || *s == '\t')
        s++;
    e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' || e[-1] == '\n'))
        *--e = 0;
    return s;
}

static void config_load(void)
{
    wchar_t wp[MAX_PATH];
    char line[1024], pass_obf[512];
    FILE *f;
    int seen[3] = { 0, 0, 0 };

    pass_obf[0] = 0;
    app_path(L"vpn-gui.ini", wp, MAX_PATH);
    f = _wfopen(wp, L"rb");
    if (!f)
        return;   /* 无配置文件：保持内置默认端口 443/1701/1723 */
    g_cfg_port = 0;
    g_proto_port[0] = g_proto_port[1] = g_proto_port[2] = 0;
    while (fgets(line, sizeof(line), f)) {
        char *eq = strchr(line, '=');
        char *k, *v;

        if (!eq || line[0] == ';' || line[0] == '#' || line[0] == '[')
            continue;
        *eq = 0;
        k = str_trim(line);
        v = str_trim(eq + 1);
        if (!strcmp(k, "proto"))
            g_cfg_proto = atoi(v);
        else if (!strcmp(k, "host"))
            snprintf(g_cfg_host, sizeof(g_cfg_host), "%s", v);
        else if (!strcmp(k, "port0")) {
            g_proto_port[0] = atoi(v);
            seen[0] = 1;
        } else if (!strcmp(k, "port1")) {
            g_proto_port[1] = atoi(v);
            seen[1] = 1;
        } else if (!strcmp(k, "port2")) {
            g_proto_port[2] = atoi(v);
            seen[2] = 1;
        } else if (!strcmp(k, "port"))
            g_cfg_port = atoi(v);   /* 旧版单端口键，见下方纠偏 */
        else if (!strcmp(k, "user"))
            snprintf(g_cfg_user, sizeof(g_cfg_user), "%s", v);
        else if (!strcmp(k, "pass"))
            snprintf(pass_obf, sizeof(pass_obf), "%s", v);
        else if (!strcmp(k, "cert"))
            g_cfg_cert = atoi(v);
        else if (!strcmp(k, "mtu"))
            g_cfg_mtu = atoi(v);
        else if (!strcmp(k, "routeall"))
            g_cfg_routeall = atoi(v);
        else if (!strcmp(k, "routepriv"))
            g_cfg_routepriv = atoi(v);
        else if (!strcmp(k, "vpndns"))
            g_cfg_vpndns = atoi(v);
        else if (!strcmp(k, "debug"))
            g_cfg_debug = atoi(v) ? 1 : 0;
        else if (!strcmp(k, "lang"))
            g_lang = (v[0] == 'e' || v[0] == 'E') ? LANG_EN : LANG_ZH;
    }
    fclose(f);
    obf_dec(pass_obf, g_cfg_pass, sizeof(g_cfg_pass));

    if (g_cfg_proto < 0 || g_cfg_proto > 2)
        g_cfg_proto = 0;

    /* 旧版 ini 只有一个 port=，那是各协议混用留下的值（典型：L2TP/PPTP 里
     * 残留了 SSTP 的 446），只能当成 SSTP 端口，绝不能喂给 1701/1723 的协议 */
    if (!seen[0] && g_cfg_port > 0 && g_cfg_port < 65536)
        g_proto_port[0] = g_cfg_port;

    {
        int i;

        for (i = 0; i < 3; i++) {
            if (proto_fixed_port(i))
                g_proto_port[i] = proto_fixed_port(i);   /* 固定协议，忽略 ini 值 */
            else if (g_proto_port[i] <= 0 || g_proto_port[i] > 65535)
                g_proto_port[i] = 443;
        }
    }
    g_cfg_port = g_proto_port[g_cfg_proto];
}

static void config_save(void)
{
    wchar_t wp[MAX_PATH];
    char buf[64], pass_obf[512];
    FILE *f;

    if (!g_hHost || !g_hProto || !g_hCert || !g_hMtu || !g_hRouteAll)
        return;

    get_text(g_hHost, g_cfg_host, sizeof(g_cfg_host));
    get_text(g_hUser, g_cfg_user, sizeof(g_cfg_user));
    get_text(g_hPass, g_cfg_pass, sizeof(g_cfg_pass));

    g_cfg_proto = ComboBox_GetCurSel(g_hProto);
    if (g_cfg_proto < 0 || g_cfg_proto > 2)
        g_cfg_proto = 0;
    get_text(g_hPort, buf, sizeof(buf));
    g_cfg_port = atoi(buf);
    if (proto_fixed_port(g_cfg_proto))
        g_cfg_port = proto_fixed_port(g_cfg_proto);   /* L2TP/PPTP 端口固定 */
    else if (g_cfg_port <= 0)
        g_cfg_port = g_proto_port[0];
    g_proto_port[g_cfg_proto] = g_cfg_port;
    g_cfg_cert = ComboBox_GetCurSel(g_hCert) ? 1 : 0;
    get_text(g_hMtu, buf, sizeof(buf));
    g_cfg_mtu = atoi(buf);
    if (g_cfg_mtu <= 0)
        g_cfg_mtu = 1400;
    g_cfg_routeall = (Button_GetCheck(g_hRouteAll) == BST_CHECKED) ? 1 : 0;
    g_cfg_routepriv = (g_hRoutePriv &&
                       Button_GetCheck(g_hRoutePriv) == BST_CHECKED) ? 1 : 0;

    app_path(L"vpn-gui.ini", wp, MAX_PATH);
    f = _wfopen(wp, L"wb");
    if (!f)
        return;
    obf_enc(g_cfg_pass, pass_obf, sizeof(pass_obf));
    fprintf(f, "; VPN client configuration (generated automatically, by wwm <szwwmz@gmail.com>)\n");
    fprintf(f, "; debug=1 enables per-packet debug logging (restart required); keep 0 normally\n");
    fprintf(f, "debug=%d\n", g_cfg_debug);
    fprintf(f, "; lang: zh = Chinese UI, en = English UI\n");
    fprintf(f, "lang=%s\n", g_lang == LANG_EN ? "en" : "zh");
    fprintf(f, "proto=%d\n", g_cfg_proto);
    fprintf(f, "host=%s\n", g_cfg_host);
    fprintf(f, "port=%d\n", g_cfg_port);
    fprintf(f, "port0=%d\n", g_proto_port[0]);
    fprintf(f, "port1=%d\n", g_proto_port[1]);
    fprintf(f, "port2=%d\n", g_proto_port[2]);
    fprintf(f, "user=%s\n", g_cfg_user);
    fprintf(f, "pass=%s\n", pass_obf);
    fprintf(f, "cert=%d\n", g_cfg_cert);
    fprintf(f, "mtu=%d\n", g_cfg_mtu);
    fprintf(f, "routeall=%d\n", g_cfg_routeall);
    fprintf(f, "routepriv=%d\n", g_cfg_routepriv);
    fprintf(f, "vpndns=%d\n", g_cfg_vpndns);
    fclose(f);
}

static void apply_config_to_ui(void)
{
    wchar_t w[512];
    char buf[32];

    if (!g_hProto)
        return;

    g_mtu = (g_cfg_mtu > 0) ? g_cfg_mtu : 1400;
    {
        int sel = (g_cfg_proto < 0 || g_cfg_proto > 2) ? 0 : g_cfg_proto;

        SendMessageW(g_hProto, CB_SETCURSEL, (WPARAM)sel, 0);
        if (g_proto_port[sel] <= 0)
            g_proto_port[sel] = (sel == 0) ? 443 : ((sel == 1) ? 1701 : 1723);
        g_port_owner = sel;
        u8_to_w(g_cfg_host, w, 512);
        SetWindowTextW(g_hHost, w);
        snprintf(buf, sizeof(buf), "%d", g_proto_port[sel]);
        u8_to_w(buf, w, 512);
        SetWindowTextW(g_hPort, w);
        update_port_edit_state();
    }
    u8_to_w(g_cfg_user, w, 512);
    SetWindowTextW(g_hUser, w);
    u8_to_w(g_cfg_pass, w, 512);
    SetWindowTextW(g_hPass, w);
    SendMessageW(g_hCert, CB_SETCURSEL, (WPARAM)(g_cfg_cert ? 1 : 0), 0);
    snprintf(buf, sizeof(buf), "%d", g_mtu);
    u8_to_w(buf, w, 512);
    SetWindowTextW(g_hMtu, w);
    Button_SetCheck(g_hRouteAll, g_cfg_routeall ? BST_CHECKED : BST_UNCHECKED);
    if (g_hRoutePriv)
        Button_SetCheck(g_hRoutePriv, g_cfg_routepriv ? BST_CHECKED : BST_UNCHECKED);
}

/* ---------------- 连接/断开 ---------------- */

static void set_ui_running(int running)
{
    HWND ctl[] = { g_hProto, g_hHost, g_hPort, g_hUser, g_hPass,
                   g_hCert, g_hMtu, g_hRouteAll, g_hRoutePriv };
    size_t i;

    g_ui_running = running;
    for (i = 0; i < sizeof(ctl) / sizeof(ctl[0]); i++)
        if (ctl[i])
            EnableWindow(ctl[i], !running);
    g_btn_conn.enabled = !running;
    g_btn_disc.enabled = running;
    if (!running)
        update_port_edit_state();   /* 恢复后仍按协议决定端口框是否可用 */
    if (g_hwnd) {
        InvalidateRect(g_hwnd, &g_btn_conn.rc, FALSE);
        InvalidateRect(g_hwnd, &g_btn_disc.rc, FALSE);
    }
}

/* ---------------- 路由下发 ---------------- */

/* 私有网段路由的 metric：远大于本机直连/默认路由（通常 25 上下），
 * 同前缀时本机路由优先；更具体的前缀按最长匹配也先走本机，不影响本地互访 */
#define PRIV_ROUTE_METRIC 6000

static const struct {
    uint32_t net;
    uint32_t mask;
    const char *name;
} g_priv_nets[] = {
    { 0x0A000000u, 0xFF000000u, "10.0.0.0/8" },
    { 0xAC100000u, 0xFFF00000u, "172.16.0.0/12" },
    { 0xC0A80000u, 0xFFFF0000u, "192.168.0.0/16" },
};

static int g_route_all_on, g_route_priv_on;

/* 只接管私有网段时，服务器下发的 DNS 若落在这三个网段之外，
 * 必须单独补一条 /32 路由，否则系统的 DNS 查询会从物理网卡出去（永远解析不到） */
static uint32_t g_dns_routes[2];
static int g_dns_route_n;

static int is_priv_addr(uint32_t be)
{
    uint32_t h = ntohl(be);

    if ((h & 0xFF000000u) == 0x0A000000u) return 1;   /* 10.0.0.0/8 */
    if ((h & 0xFFF00000u) == 0xAC100000u) return 1;   /* 172.16.0.0/12 */
    if ((h & 0xFFFF0000u) == 0xC0A80000u) return 1;   /* 192.168.0.0/16 */
    return 0;
}

static void dns_routes_clear(void)
{
    while (g_dns_route_n > 0) {
        uint32_t a = g_dns_routes[--g_dns_route_n];

        if (g_tun_name[0])
            vpn_tun_del_route(g_tun_name, a, htonl(0xFFFFFFFFu));
    }
}

static void routes_apply(int want_all, int want_priv)
{
    size_t i, n = sizeof(g_priv_nets) / sizeof(g_priv_nets[0]);

    if (!g_tun_name[0])
        return;

    /* 先清掉本接口上可能残留的 0.0.0.0/0（旧版本写错过前缀，会变成默认路由） */
    vpn_tun_del_route(g_tun_name, 0, 0);

    /* 全部流量：先删后加，避免重连换地址后残留旧条目 */
    if (want_all) {
        vpn_tun_del_route(g_tun_name, 0, 0);
        if (vpn_tun_add_route_via(g_tun_name, 0, 0, 0) == VPN_OK) {
            g_route_all_on = 1;
            log_fmt("[INFO] route all traffic taken over (0.0.0.0/0 -> %s)", g_tun_name);
        } else {
            log_fmt("[WARN] failed to take over all traffic (administrator rights missing?)");
        }
    } else if (g_route_all_on) {
        vpn_tun_del_route(g_tun_name, 0, 0);
        g_route_all_on = 0;
        log_fmt("[INFO] all-traffic routing reverted");
    }

    /* 私有网段 */
    if (want_priv) {
        for (i = 0; i < n; i++) {
            uint32_t net = htonl(g_priv_nets[i].net);
            uint32_t mask = htonl(g_priv_nets[i].mask);

            vpn_tun_del_route(g_tun_name, net, mask);
            if (vpn_tun_add_route_metric(g_tun_name, net, mask, 0,
                                         PRIV_ROUTE_METRIC) == VPN_OK)
                log_fmt("[INFO] private ranges taken over: %s (metric %d, local routes still win)",
                        g_priv_nets[i].name, PRIV_ROUTE_METRIC);
            else
                log_fmt("[WARN] failed to add the private range %s", g_priv_nets[i].name);
        }
        g_route_priv_on = 1;
    } else if (g_route_priv_on) {
        for (i = 0; i < n; i++)
            vpn_tun_del_route(g_tun_name, htonl(g_priv_nets[i].net),
                              htonl(g_priv_nets[i].mask));
        g_route_priv_on = 0;
        log_fmt("[INFO] private-range routes reverted");
    }
}

static void routes_cleanup(void)
{
    size_t i, n = sizeof(g_priv_nets) / sizeof(g_priv_nets[0]);

    if (!g_tun_name[0])
        return;
    if (g_route_all_on) {
        vpn_tun_del_route(g_tun_name, 0, 0);
        g_route_all_on = 0;
    }
    if (g_route_priv_on) {
        for (i = 0; i < n; i++)
            vpn_tun_del_route(g_tun_name, htonl(g_priv_nets[i].net),
                              htonl(g_priv_nets[i].mask));
        g_route_priv_on = 0;
    }
    dns_routes_clear();
}

static void do_disconnect(void);

static void do_connect(void)
{
    vpn_capi_config cfg;
    vpn_capi_tun ct;
    char port[16], mtu[16], err[256];
    uint32_t ip = 0;
    int rc;

    get_text(g_hHost, g_host, sizeof(g_host));
    if (!g_host[0]) {
        MessageBoxW(g_hwnd, L"请填写服务器地址", L"提示", MB_ICONINFORMATION);
        return;
    }
    get_text(g_hUser, g_user, sizeof(g_user));
    get_text(g_hPass, g_pass, sizeof(g_pass));
    get_text(g_hPort, port, sizeof(port));
    get_text(g_hMtu, mtu, sizeof(mtu));
    g_mtu = atoi(mtu);
    if (g_mtu <= 0)
        g_mtu = 1400;
    g_dns[0] = 0;

    (void)vpn_ip_parse("0.0.0.0", &ip);
    (void)ip;

    memset(&cfg, 0, sizeof(cfg));
    cfg.proto = ComboBox_GetCurSel(g_hProto);
    if (cfg.proto < 0 || cfg.proto > 2)
        cfg.proto = 0;
    cfg.host = g_host;
    cfg.port = atoi(port);
    if (proto_fixed_port(cfg.proto)) {
        /* L2TP/PPTP 端口固定，不看输入框内容 */
        cfg.port = (uint16_t)proto_fixed_port(cfg.proto);
    } else if (cfg.port <= 0) {
        cfg.port = g_proto_port[0];       /* SSTP 留空则用上次的值 */
    }
    if (cfg.port > 0 && cfg.port < 65536)
        g_proto_port[cfg.proto] = cfg.port;
    {
        char pb[16];
        wchar_t wp[16];

        g_port_owner = cfg.proto;
        snprintf(pb, sizeof(pb), "%d", (int)cfg.port);
        MultiByteToWideChar(CP_UTF8, 0, pb, -1, wp, 16);
        SetWindowTextW(g_hPort, wp);
    }
    cfg.username = g_user;
    cfg.password = g_pass;
    cfg.auth = 3; /* auto：优先 MSCHAPv2，兼容 RouterOS 的配置 */
    cfg.cert_mode = ComboBox_GetCurSel(g_hCert);
    cfg.verify_hostname = (cfg.cert_mode == 0) ? 1 : 0;
    cfg.mtu = g_mtu;
    cfg.keepalive_s = 0;
    cfg.reconnect_delay_s = 3;
    cfg.max_retries = -1;
    cfg.connect_timeout_s = 15;
    cfg.io_timeout_s = 30;
    /* 日志级别由 vpn-gui.ini 的 debug 项决定：默认 0=仅要点信息，
     * 改成 1 才会输出逐包/协商细节（GRE 头、LCP 每帧、netsh 返回值） */
    cfg.log_level = g_cfg_debug ? 1 : 2;
    cfg.tun_fd = -1;

    vpn_capi_set_log_level(cfg.log_level);
    vpn_capi_set_log_callback(on_log, NULL);

    /* 1) 先建 Wintun 网卡（失败则退化为仅连通性验证） */
    g_has_tun = 0;
    memset(&g_tun, 0, sizeof(g_tun));
    if (vpn_tun_open("VPNClient", (uint32_t)g_mtu, g_tun_name, sizeof(g_tun_name), &g_tun) == VPN_OK) {
        g_has_tun = 1;
        g_net_configured = 0;
        log_fmt("[INFO] virtual adapter %s created", g_tun_name);
    } else {
        log_fmt("[WARN] could not create the virtual adapter (wintun.dll missing or not elevated), connectivity check only");
    }

    /* 2) 创建会话 */
    err[0] = 0;
    g_h = vpn_capi_create(&cfg, on_state, NULL, NULL, err, (int)sizeof(err));
    if (!g_h) {
        log_fmt("[ERROR] creation failed: %s", err);
        if (g_has_tun && g_tun.destroy) {
            g_tun.destroy(g_tun.ctx);
            memset(&g_tun, 0, sizeof(g_tun));
            g_has_tun = 0;
        }
        return;
    }

    /* 3) 挂接网卡 */
    if (g_has_tun) {
        memset(&ct, 0, sizeof(ct));
        ct.read = tun_read_cb;
        ct.write = tun_write_cb;
        ct.destroy = NULL; /* GUI 自己回收 wintun 会话 */
        ct.ctx = NULL;
        if (vpn_capi_attach_tun(g_h, &ct) != 0)
            log_fmt("[WARN] failed to attach the virtual adapter, IP packets will not be forwarded");
    }

    /* 4) 启动 */
    rc = vpn_capi_start(g_h);
    if (rc != 0) {
        log_fmt("[ERROR] start failed: %s", vpn_capi_strerror(rc));
        do_disconnect();
        return;
    }

    g_was_connected = 0;
    set_ui_running(1);
    config_save();
    log_fmt("[INFO] connecting %s:%d ...", g_host, cfg.port);
}

static void do_disconnect(void)
{
    /* 先把路由撤掉，避免断开后本机路由表还指向已下线的网卡 */
    routes_cleanup();
    /* DNS 与接口度量一并还原，否则物理网卡的解析会被这台已下线网卡拖慢 */
    if (g_tun_name[0])
        vpn_tun_clear_dns(g_tun_name);

    if (g_h) {
        vpn_capi_stop(g_h);
        vpn_capi_detach_tun(g_h);
        vpn_capi_destroy(g_h);
        g_h = NULL;
    }
    if (g_has_tun) {
        if (g_tun.destroy)
            g_tun.destroy(g_tun.ctx);
        memset(&g_tun, 0, sizeof(g_tun));
        g_has_tun = 0;
    }
    g_net_configured = 0;
    g_last_ip[0] = 0;
    g_was_connected = 0;
    set_ui_running(0);
    reset_status_lines();
    g_stat_color = C_GRAY;
    tray_tip_status();
    if (g_hwnd)
        InvalidateRect(g_hwnd, NULL, FALSE);
    log_fmt("[INFO] disconnected");
}

/* ---------------- 定时器：刷新状态、配置路由 ---------------- */

static void update_status(void)
{
    vpn_capi_stats st;
    char ip[32], peer[32], dns[32];

    if (!g_h)
        return;

    memset(&st, 0, sizeof(st));
    vpn_capi_get_stats(g_h, &st);

    snprintf(ip, sizeof(ip), "%s", st.local_ip[0] ? st.local_ip : "-");
    snprintf(peer, sizeof(peer), "%s", st.peer_ip[0] ? st.peer_ip : "-");
    snprintf(dns, sizeof(dns), "%s", st.dns1[0] ? st.dns1 : "-");

    {
        char line[512];

        wcscpy(g_status_text, state_name(st.state));
        snprintf(line, sizeof(line), stat_ip_fmt(), ip, peer, dns);
        u8_to_w(line, g_stat_line, 512);
        snprintf(line, sizeof(line), stat_traffic_fmt(),
                 (double)st.rx_bytes / 1024.0, (double)st.tx_bytes / 1024.0,
                 (unsigned long)st.reconnects);
        u8_to_w(line, g_stat2_line, 512);
        g_stat_color = state_color(st.state);
        if (g_ui_running)
            tray_tip_status();
        if (g_hwnd) {
            RECT r1 = { 40, 228, 740, 300 };
            RECT r2 = { 560, 22, 764, 56 };
            InvalidateRect(g_hwnd, &r1, FALSE);
            InvalidateRect(g_hwnd, &r2, FALSE);
        }
    }

    g_last_state = (unsigned long)st.state;

    /* 连上后（含核心自动重连换了地址时）：给 Wintun 配地址/DNS/路由 */
    if (st.state == VPN_CAPI_STATE_CONNECTED && g_has_tun && st.local_ip[0] &&
        (!g_net_configured || strcmp(g_last_ip, st.local_ip) != 0)) {
        uint32_t local = 0, peer_ip = 0;
        /* SSTP / L2TP / PPTP 都是点对点接口，服务器分配的地址应配 /32：
         * 用 /24 会让系统误以为同网段的其它地址直连可达，绕过隧道；
         * RouterOS 侧 L2TP 也是按 /32 下发的 */
        uint32_t mask = htonl(0xFFFFFFFFu);

        if (vpn_ip_parse(st.local_ip, &local) == 0) {
            if (st.peer_ip[0])
                vpn_ip_parse(st.peer_ip, &peer_ip);
            vpn_tun_configure(g_tun_name, local, peer_ip, mask, (uint32_t)g_mtu);
            if (peer_ip)
                vpn_tun_add_route_via(g_tun_name, peer_ip, htonl(0xFFFFFFFFu), 0);
            if (st.dns1[0] && !g_cfg_vpndns)
                log_fmt("[INFO] DNS takeover skipped by configuration (vpndns=0)");
            if (st.dns1[0] && g_cfg_vpndns) {
                uint32_t d1 = 0, d2 = 0;
                int route_all_now = (Button_GetCheck(g_hRouteAll) == BST_CHECKED);

                vpn_ip_parse(st.dns1, &d1);
                if (st.dns2[0])
                    vpn_ip_parse(st.dns2, &d2);
                /* 只接管私有网段时，落在网段外的 DNS 要单独给一条 /32 路由，
                 * 否则查询被系统发往物理网卡，VPN 下发的 DNS 形同虚设 */
                dns_routes_clear();
                if (d1 && !route_all_now && !is_priv_addr(d1) &&
                    vpn_tun_add_route_via(g_tun_name, d1, htonl(0xFFFFFFFFu), 0) == VPN_OK) {
                    g_dns_routes[g_dns_route_n++] = d1;
                    log_fmt("[INFO] DNS route added: %s/32 -> %s", st.dns1, g_tun_name);
                }
                if (d2 && !route_all_now && !is_priv_addr(d2) &&
                    vpn_tun_add_route_via(g_tun_name, d2, htonl(0xFFFFFFFFu), 0) == VPN_OK) {
                    g_dns_routes[g_dns_route_n++] = d2;
                    log_fmt("[INFO] DNS route added: %s/32 -> %s", st.dns2, g_tun_name);
                }
                if (d1) {
                    /* 接口度量压到 5，系统才会优先用 VPN 下发的 DNS；
                     * 否则 Windows 仍先问物理网卡的 DNS，内网域名解析不到 */
                    if (vpn_tun_set_dns_pref(g_tun_name, d1, d2, 5) == VPN_OK)
                        log_fmt("[INFO] DNS taken over: %s%s%s (VPN adapter metric 5)",
                                st.dns1, st.dns2[0] ? " / " : "",
                                st.dns2[0] ? st.dns2 : "");
                    else
                        log_fmt("[WARN] failed to set DNS: %s", st.dns1);
                }
            }
            routes_apply(Button_GetCheck(g_hRouteAll) == BST_CHECKED,
                         g_hRoutePriv && Button_GetCheck(g_hRoutePriv) == BST_CHECKED);
            snprintf(g_last_ip, sizeof(g_last_ip), "%s", st.local_ip);
            g_net_configured = 1;
            log_fmt("[INFO] adapter configured: %s/32 gateway %s", st.local_ip, st.peer_ip);
            g_was_connected = 1;
        }
    }

    /* 连接失败/断开时把界面恢复成可编辑 */
    if ((st.state == VPN_CAPI_STATE_FAILED || st.state == VPN_CAPI_STATE_DISCONNECTED) && g_was_connected) {
        log_fmt("[WARN] connection lost (the core will reconnect automatically)");
        g_was_connected = 0;
    }
}

/* ---------------- 自绘界面 ---------------- */

static HBRUSH g_br_bg;

static void fill_round(HDC dc, const RECT *rc, int r, COLORREF c)
{
    HBRUSH br = CreateSolidBrush(c);
    HPEN pen = CreatePen(PS_NULL, 0, c);
    HGDIOBJ ob = SelectObject(dc, br);
    HGDIOBJ op = SelectObject(dc, pen);

    RoundRect(dc, rc->left, rc->top, rc->right, rc->bottom, r, r);
    SelectObject(dc, ob);
    SelectObject(dc, op);
    DeleteObject(br);
    DeleteObject(pen);
}

static void stroke_round(HDC dc, const RECT *rc, int r, COLORREF c)
{
    HPEN pen = CreatePen(PS_SOLID, 1, c);
    HGDIOBJ op = SelectObject(dc, pen);
    HGDIOBJ ob = SelectObject(dc, GetStockObject(NULL_BRUSH));

    RoundRect(dc, rc->left, rc->top, rc->right, rc->bottom, r, r);
    SelectObject(dc, op);
    SelectObject(dc, ob);
    DeleteObject(pen);
}

static void draw_text(HDC dc, const wchar_t *s, const RECT *rc, HFONT f, COLORREF c, UINT flags)
{
    HGDIOBJ of = SelectObject(dc, f);
    COLORREF oc = SetTextColor(dc, c);
    int ob = SetBkMode(dc, TRANSPARENT);

    DrawTextW(dc, s, -1, (RECT *)rc, flags);
    SetBkMode(dc, ob);
    SetTextColor(dc, oc);
    SelectObject(dc, of);
}

static void draw_dot(HDC dc, int cx, int cy, int rad, COLORREF c)
{
    HBRUSH br = CreateSolidBrush(c);
    HGDIOBJ ob = SelectObject(dc, br);
    HGDIOBJ op = SelectObject(dc, GetStockObject(NULL_PEN));

    Ellipse(dc, cx - rad, cy - rad, cx + rad, cy + rad);
    SelectObject(dc, ob);
    SelectObject(dc, op);
    DeleteObject(br);
}

/* 语言切换胶囊：active=1 画成白底深字（当前语言） */
static void draw_chip(HDC dc, const RECT *rc, const wchar_t *text, int active)
{
    int rad = (rc->bottom - rc->top) / 2;

    if (active)
        fill_round(dc, rc, rad, RGB(255, 255, 255));
    else
        stroke_round(dc, rc, rad, RGB(0x8F, 0xAC, 0xCC));
    draw_text(dc, text, rc, g_font_small,
              active ? C_PRIMARY : RGB(0xC7, 0xDC, 0xF2),
              DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}

static void draw_banner(HDC dc)
{
    RECT r, tr;
    int i;

    for (i = 0; i < BANNER_H; i++) {
        int cr = 0x2E + (0x1B - 0x2E) * i / BANNER_H;
        int cg = 0x6C + (0x47 - 0x6C) * i / BANNER_H;
        int cb = 0xA8 + (0x72 - 0xA8) * i / BANNER_H;
        HBRUSH b = CreateSolidBrush(RGB(cr, cg, cb));

        SetRect(&r, 0, i, WIN_W, i + 1);
        FillRect(dc, &r, b);
        DeleteObject(b);
    }

    if (g_icon_big)
        DrawIconEx(dc, 22, 20, g_icon_big, 36, 36, 0, NULL, DI_NORMAL);

    SetRect(&tr, 70, 12, 500, 42);
    draw_text(dc, T(S_APP_NAME), &tr, g_font_title, RGB(255, 255, 255),
              DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    SetRect(&tr, 70, 42, 540, 64);
    {
        wchar_t meta[192];

        swprintf(meta, 192, T(S_BANNER_META), APP_VERSION_W, APP_AUTHOR_W);
        draw_text(dc, meta, &tr, g_font_small, RGB(0xC7, 0xDC, 0xF2),
                  DT_LEFT | DT_SINGLELINE);
    }

    draw_dot(dc, 612, 24, 5, g_stat_color);
    SetRect(&tr, 624, 10, 768, 38);
    draw_text(dc, g_status_text, &tr, g_font_bold, RGB(255, 255, 255),
              DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);

    /* 语言切换胶囊：点一下立即切换，选择写入 vpn-gui.ini */
    SetRect(&g_lang_zh_rc, 660, 44, 712, 68);
    SetRect(&g_lang_en_rc, 716, 44, 768, 68);
    draw_chip(dc, &g_lang_zh_rc, L"中文", g_lang != LANG_ZH);
    draw_chip(dc, &g_lang_en_rc, L"EN", g_lang != LANG_EN);
}

static void draw_btn(HDC dc, const gui_btn *b, int idx)
{
    RECT r = b->rc;
    COLORREF bg, fg;

    if (!b->enabled) {
        bg = RGB(0xEE, 0xF2, 0xF7);
        fg = RGB(0xA8, 0xB3, 0xC0);
    } else if (b->primary) {
        bg = (g_press == idx) ? RGB(0x22, 0x58, 0x96)
                             : (g_hover == idx ? C_PRIMARY_HI : C_PRIMARY);
        fg = RGB(255, 255, 255);
    } else {
        bg = (g_hover == idx || g_press == idx) ? C_NEUTRAL_HI : C_NEUTRAL;
        fg = C_TEXT;
    }
    fill_round(dc, &r, r.bottom - r.top, bg);
    draw_text(dc, b->text, &r, g_font_bold, fg,
              DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}

static void draw_card(HDC dc)
{
    RECT r, tr;
    int i;

    SetRect(&r, CARD_X + 2, CARD_Y + 3, CARD_X + CARD_W + 2, CARD_Y + CARD_H + 3);
    fill_round(dc, &r, 16, RGB(0xE3, 0xE9, 0xF2));
    SetRect(&r, CARD_X, CARD_Y, CARD_X + CARD_W, CARD_Y + CARD_H);
    fill_round(dc, &r, 16, C_CARD);

    for (i = 0; i < g_field_n; i++) {
        if (i == g_port_field_idx && g_hPort && !IsWindowVisible(g_hPort))
            continue;   /* 端口框隐藏（L2TP/PPTP）时不画底纹，避免留个空框 */
        fill_round(dc, &g_fields[i], 8, RGB(0xF7, 0xF9, 0xFC));
        stroke_round(dc, &g_fields[i], 8, C_BORDER);
    }

    /* 私网路由说明 */
    SetRect(&tr, 40, 232, 740, 250);
    draw_text(dc, T(S_CARD_NOTE), &tr, g_font_small, RGB(0x8A, 0x97, 0xA8),
              DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);

    draw_dot(dc, 48, 262, 5, g_stat_color);
    SetRect(&tr, 62, 250, 300, 272);
    draw_text(dc, g_status_text, &tr, g_font_bold, C_TEXT,
              DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    SetRect(&tr, 62, 272, 470, 292);
    draw_text(dc, g_stat_line, &tr, g_font_small, C_SUBTEXT,
              DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
    SetRect(&tr, 466, 272, 738, 292);
    draw_text(dc, g_stat2_line, &tr, g_font_small, C_SUBTEXT, DT_RIGHT | DT_SINGLELINE);

    draw_btn(dc, &g_btn_conn, 0);
    draw_btn(dc, &g_btn_disc, 1);
}

static void draw_log(HDC dc)
{
    RECT r;

    SetRect(&r, LOG_X + 2, LOG_Y + 3, LOG_X + LOG_W + 2, LOG_Y + LOG_H + 3);
    fill_round(dc, &r, 12, RGB(0xE3, 0xE9, 0xF2));
    SetRect(&r, LOG_X, LOG_Y, LOG_X + LOG_W, LOG_Y + LOG_H);
    fill_round(dc, &r, 12, C_LOGBG);

    SetRect(&r, 22, LOG_Y - 26, 240, LOG_Y - 4);
    draw_text(dc, T(S_LOG_TITLE), &r, g_font_bold, C_TEXT,
              DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    SetRect(&r, 360, LOG_Y - 26, 760, LOG_Y - 4);
    draw_text(dc, T(S_LOG_HINT), &r, g_font_small, C_SUBTEXT,
              DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
}

static void draw_footer(HDC dc)
{
    RECT r;
    wchar_t foot[256];

    SetRect(&r, 22, LOG_Y + LOG_H + 8, 760, WIN_H - 6);
    swprintf(foot, 256, T(S_FOOTER), APP_VERSION_W, APP_AUTHOR_W);
    draw_text(dc, foot, &r, g_font_small, C_SUBTEXT, DT_LEFT | DT_SINGLELINE);
}

static void paint_all(HDC dc)
{
    RECT clip;

    GetClipBox(dc, &clip);
    if (clip.right <= clip.left || clip.bottom <= clip.top)
        return;
    FillRect(dc, &clip, g_br_bg);

    if (clip.top < BANNER_H)
        draw_banner(dc);
    if (clip.bottom > CARD_Y - 24 && clip.top < CARD_Y + CARD_H + 24)
        draw_card(dc);
    if (clip.bottom > LOG_Y - 40 && clip.top < LOG_Y + LOG_H + 30)
        draw_log(dc);
    if (clip.bottom > LOG_Y + LOG_H + 6)
        draw_footer(dc);
}

/* ---------------- 字体 / 托盘 ---------------- */

static HBRUSH g_br_field;

static HFONT make_font(const wchar_t *face, int px, int weight)
{
    return CreateFontW(px, 0, 0, 0, weight, 0, 0, 0, DEFAULT_CHARSET,
                       OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                       DEFAULT_PITCH | FF_DONTCARE, face);
}

static void ui_resources_init(void)
{
    g_font = make_font(L"Microsoft YaHei UI", -13, FW_NORMAL);
    g_font_small = make_font(L"Microsoft YaHei UI", -12, FW_NORMAL);
    g_font_bold = make_font(L"Microsoft YaHei UI", -13, FW_SEMIBOLD);
    g_font_title = make_font(L"Microsoft YaHei UI", -19, FW_BOLD);
    g_font_mono = make_font(L"Consolas", -12, FW_NORMAL);

    g_br_bg = CreateSolidBrush(C_BG);
    g_br_card = CreateSolidBrush(C_CARD);
    g_br_log = CreateSolidBrush(C_LOGBG);
    g_br_field = CreateSolidBrush(RGB(0xF7, 0xF9, 0xFC));

    g_icon_big = (HICON)LoadImageW(g_inst, MAKEINTRESOURCEW(IDI_APP), IMAGE_ICON,
                                   36, 36, LR_DEFAULTCOLOR);
}

static void tray_add(void)
{
    int cx, cy;

    if (g_tray_added)
        return;
    cx = GetSystemMetrics(SM_CXSMICON);
    cy = GetSystemMetrics(SM_CYSMICON);
    memset(&g_nid, 0, sizeof(g_nid));
    g_nid.cbSize = sizeof(g_nid);
    g_nid.hWnd = g_hwnd;
    g_nid.uID = 1;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAY;
    g_nid.hIcon = (HICON)LoadImageW(g_inst, MAKEINTRESOURCEW(IDI_APP), IMAGE_ICON,
                                    cx, cy, LR_DEFAULTCOLOR);
    swprintf(g_nid.szTip, 128, L"%ls - %ls", T(S_APP_NAME), T(S_ST_IDLE));
    if (Shell_NotifyIconW(NIM_ADD, &g_nid))
        g_tray_added = 1;
}

static void tray_remove(void)
{
    if (!g_tray_added)
        return;
    Shell_NotifyIconW(NIM_DELETE, &g_nid);
    g_tray_added = 0;
}

static void tray_tip(const wchar_t *s)
{
    if (!g_tray_added || !s)
        return;
    wcsncpy(g_nid.szTip, s, 127);
    g_nid.szTip[127] = 0;
    g_nid.uFlags = NIF_TIP;
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
}

static void tray_balloon(const wchar_t *title, const wchar_t *text)
{
    if (!g_tray_added)
        return;
    wcsncpy(g_nid.szInfoTitle, title, 63);
    g_nid.szInfoTitle[63] = 0;
    wcsncpy(g_nid.szInfo, text, 255);
    g_nid.szInfo[255] = 0;
    g_nid.dwInfoFlags = NIIF_INFO;
    g_nid.uFlags = NIF_INFO;
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
}

static void show_main(void)
{
    if (!g_hwnd)
        return;
    ShowWindow(g_hwnd, SW_SHOW);
    ShowWindow(g_hwnd, SW_RESTORE);
    SetForegroundWindow(g_hwnd);
}

static void show_about(void)
{
    if (!g_hwnd)
        return;
    MessageBoxW(g_hwnd, T(S_ABOUT), T(S_ABOUT_TITLE), MB_OK | MB_ICONINFORMATION);
}

static void tray_menu(void)
{
    HMENU m = CreatePopupMenu();
    HMENU lang;
    POINT pt;

    if (!m)
        return;
    AppendMenuW(m, MF_STRING, IDM_SHOW, T(S_TRAY_SHOW));
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(m, g_ui_running ? MF_GRAYED : MF_STRING, IDM_CONNECT, T(S_TRAY_CONNECT));
    AppendMenuW(m, g_ui_running ? MF_STRING : MF_GRAYED, IDM_DISCONNECT, T(S_TRAY_DISCONNECT));
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    /* 语言子菜单：与标题栏右上角胶囊等效，点完立即生效 */
    lang = CreatePopupMenu();
    AppendMenuW(lang, MF_STRING | (g_lang == LANG_ZH ? MF_CHECKED : 0), IDM_LANG_ZH, T(S_LANG_ZH));
    AppendMenuW(lang, MF_STRING | (g_lang == LANG_EN ? MF_CHECKED : 0), IDM_LANG_EN, T(S_LANG_EN));
    AppendMenuW(m, MF_POPUP, (UINT_PTR)lang, T(S_LANG_MENU));
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(m, MF_STRING, IDM_ABOUT, T(S_TRAY_ABOUT));
    AppendMenuW(m, MF_STRING, IDM_EXIT, T(S_TRAY_EXIT));
    SetMenuDefaultItem(m, IDM_SHOW, FALSE);

    GetCursorPos(&pt);
    SetForegroundWindow(g_hwnd);
    TrackPopupMenu(m, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | TPM_LEFTALIGN,
                   pt.x, pt.y, 0, g_hwnd, NULL);
    PostMessageW(g_hwnd, WM_NULL, 0, 0);
    DestroyMenu(m);
}

/* ---------------- 窗口 ---------------- */

static HWND mk_label(HWND p, const wchar_t *text, int x, int y, int w, int h)
{
    HWND hc = CreateWindowExW(0, L"STATIC", text, WS_CHILD | WS_VISIBLE,
                              x, y, w, h, p, NULL, NULL, NULL);
    SendMessageW(hc, WM_SETFONT, (WPARAM)g_font_small, TRUE);
    return hc;
}

static void add_field(int x, int y, int w, int h)
{
    if (g_field_n < MAX_FIELDS) {
        g_fields[g_field_n].left = x - 1;
        g_fields[g_field_n].top = y - 1;
        g_fields[g_field_n].right = x + w + 1;
        g_fields[g_field_n].bottom = y + h + 1;
        g_field_n++;
    }
}

static HWND mk_edit(HWND p, int id, int x, int y, int w, int h, DWORD style)
{
    HWND e;

    add_field(x, y, w, h);
    e = CreateWindowExW(0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | style,
                        x, y, w, h, p, (HMENU)(INT_PTR)id, NULL, NULL);
    SendMessageW(e, WM_SETFONT, (WPARAM)g_font, TRUE);
    return e;
}

static HWND mk_combo(HWND p, int id, int x, int y, int w)
{
    HWND c = CreateWindowExW(0, L"COMBOBOX", L"", WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST,
                             x, y, w, 240, p, (HMENU)(INT_PTR)id, NULL, NULL);
    SendMessageW(c, WM_SETFONT, (WPARAM)g_font, TRUE);
    return c;
}

static void apply_config_to_ui(void);

static void on_create(HWND hwnd)
{
    g_field_n = 0;

    /* 第一行：协议 / 服务器 / 端口 */
    g_label_n = 0;   /* 窗口重建时重新登记，避免残留失效句柄 */
    lbl_add(mk_label(hwnd, T(S_PROTO), 40, ROW1_Y + 4, 44, 20), S_PROTO);
    g_hProto = mk_combo(hwnd, IDC_PROTO, 84, ROW1_Y, 96);
    SendMessageW(g_hProto, CB_ADDSTRING, 0, (LPARAM)L"SSTP");
    SendMessageW(g_hProto, CB_ADDSTRING, 0, (LPARAM)L"L2TP");
    SendMessageW(g_hProto, CB_ADDSTRING, 0, (LPARAM)L"PPTP");
    SendMessageW(g_hProto, CB_SETCURSEL, 0, 0);

    lbl_add(mk_label(hwnd, T(S_SERVER), 196, ROW1_Y + 4, 52, 20), S_SERVER);
    g_hHost = mk_edit(hwnd, IDC_HOST, 250, ROW1_Y, 250, CTL_H, 0);
    g_hPortLabel = mk_label(hwnd, T(S_PORT), 516, ROW1_Y + 4, 40, 20);
    lbl_add(g_hPortLabel, S_PORT);
    g_hPort = mk_edit(hwnd, IDC_PORT, 556, ROW1_Y, 80, CTL_H, ES_NUMBER);
    g_port_field_idx = g_field_n - 1;
    g_port_owner = 0;
    SetWindowTextW(g_hPort, L"443");

    /* 第二行：用户名 / 密码 / 证书 */
    lbl_add(mk_label(hwnd, T(S_USER), 40, ROW2_Y + 4, 52, 20), S_USER);
    g_hUser = mk_edit(hwnd, IDC_USER, 94, ROW2_Y, 170, CTL_H, 0);
    lbl_add(mk_label(hwnd, T(S_PASS), 280, ROW2_Y + 4, 40, 20), S_PASS);
    g_hPass = mk_edit(hwnd, IDC_PASS, 318, ROW2_Y, 170, CTL_H, ES_PASSWORD);
    lbl_add(mk_label(hwnd, T(S_CERT), 504, ROW2_Y + 4, 40, 20), S_CERT);
    g_hCert = mk_combo(hwnd, IDC_CERT, 544, ROW2_Y, 96);
    SendMessageW(g_hCert, CB_ADDSTRING, 0, (LPARAM)T(S_CERT_VERIFY));
    SendMessageW(g_hCert, CB_ADDSTRING, 0, (LPARAM)T(S_CERT_IGNORE));
    SendMessageW(g_hCert, CB_SETCURSEL, 1, 0);

    /* 第三行：MTU / 路由 / 按钮 */
    mk_label(hwnd, L"MTU", 40, ROW3_Y + 4, 36, 20);   /* MTU 中英同形，无需登记 */
    g_hMtu = mk_edit(hwnd, IDC_MTU, 78, ROW3_Y, 80, CTL_H, ES_NUMBER);
    SetWindowTextW(g_hMtu, L"1400");

    g_hRouteAll = CreateWindowExW(0, L"BUTTON", T(S_ROUTE_ALL),
                                  WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                                  178, ROW3_Y + 2, 150, 22, hwnd,
                                  (HMENU)(INT_PTR)IDC_ROUTEALL, NULL, NULL);
    SendMessageW(g_hRouteAll, WM_SETFONT, (WPARAM)g_font, TRUE);

    /* 私网段路由：优先级低于本机已有路由，不影响本地网络互访 */
    g_hRoutePriv = CreateWindowExW(0, L"BUTTON", T(S_ROUTE_PRIV),
                                   WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                                   334, ROW3_Y + 2, 160, 22, hwnd,
                                   (HMENU)(INT_PTR)IDC_ROUTEPRIV, NULL, NULL);
    SendMessageW(g_hRoutePriv, WM_SETFONT, (WPARAM)g_font, TRUE);

    g_btn_conn.primary = 1;
    g_btn_conn.text = T(S_BTN_CONNECT);
    g_btn_conn.enabled = 1;
    SetRect(&g_btn_conn.rc, 496, 184, 606, 226);

    g_btn_disc.primary = 0;
    g_btn_disc.text = T(S_BTN_DISCONNECT);
    g_btn_disc.enabled = 0;
    SetRect(&g_btn_disc.rc, 618, 184, 728, 226);

    /* 日志区 */
    g_hLog = CreateWindowExW(0, L"EDIT", L"",
                             WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY |
                                 ES_AUTOVSCROLL,
                             LOG_X + 8, LOG_Y + 8, LOG_W - 16, LOG_H - 16, hwnd,
                             (HMENU)(INT_PTR)IDC_LOG, NULL, NULL);
    SendMessageW(g_hLog, WM_SETFONT, (WPARAM)g_font_mono, TRUE);
    SendMessageW(g_hLog, EM_SETLIMITTEXT, (WPARAM)(4 * 1024 * 1024), 0);
    g_log_orig_proc = (WNDPROC)SetWindowLongPtrW(g_hLog, GWLP_WNDPROC,
                                                 (LONG_PTR)log_ctrl_proc);

    apply_config_to_ui();

    log_fmt("[INFO] ready. enter the server address and credentials, then press Connect; closing the window minimizes to the tray.");
    /* 构建时间随每次编译变化，用户报问题时据此确认跑的是哪个版本 */
    log_fmt("[INFO] client build time %s %s", __DATE__, __TIME__);
}

static BOOL hit_btn(const gui_btn *b, POINT p)
{
    return (b->enabled && PtInRect(&b->rc, p)) ? TRUE : FALSE;
}

static LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE:
        g_hwnd = hwnd;
        on_create(hwnd);
        SetTimer(hwnd, TIMER_UI, 200, NULL);
        tray_add();
        return 0;

    case WM_TIMER:
        pump_log_to_ui();
        update_status();
        return 0;

    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC dc = BeginPaint(hwnd, &ps);
            paint_all(dc);
            EndPaint(hwnd, &ps);
        }
        return 0;

    case WM_ERASEBKGND:
        return 1;

    case WM_CTLCOLORSTATIC:
        if ((HWND)lp == g_hLog) {
            SetTextColor((HDC)wp, C_LOGTX);
            SetBkColor((HDC)wp, C_LOGBG);
            return (LRESULT)g_br_log;
        }
        SetTextColor((HDC)wp, C_TEXT);
        SetBkColor((HDC)wp, C_CARD);
        return (LRESULT)g_br_card;

    case WM_CTLCOLOREDIT:
        SetTextColor((HDC)wp, C_TEXT);
        SetBkColor((HDC)wp, RGB(0xF7, 0xF9, 0xFC));
        return (LRESULT)g_br_field;

    case WM_MOUSEMOVE:
        {
            POINT p = { GET_X_LPARAM(lp), GET_Y_LPARAM(lp) };
            int idx = -1;

            if (hit_btn(&g_btn_conn, p))
                idx = 0;
            else if (hit_btn(&g_btn_disc, p))
                idx = 1;
            if (idx != g_hover) {
                RECT a = g_btn_conn.rc, b = g_btn_disc.rc;
                g_hover = idx;
                InvalidateRect(hwnd, &a, FALSE);
                InvalidateRect(hwnd, &b, FALSE);
            }
            if (idx >= 0 || PtInRect(&g_lang_zh_rc, p) || PtInRect(&g_lang_en_rc, p))
                SetCursor(LoadCursorW(NULL, MAKEINTRESOURCEW(32649))); /* IDC_HAND */
        }
        return 0;

    case WM_LBUTTONDOWN:
        {
            POINT p = { GET_X_LPARAM(lp), GET_Y_LPARAM(lp) };
            int idx = -1;

            /* 标题栏右上角语言胶囊优先判定：与按钮区域不重叠 */
            if (PtInRect(&g_lang_zh_rc, p)) {
                set_language(LANG_ZH);
                return 0;
            }
            if (PtInRect(&g_lang_en_rc, p)) {
                set_language(LANG_EN);
                return 0;
            }
            if (hit_btn(&g_btn_conn, p))
                idx = 0;
            else if (hit_btn(&g_btn_disc, p))
                idx = 1;
            if (idx >= 0) {
                g_press = idx;
                InvalidateRect(hwnd, &g_btn_conn.rc, FALSE);
                InvalidateRect(hwnd, &g_btn_disc.rc, FALSE);
                SetCapture(hwnd);
            } else if (p.y > LOG_Y + LOG_H + 4) {
                show_about();  /* 点底部版本信息看版本说明 */
            }
        }
        return 0;

    case WM_LBUTTONUP:
        {
            POINT p = { GET_X_LPARAM(lp), GET_Y_LPARAM(lp) };
            int was = g_press;

            g_press = -1;
            ReleaseCapture();
            InvalidateRect(hwnd, &g_btn_conn.rc, FALSE);
            InvalidateRect(hwnd, &g_btn_disc.rc, FALSE);
            if (was == 0 && hit_btn(&g_btn_conn, p))
                do_connect();
            else if (was == 1 && hit_btn(&g_btn_disc, p))
                do_disconnect();
        }
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDM_SHOW:
            show_main();
            return 0;
        case IDM_CONNECT:
            show_main();
            if (!g_ui_running)
                do_connect();
            return 0;
        case IDM_DISCONNECT:
            do_disconnect();
            return 0;
        case IDM_LANG_ZH:
            set_language(LANG_ZH);
            return 0;
        case IDM_LANG_EN:
            set_language(LANG_EN);
            return 0;
        case IDM_ABOUT:
            show_about();
            return 0;
        case IDM_EXIT:
            g_allow_close = 1;
            SendMessageW(hwnd, WM_CLOSE, 0, 0);
            return 0;
        case IDC_PROTO:
            if (HIWORD(wp) == CBN_SELCHANGE) {
                proto_port_sync((int)ComboBox_GetCurSel(g_hProto));
                return 0;
            }
            break;
        default:
            break;
        }
        break;

    case WM_TRAY:
        if (lp == WM_LBUTTONDBLCLK) {
            if (IsWindowVisible(hwnd) && !IsIconic(hwnd))
                ShowWindow(hwnd, SW_HIDE);
            else
                show_main();
        } else if (lp == WM_RBUTTONUP || lp == WM_CONTEXTMENU) {
            tray_menu();
        } else if (lp == WM_LBUTTONUP) {
            show_main();
        }
        return 0;

    case WM_CLOSE:
        if (!g_allow_close && g_tray_added) {
            ShowWindow(hwnd, SW_HIDE);
            tray_balloon(L"tunnel-client仍在运行",
                         L"已最小化到托盘，双击图标可恢复窗口；托盘菜单可退出。");
            return 0;
        }
        config_save();
        do_disconnect();
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        KillTimer(hwnd, TIMER_UI);
        tray_remove();
        do_disconnect();
        PostQuitMessage(0);
        return 0;

    default:
        break;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

/* 创建 Wintun 适配器需要管理员权限；非提权时尝试用 UAC 自我重启 */
static BOOL is_elevated(void)
{
    HANDLE tok = NULL;
    TOKEN_ELEVATION el;
    DWORD sz = sizeof(el);
    BOOL r = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok))
        return FALSE;
    memset(&el, 0, sizeof(el));
    if (GetTokenInformation(tok, TokenElevation, &el, sizeof(el), &sz))
        r = el.TokenIsElevated ? TRUE : FALSE;
    CloseHandle(tok);
    return r;
}

/* 找回已在运行的实例：窗口可能被最小化到托盘，SW_RESTORE 能让它显形。
 * 返回 TRUE 表示已有实例存在，当前进程应直接退出 */
static BOOL focus_existing_instance(void)
{
    HWND old = FindWindowW(APP_CLASS_W, NULL);

    if (!old)
        return FALSE;
    if (IsIconic(old))
        ShowWindow(old, SW_RESTORE);
    ShowWindow(old, SW_SHOW);
    SetForegroundWindow(old);
    return TRUE;
}

static BOOL try_elevate(void)
{
    wchar_t path[MAX_PATH];
    HINSTANCE rc;

    if (wcsstr(GetCommandLineW(), L"--elevated"))
        return FALSE; /* 已经通过 UAC 重启过，不要循环 */
    if (!GetModuleFileNameW(NULL, path, MAX_PATH))
        return FALSE;

    rc = ShellExecuteW(NULL, L"runas", path, L"--elevated", NULL, SW_SHOWNORMAL);
    return (INT_PTR)rc > 32;
}

int WINAPI WinMain(HINSTANCE inst, HINSTANCE prev, LPSTR cmd, int show)
{
    WNDCLASSEXW wc;
    MSG m;
    HWND hwnd;
    HICON icon;
    RECT rc;
    HANDLE mtx;
    wchar_t title[128];

    (void)prev;
    (void)cmd;

    /* 单实例限制，顺序很关键：
     *   1) 先查窗口——这一步必须在提权之前，否则普通双击启动的进程会先
     *      提权重启，而重启出来的进程带 --elevated，原有判定对它跳过，
     *      于是双击几次就开几个窗口；
     *   2) 提权重启期间父进程立刻退出，不持有任何锁，避免子进程被自己挡住；
     *   3) 真正跑起来的 GUI 进程再用命名互斥体兜底，覆盖「窗口还没建好
     *      就被连点」这种几毫秒的竞态。 */
    if (!wcsstr(GetCommandLineW(), L"--elevated") && focus_existing_instance())
        return 0;

    /* 非管理员：先尝试提权重启（用户拒绝 UAC 则继续，仅作连通性验证） */
    if (!is_elevated() && try_elevate())
        return 0;

    mtx = CreateMutexW(NULL, TRUE, L"Local\\VpnClientGuiSingleton");
    if (mtx && GetLastError() == ERROR_ALREADY_EXISTS) {
        focus_existing_instance();
        CloseHandle(mtx);
        return 0;
    }

    SetProcessDPIAware();
    g_inst = inst;

    InitializeCriticalSection(&g_log_cs);
    log_file_open();
    SetUnhandledExceptionFilter(crash_filter);
    vpn_net_init();
    ui_resources_init();
    config_load();

    icon = (HICON)LoadImageW(inst, MAKEINTRESOURCEW(IDI_APP), IMAGE_ICON,
                             32, 32, LR_DEFAULTCOLOR);
    if (!icon)
        icon = LoadIconW(NULL, MAKEINTRESOURCEW(IDI_APPLICATION));

    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = wnd_proc;
    wc.hInstance = inst;
    wc.hCursor = LoadCursorW(NULL, MAKEINTRESOURCEW(IDC_ARROW));
    wc.hbrBackground = g_br_bg ? g_br_bg : (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = APP_CLASS_W;
    wc.hIcon = icon;
    wc.hIconSm = icon;
    RegisterClassExW(&wc);

    SetRect(&rc, 0, 0, WIN_W, WIN_H);
    AdjustWindowRectEx(&rc, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                       FALSE, 0);

    swprintf(title, 128, L"%ls v%ls  -  SSTP / L2TP / PPTP", T(S_APP_NAME), APP_VERSION_W);
    hwnd = CreateWindowExW(0, APP_CLASS_W, title,
                           WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                           CW_USEDEFAULT, CW_USEDEFAULT,
                           rc.right - rc.left, rc.bottom - rc.top,
                           NULL, NULL, inst, NULL);
    if (!hwnd)
        return 1;

    ShowWindow(hwnd, show == SW_SHOWMINIMIZED ? SW_SHOWMINIMIZED : SW_SHOW);
    UpdateWindow(hwnd);

    while (GetMessageW(&m, NULL, 0, 0) > 0) {
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }

    vpn_net_cleanup();
    DeleteCriticalSection(&g_log_cs);
    return 0;
}
