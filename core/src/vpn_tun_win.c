/* SPDX-License-Identifier: LicenseRef-Proprietary
   Copyright (c) 2026 wwm-spec. All rights reserved.
 */

/* vpn_tun_win.c - Windows 侧的 TUN 实现（Wintun）
 *
 * 为什么在这里做而不是 C#：
 *   - Wintun 的 API 就是普通 C 导出函数，动态加载后可直接读写，省掉 .NET 运行时依赖；
 *   - GUI 只要一个 exe + wintun.dll，方便分发和排查。
 *
 * 约定：
 *   - wintun.dll 与 exe 同目录（或系统 PATH 里）；找不到时返回 VPN_ERR_UNSUPPORTED，
 *     调用方（GUI）会提示"仅连通性模式"。
 *   - 创建适配器需要管理员权限（WintunCreateAdapter 会失败并返回 ACCESS_DENIED）。
 *   - IP/路由/DNS 通过 netsh 配置，不引入 IP Helper API 的复杂依赖。
 */
#ifdef _WIN32

#include <winsock2.h>
#include <windows.h>

#include "vpncore/vpn_tun.h"
#include "vpncore/vpn_error.h"
#include "vpncore/vpn_log.h"
#include "vpncore/vpn_net.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

/* ---------------- Wintun 0.14 动态绑定 ---------------- */

typedef void *WINTUN_ADAPTER_HANDLE;
typedef void *WINTUN_SESSION_HANDLE;

typedef struct {
    WINTUN_ADAPTER_HANDLE(WINAPI *CreateAdapter)(const wchar_t *name,
                                                 const wchar_t *tunnel_type,
                                                 const GUID *requested_guid);
    void(WINAPI *CloseAdapter)(WINTUN_ADAPTER_HANDLE adapter);
    WINTUN_SESSION_HANDLE(WINAPI *StartSession)(WINTUN_ADAPTER_HANDLE adapter, DWORD capacity);
    void(WINAPI *EndSession)(WINTUN_SESSION_HANDLE session);
    BYTE *(WINAPI *ReceivePacket)(WINTUN_SESSION_HANDLE session, DWORD *packet_size);
    void(WINAPI *ReleaseReceivePacket)(WINTUN_SESSION_HANDLE session, const BYTE *packet);
    BYTE *(WINAPI *AllocateSendPacket)(WINTUN_SESSION_HANDLE session, DWORD packet_size);
    void(WINAPI *SendPacket)(WINTUN_SESSION_HANDLE session, const BYTE *packet);
    HANDLE(WINAPI *GetReadWaitEvent)(WINTUN_SESSION_HANDLE session);
} wintun_api;

static wintun_api g_win;
static HMODULE g_win_mod;
static int g_win_state; /* 0=未加载 1=可用 -1=不可用 */

/* 会话 ring 容量：4MB 足够 1Gbps 短突发 */
#define WIN_TUN_RING 0x400000

static int wintun_load(void)
{
    if (g_win_state)
        return g_win_state > 0 ? 0 : -1;

    g_win_mod = LoadLibraryA("wintun.dll");
    if (!g_win_mod) {
        VPN_ERROR("wintun.dll not found (put it next to the executable); only connectivity tests will work");
        g_win_state = -1;
        return -1;
    }

#define WIN_BIND(field, name)                                                   \
    do {                                                                        \
        FARPROC fp = GetProcAddress(g_win_mod, name);                            \
        memcpy(&g_win.field, &fp, sizeof(fp));                                   \
        if (!g_win.field) {                                                     \
            VPN_ERROR("wintun.dll is missing export %s (outdated? 0.14+ required)", name);   \
            g_win_state = -1;                                                   \
            return -1;                                                          \
        }                                                                       \
    } while (0)

    WIN_BIND(CreateAdapter, "WintunCreateAdapter");
    WIN_BIND(CloseAdapter, "WintunCloseAdapter");
    WIN_BIND(StartSession, "WintunStartSession");
    WIN_BIND(EndSession, "WintunEndSession");
    WIN_BIND(ReceivePacket, "WintunReceivePacket");
    WIN_BIND(ReleaseReceivePacket, "WintunReleaseReceivePacket");
    WIN_BIND(AllocateSendPacket, "WintunAllocateSendPacket");
    WIN_BIND(SendPacket, "WintunSendPacket");
    WIN_BIND(GetReadWaitEvent, "WintunGetReadWaitEvent");
#undef WIN_BIND

    g_win_state = 1;
    return 0;
}

/* ---------------- 工具函数 ---------------- */

static void utf8_to_wide(const char *s, wchar_t *out, int outn)
{
    if (!out || outn <= 0)
        return;
    if (!s) {
        out[0] = 0;
        return;
    }
    MultiByteToWideChar(CP_UTF8, 0, s, -1, out, outn);
    out[outn - 1] = 0;
}

static void wide_to_utf8(const wchar_t *s, char *out, int outn)
{
    if (!out || outn <= 0)
        return;
    if (!s) {
        out[0] = 0;
        return;
    }
    WideCharToMultiByte(CP_UTF8, 0, s, -1, out, outn, NULL, NULL);
    out[outn - 1] = 0;
}

/* 静默执行一条命令行（隐藏窗口），返回退出码（0 表示成功） */
/* 执行命令，out 非空时把子进程 stdout+stderr（OEM 代码页）转 UTF-8 带回，
 * 失败时把 netsh 的原始报错写进日志——否则只能看到“命令返回 1”无法定位 */
static int run_hidden_out(const wchar_t *cmdline, char *out, size_t cap)
{
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    SECURITY_ATTRIBUTES sa;
    wchar_t buf[1024];
    HANDLE rd = NULL, wr = NULL, nul;
    DWORD code = 1;
    char raw[2048];
    size_t rawn = 0;

    if (out && cap)
        out[0] = 0;

    memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    if (!CreatePipe(&rd, &wr, &sa, 0)) {
        VPN_WARN("CreatePipe failed (err=%lu)", GetLastError());
        return -1;
    }
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    nul = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                      &sa, OPEN_EXISTING, 0, NULL);

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = wr;
    si.hStdError = wr;
    si.hStdInput = (nul != INVALID_HANDLE_VALUE) ? nul : NULL;

    wcsncpy(buf, cmdline, 1023);
    buf[1023] = 0;

    if (!CreateProcessW(NULL, buf, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        VPN_WARN("command failed (err=%lu): %ls", GetLastError(), cmdline);
        CloseHandle(rd);
        CloseHandle(wr);
        if (nul != INVALID_HANDLE_VALUE)
            CloseHandle(nul);
        return -1;
    }
    CloseHandle(wr);   /* 父进程关掉写端，ReadFile 才能读到 EOF */
    if (nul != INVALID_HANDLE_VALUE)
        CloseHandle(nul);

    for (;;) {
        char tmp[512];
        DWORD got = 0;
        if (!ReadFile(rd, tmp, sizeof(tmp) - 1, &got, NULL) || got == 0)
            break;
        tmp[got] = 0;
        if (rawn + got < sizeof(raw) - 1) {
            memcpy(raw + rawn, tmp, got);
            rawn += got;
            raw[rawn] = 0;
        }
    }
    CloseHandle(rd);

    WaitForSingleObject(pi.hProcess, 20000);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (out && cap && rawn) {
        wchar_t wbuf[2048];
        int wn = MultiByteToWideChar(CP_OEMCP, 0, raw, (int)rawn, wbuf, 2047);
        if (wn > 0) {
            int n;
            wbuf[wn] = 0;
            n = WideCharToMultiByte(CP_UTF8, 0, wbuf, wn, out, (int)cap - 1, NULL, NULL);
            if (n < 0)
                n = 0;
            out[n] = 0;
            /* 去掉尾部空白/换行，日志一行更清爽 */
            while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r' || out[n - 1] == ' '))
                out[--n] = 0;
        }
    }

    if (code != 0) {
        if (out && out[0])
            VPN_DEBUG("command returned %lu: %ls | %s", code, cmdline, out);
        else
            VPN_DEBUG("command returned %lu: %ls", code, cmdline);
    }
    return (int)code;
}

static int run_hidden(const wchar_t *cmdline)
{
    return run_hidden_out(cmdline, NULL, 0);
}

/* ---------------- TUN ops ---------------- */

typedef struct {
    WINTUN_ADAPTER_HANDLE adapter;
    WINTUN_SESSION_HANDLE session;
    char name[128];
} win_tun_ctx;

static int win_read(void *ctx, void *buf, size_t cap, int timeout_ms)
{
    win_tun_ctx *t = (win_tun_ctx *)ctx;
    DWORD size = 0;
    BYTE *pkt;
    size_t n;

    if (!t || !t->session)
        return VPN_ERR_INVALID;

    pkt = g_win.ReceivePacket(t->session, &size);
    if (!pkt) {
        DWORD err = GetLastError();
        if (err == ERROR_NO_MORE_ITEMS) {
            HANDLE ev;
            if (timeout_ms <= 0)
                return 0; /* 非阻塞：交给调用方下一轮再读 */
            ev = g_win.GetReadWaitEvent(t->session);
            if (ev)
                WaitForSingleObject(ev, (DWORD)timeout_ms);
            else
                Sleep((DWORD)timeout_ms);
            return 0;
        }
        if (err == ERROR_HANDLE_EOF)
            return VPN_ERR_CLOSED;
        return VPN_ERR_IO;
    }

    n = size > cap ? cap : (size_t)size;
    memcpy(buf, pkt, n);
    g_win.ReleaseReceivePacket(t->session, pkt);
    return (int)n;
}

static int win_write(void *ctx, const void *buf, size_t len)
{
    win_tun_ctx *t = (win_tun_ctx *)ctx;
    BYTE *pkt;

    if (!t || !t->session || len == 0)
        return VPN_ERR_INVALID;

    pkt = g_win.AllocateSendPacket(t->session, (DWORD)len);
    if (!pkt)
        return VPN_ERR_IO;
    memcpy(pkt, buf, len);
    g_win.SendPacket(t->session, pkt);
    return (int)len;
}

static void win_destroy(void *ctx)
{
    win_tun_ctx *t = (win_tun_ctx *)ctx;

    if (!t)
        return;
    if (t->session) {
        g_win.EndSession(t->session);
        t->session = NULL;
    }
    if (t->adapter) {
        g_win.CloseAdapter(t->adapter);
        t->adapter = NULL;
    }
    free(t);
}

int vpn_tun_open(const char *dev_name, uint32_t mtu, char *name_out, size_t name_len,
                 vpn_tun_ops *out)
{
    win_tun_ctx *t;
    wchar_t wname[128];
    DWORD err;

    if (!out)
        return VPN_ERR_INVALID;
    if (wintun_load() != 0)
        return VPN_ERR_UNSUPPORTED;

    t = (win_tun_ctx *)calloc(1, sizeof(*t));
    if (!t)
        return VPN_ERR_NOMEM;

    utf8_to_wide(dev_name && dev_name[0] ? dev_name : "VPNClient", wname, 128);

    t->adapter = g_win.CreateAdapter(wname, L"VPNClient", NULL);
    if (!t->adapter) {
        err = GetLastError();
        VPN_ERROR("failed to create the Wintun adapter (err=%lu)%s", err,
                  err == ERROR_ACCESS_DENIED ? ": please run as administrator" : "");
        free(t);
        return VPN_ERR_IO;
    }

    t->session = g_win.StartSession(t->adapter, WIN_TUN_RING);
    if (!t->session) {
        VPN_ERROR("failed to start the Wintun session (err=%lu)", GetLastError());
        g_win.CloseAdapter(t->adapter);
        free(t);
        return VPN_ERR_IO;
    }

    wide_to_utf8(wname, t->name, sizeof(t->name));
    if (name_out && name_len)
        snprintf(name_out, name_len, "%s", t->name);

    memset(out, 0, sizeof(*out));
    out->read = win_read;
    out->write = win_write;
    out->destroy = win_destroy;
    out->ctx = t;

    VPN_INFO("Wintun adapter ready: %s", t->name);
    if (mtu)
        vpn_tun_configure(t->name, 0, 0, 0, mtu);
    return VPN_OK;
}

int vpn_tun_configure(const char *dev_name, uint32_t local_ip, uint32_t peer_ip,
                      uint32_t netmask, uint32_t mtu)
{
    wchar_t wname[128], wip[32], wmask[32], cmd[768];

    if (!dev_name || !dev_name[0])
        return VPN_ERR_INVALID;

    utf8_to_wide(dev_name, wname, 128);

    if (local_ip) {
        char ip[32], mask[32];
        vpn_ip_ntoa(local_ip, ip, sizeof(ip));
        vpn_ip_ntoa(netmask ? netmask : htonl(0xFFFFFF00u), mask, sizeof(mask));
        utf8_to_wide(ip, wip, 32);
        utf8_to_wide(mask, wmask, 32);
        /* 注意：swprintf 中 %s 接的是窄串，宽串必须用 %ls，否则只取到首字节 */
        swprintf(cmd, 768, L"netsh interface ipv4 set address name=\"%ls\" source=static "
                           L"address=%ls mask=%ls", wname, wip, wmask);
        run_hidden(cmd);
        VPN_INFO("interface %s address set to %s/%s", dev_name, ip, mask);
    }

    if (mtu) {
        swprintf(cmd, 768, L"netsh interface ipv4 set subinterface \"%ls\" mtu=%lu store=persistent",
                 wname, (unsigned long)mtu);
        run_hidden(cmd);
    }

    (void)peer_ip;
    return VPN_OK;
}

int vpn_tun_add_route_metric(const char *dev_name, uint32_t dst, uint32_t mask,
                             uint32_t gateway, int metric)
{
    char sdst[32], sgate[32];
    wchar_t wdst[32], wgate[32], wname[128], cmd[768];
    uint32_t m = ntohl(mask);   /* 掩码按网络序传入，转主机序再数前缀 */
    int prefix = 0;

    if (!dev_name || !dev_name[0])
        return VPN_ERR_INVALID;

    /* 掩码转前缀长度 */
    while (m & 0x80000000u) {
        prefix++;
        m <<= 1;
    }

    vpn_ip_ntoa(dst, sdst, sizeof(sdst));
    utf8_to_wide(sdst, wdst, 32);
    utf8_to_wide(dev_name, wname, 128);
    if (metric <= 0)
        metric = 5;

    /* 用 name=value 形式，避免位置参数错位；store=active 不进注册表，
     * 进程异常退出也不会留下永久路由 */
    if (gateway) {
        vpn_ip_ntoa(gateway, sgate, sizeof(sgate));
        utf8_to_wide(sgate, wgate, 32);
        /* 显式带上接口名，避免 route.exe 按网关把条目塞到物理网卡 */
        swprintf(cmd, 768,
                 L"netsh interface ipv4 add route prefix=%ls/%d interface=\"%ls\" "
                 L"nexthop=%ls metric=%d store=active",
                 wdst, prefix, wname, wgate, metric);
    } else {
        /* 走接口 on-link（Wintun 没有真实网关，on-link 才可靠） */
        swprintf(cmd, 768,
                 L"netsh interface ipv4 add route prefix=%ls/%d interface=\"%ls\" "
                 L"metric=%d store=active",
                 wdst, prefix, wname, metric);
    }
    return run_hidden(cmd) == 0 ? VPN_OK : VPN_ERR_IO;
}

int vpn_tun_add_route_via(const char *dev_name, uint32_t dst, uint32_t mask,
                          uint32_t gateway)
{
    return vpn_tun_add_route_metric(dev_name, dst, mask, gateway, 5);
}

int vpn_tun_add_route(const char *dev_name, uint32_t dst, uint32_t mask)
{
    return vpn_tun_add_route_via(dev_name, dst, mask, 0);
}

int vpn_tun_del_route(const char *dev_name, uint32_t dst, uint32_t mask)
{
    char sdst[32];
    wchar_t wdst[32], wname[128], cmd[768];
    uint32_t m = ntohl(mask);
    int prefix = 0;

    if (!dev_name || !dev_name[0])
        return VPN_ERR_INVALID;

    while (m & 0x80000000u) {
        prefix++;
        m <<= 1;
    }

    vpn_ip_ntoa(dst, sdst, sizeof(sdst));
    utf8_to_wide(sdst, wdst, 32);
    utf8_to_wide(dev_name, wname, 128);

    swprintf(cmd, 768,
             L"netsh interface ipv4 delete route prefix=%ls/%d interface=\"%ls\" store=active",
             wdst, prefix, wname);
    if (run_hidden(cmd) == 0)
        return VPN_OK;

    /* 旧版本写入的是 persistent store，再按默认 store 删一次 */
    swprintf(cmd, 768,
             L"netsh interface ipv4 delete route prefix=%ls/%d interface=\"%ls\"",
             wdst, prefix, wname);
    return run_hidden(cmd) == 0 ? VPN_OK : VPN_ERR_IO;
}

int vpn_tun_set_dns_pref(const char *dev_name, uint32_t dns1, uint32_t dns2, int metric)
{
    wchar_t wname[128], w1[32], w2[32], cmd[768];

    if (!dev_name || !dev_name[0] || !dns1)
        return VPN_ERR_INVALID;

    utf8_to_wide(dev_name, wname, 128);
    {
        char b1[32], b2[32];
        vpn_ip_ntoa(dns1, b1, sizeof(b1));
        utf8_to_wide(b1, w1, 32);
        if (dns2) {
            vpn_ip_ntoa(dns2, b2, sizeof(b2));
            utf8_to_wide(b2, w2, 32);
        } else {
            w2[0] = 0;
        }
    }

    swprintf(cmd, 768, L"netsh interface ipv4 set dnsservers name=\"%ls\" source=static "
                       L"address=%ls register=primary", wname, w1);
    /* 刚配好地址时接口可能尚未就绪，失败就重试一次 */
    if (run_hidden(cmd) != 0) {
        Sleep(500);
        run_hidden(cmd);
    }

    if (w2[0]) {
        swprintf(cmd, 768, L"netsh interface ipv4 add dnsservers name=\"%ls\" address=%ls index=2",
                 wname, w2);
        run_hidden(cmd);
    }

    /* 关键：Windows 按“接口度量 + 路由度量”决定先用哪个网卡的 DNS。
     * 不压低接口度量时，查询顺序仍偏向物理网卡，内网域名解析不到。
     * 私有网段路由自带 6000 度量，本机直连路由优先的结论不受影响。 */
    if (metric > 0) {
        swprintf(cmd, 768,
                 L"netsh interface ipv4 set interface \"%ls\" metric=%d",
                 wname, metric);
        if (run_hidden(cmd) != 0)
            VPN_WARN("failed to set the interface metric for %s, DNS may not take effect", dev_name);
    }

    run_hidden(L"ipconfig /flushdns");
    return VPN_OK;
}

int vpn_tun_set_dns(const char *dev_name, uint32_t dns1, uint32_t dns2)
{
    return vpn_tun_set_dns_pref(dev_name, dns1, dns2, 0);
}

int vpn_tun_clear_dns(const char *dev_name)
{
    wchar_t wname[128], cmd[768];

    if (!dev_name || !dev_name[0])
        return VPN_ERR_INVALID;

    utf8_to_wide(dev_name, wname, 128);

    /* 清空静态 DNS（Wintun 没有 DHCP，只能用 address=none） */
    swprintf(cmd, 768,
             L"netsh interface ipv4 set dnsservers name=\"%ls\" source=static "
             L"address=none register=primary", wname);
    if (run_hidden(cmd) != 0) {
        swprintf(cmd, 768,
                 L"netsh interface ipv4 delete dnsservers name=\"%ls\" address=all", wname);
        run_hidden(cmd);
    }

    /* 度量还原为自动，避免断开后该网卡仍抢 DNS/路由优先级 */
    swprintf(cmd, 768,
             L"netsh interface ipv4 set interface \"%ls\" metric=automatic",
             wname);
    run_hidden(cmd);
    run_hidden(L"ipconfig /flushdns");
    return VPN_OK;
}

#endif /* _WIN32 */
