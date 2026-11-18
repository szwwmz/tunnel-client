# Windows 外壳接入说明

Wintun（用户态 TUN 驱动）+ C#，协议栈复用 `core/`。

## 目录

```
VpnCoreApi.cs     vpn_capi 的 P/Invoke 声明（结构体、回调委托、导出函数）
Wintun.cs         wintun.dll 最小封装（适配器/会话/收发环形缓冲）
VpnClientApp.cs   控制台外壳：连接 → 建 Wintun → 挂接读回调 → 循环打印统计
```

## 依赖

- `wintun.dll`（按架构选 x86_64/arm64）：<https://www.wintun.net>，放到 exe 同目录。
- `vpncore.dll`：本仓库 `vpncore_shared` 目标的产物（导出 `vpn_capi_*`）。
- OpenSSL 3 的 `libssl-3-x64.dll` / `libcrypto-3-x64.dll` 与 vpncore.dll 同目录。
- 需要 **管理员权限**：创建 Wintun 适配器、修改路由。

## 构建

```bash
cmake -S . -B build-win -DCMAKE_TOOLCHAIN_FILE=... (或直接在 VS 中打开)
cmake --build build-win --config Release
```

C# 侧：

```bash
csc /platform:x64 /out:VpnClientApp.exe platform/windows/*.cs
# 或 dotnet new console + 复制三个 .cs（Wintun.cs 用到 DllImport，无需 NuGet）
```

## 运行时序

1. `vpn_capi_create`：`tun_fd = -1`，先以"无 TUN"模式连接；
2. `vpn_capi_wait` 返回 0（PPP 已 up，服务器已分配地址）；
3. 建 `WintunSession`，`netsh interface ip set address` 配置地址（生产环境建议改用
   IP Helper API 的 `CreateUnicastIpAddressEntry` 等接口）；
4. `vpn_capi_attach_tun(h, ref tun)` 把 `read/write/destroy` 三个 C 函数指针交给核心，
   之后就由核心的 worker 线程调用 Wintun 收发包。

回调签名（`vpn_capi_tun`）：
`read(ctx, buf, cap, timeout_ms) -> 字节数 / 0=超时 / <0=错误`，
`write(ctx, buf, len) -> len / <0=失败`，`destroy(ctx)`。

## 平台差异提醒

- **PPTP** 需要 GRE（IP 协议 47）RAW socket 权限，Windows 上通常被系统拒绝；
  核心的 `vpn_pptp_supported()` 会返回不支持，UI 应提示"该协议不安全且当前平台不可用"。
- **L2TP/IPsec**：IPsec 由系统负责（Windows 内置 IPsec 服务/组策略），核心只跑
  L2TP 明文部分，必须配合系统 IPsec 策略或单独的 IKE 守护进程。
- DNS 目前由外壳配置（`.addDnsServer` 等价物在 Windows 是 `netsh interface ip set dns`），
  核心只上报服务器下发的 DNS 地址。
