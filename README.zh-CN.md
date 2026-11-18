# tunnel-client（跨平台隧道客户端）

[English](README.md) | 简体中文

核心协议栈用 C11 实现，Linux / Android / Windows 三个外壳共用同一份代码，
保证协议行为、证书策略、统计口径完全一致。

## 支持的协议

| 协议 | 说明 | 状态 |
| --- | --- | --- |
| SSTP | MS-SSTP：TCP(443) + TLS + PPP over HDLC + MPPE 密钥握手 / Crypto-Binding | 可用 |
| L2TP | RFC 2661 控制与承载；IPsec 由平台侧负责（Windows 系统 IPsec / Linux strongSwan） | 可用 |
| PPTP | RFC 2637（TCP 1723 控制 + GRE 数据面）；**明文 PPTP 已被证明不安全**，UI 必须提示 | 视平台可用 |

## 目录结构

```
core/include/vpncore/  对外头文件（含给外壳用的稳定 C ABI: vpn_capi.h）
core/src/              协议实现
  vpn_client.c         生命周期编排：选传输层、PPP 交叉回调、TUN 转发、重连、统计
  vpn_tls.c            TLS 抽象（OpenSSL 3，可换成 mbedTLS）
  vpn_sstp.c vpn_l2tp.c vpn_pptp.c
  vpn_ppp*.c           LCP / IPCP / CHAP / PAP / 帧封装
  vpn_crypto.c vpn_md4.c vpn_des.c   MS-CHAPv2 / MPPE / MD4 / DES
  vpn_tun.c            虚拟网卡（Linux /dev/net/tun，Android/Windows 走外部回调）
  vpn_net.c            非阻塞 socket（poll / Winsock）
  vpn_capi.c           C ABI 薄封装（配置转换 + 回调转发）
cli/main.c             Linux 命令行客户端
platform/android/      VpnService + JNI 外壳
platform/windows/      Wintun + C# 外壳
tests/                 单元测试（HDLC/MS-CHAPv2/SSTP 报文/L2TP AVP/C ABI）
```

## 构建（Linux）

```bash
sudo apt install build-essential cmake libssl-dev
cmake -S . -B build && cmake --build build -j
cd build && ctest --output-on-failure
```

产物：`libvpncore.a`、`libvpncore.so`、`vpn-cli`、若干测试可执行文件。

## 打包与发布

`scripts/build_windows.sh`、`scripts/build_android.sh` 与 `scripts/package_all.sh`
生成 `dist/tunnel-client-all-<版本>.zip`。`dist/` 不入 git，发布包以 GitHub Release
附件形式上传：

```bash
GH_TOKEN=<具备 Contents 读写权限的 token> scripts/package_all.sh 1.4.0
```

脚本会自动创建（或复用）`v<版本>` 的 Release，并替换同名附件；`SKIP_RELEASE=1`
可跳过上传，仅保留本地 zip。

## 使用（CLI）

```bash
# 只验证连通性（不创建 TUN，无需 root）
./build/vpn-cli -s vpn.example.com -u alice -p secret --no-tun

# 完整连接（需要 root 创建 TUN）
sudo ./build/vpn-cli -s vpn.example.com -u alice -p secret

# L2TP（IPsec 由系统预先建立）
sudo ./build/vpn-cli -s vpn.example.com --proto l2tp -u alice -p secret

# 忽略证书校验（仅自签名测试环境，同时会打印风险提示）
sudo ./build/vpn-cli -s 10.0.0.1 -u alice -p secret --cert ignore
```

常用参数：`--port`、`--proto`、`--mtu`、`--ca-file`、`--cert verify|ignore`、
`--route CIDR`（可重复）、`--keepalive`、`--reconnect-delay`、`--max-retries`、
`--timeout`、`--stats-interval`、`-v/-q`。完整列表见 `vpn-cli --help`。

## 证书策略

- 默认 **verify**：校验证书链（若有 `--ca` 则用自定义根）、有效期、主机名
  （`SSL_set1_host`），并在日志里打印 SHA-256 指纹。
- **ignore**（`--cert ignore` / `cert_mode=1`）：跳过校验，但仍打印指纹，
  CLI 与外壳都会显式警告；需求要求该开关必须可见且可切回。
- TLS 最低版本放宽到 1.0 且 `SECLEVEL=1`，以兼容 RouterOS 等老实现；
  如需强制现代 TLS，改 `vpn_tls.c` 里的版本设置即可。

## 端口规则

| 协议 | 端口 | 可否修改 |
|---|---|---|
| SSTP | TCP/443 | **可改**，GUI 端口框可编辑，CLI 用 `--port N` |
| L2TP | UDP/1701 | **固定**，GUI 端口框自动禁用，`--port` 被忽略 |
| PPTP | TCP/1723 | **固定**，GUI 端口框自动禁用，`--port` 被忽略 |

SSTP 默认 443，与 HTTPS 流量特征一致，穿透性最好；改用其它端口时
CLI/GUI 会打印"穿透性可能下降"的提示。

L2TP/PPTP 是标准端口协议（RouterOS 侧监听 1701/1723），因此客户端不开放端口配置：
即使配置文件或 `--port` 里带了别的值，核心层也会归一化为协议默认端口并给出警告。

## 路由与 DNS

连接成功后客户端会：

1. 先为 VPN 服务器 IP 加一条走**原网关**的 /32 主机路由，避免隧道自身成环；
2. 下发服务器通过 IPCP 分配的地址/掩码/DNS；
3. 卸载时删除上述路由。

Android 上路由/DNS 由 `VpnService.Builder` 负责，Windows 上由外壳调用 netsh/API。

## 各平台协议可用性

| 协议 | Linux | Windows | Android（未 root） |
|---|---|---|---|
| SSTP（TCP 443/TLS） | ✓ | ✓ | ✓ |
| L2TP（UDP 1701） | ✓ | ✓ | 仅纯 L2TP；要求 IPSec 时 ESP 原始套接字不可用 |
| PPTP（GRE 47） | ✓（需 CAP_NET_RAW） | ✓（WFP） | ✗ 无法创建 GRE 原始套接字 |

PPTP 的数据面需要 IP 协议 47 的原始套接字，未 root 的 Android 应用没有
`CAP_NET_RAW`，`socket(AF_INET, SOCK_RAW, 47)` 直接返回 EPERM，因此核心在
`vpn_pptp_supported()` 里对 Android 返回 false，客户端也会在界面上提示并阻止连接，
而不是让用户连上却一个包都发不出去。

## 统计与日志

`vpn_stats` 提供收发字节/包数、丢包、重连次数、RTT、连接建立时刻、本机/对端地址、
DNS、加密套件、证书指纹。日志分 5 级（TRACE/DEBUG/INFO/WARN/ERROR），可通过
`vpn_capi_set_log_callback` 转到 Android logcat / Windows 窗口。

默认级别为 INFO：只输出连接各阶段的关键节点（TCP/控制通道/呼叫/GRE 首包/LCP 确认/
认证/IPCP/连通），逐包诊断一律在 DEBUG。Windows 端由 `vpn-gui.ini` 的 `debug` 项控制：

```ini
; 1 = 输出逐包调试日志（排障用），0 = 默认精简
debug=0
```

GRE 头格式须与对端一致：`flags=0x3001`（K+S+Ver1）并在 Call ID 后带 4 字节序列号。
省略序列号（0x2001）时，RouterOS 会按自己的头格式取字段，把 `FF03C021` 当成序列号，
PPP 帧整体错位后被静默丢弃，表现为"GRE 一直发、对端一个都不回"。

## 平台外壳

- Android：见 `platform/android/README.md`（VpnService 两阶段建隧道）
- Windows：见 `platform/windows/README.md`（Wintun 回调式 TUN）

## 已知限制

- PPTP 数据面需要 GRE RAW socket，多数平台默认禁用；核心会通过
  `vpn_pptp_supported()` 报不支持。
- L2TP 只实现明文 L2TPv2，IPsec 必须由系统或独立 IKE 进程提供。
- MPPE 只求出密钥用于 SSTP Crypto-Binding；若需 L2TP 数据面 MPPE 加密，
  需扩展 `vpn_ppp_rx/tx` 的 RC4 处理（40/56/128 位）。
- 单元测试不依赖真实服务器；端到端联调需要可用的 SSTP/L2TP 服务端。
## 第三方组件

本项目自有代码（`core/`、`cli/`、`platform/`、`tests/` 以及自绘的 `app.ico` 图标）
为原创作品；发布包里包含或链接了以下第三方组件：

| 组件 | 使用方 | 许可 |
|---|---|---|
| Wintun 0.14.1（`wintun.dll`，官方签名 amd64 构建） | Windows | Wintun Prebuilt Binaries License |
| OpenSSL 3.0.2 | Linux（动态）、Android/Windows（静态） | Apache-2.0 |
| Android NDK / libc++ / Kotlin stdlib | Android | Apache-2.0 |

Wintun 仅通过其公开 API（`wintun.h`）调用，未做修改；Wintun™ 是 WireGuard LLC 的
商标，本项目与 WireGuard 项目无隶属关系、未获其背书。许可全文见 `LICENSES/` 与
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)；每个发布包都在二进制同级附带
同样的声明（Android 端在「关于 → 第三方组件」可查看）。

## 许可

MIT 许可，详见 [LICENSE](LICENSE)。允许自由使用、修改、分发与再许可（含商业用途），
只需保留版权声明与许可声明。第三方组件仍按上表所列各自许可执行。
