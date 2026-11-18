# Third-Party Notices / 第三方组件声明

本文件列出本项目所使用、链接或随包分发的第三方组件及其许可条件。
This file lists third-party components used, linked against or redistributed by
this project, together with the applicable license terms.

适用范围：`vpn-gui.exe`（Windows）、`vpn-cli` / `libvpncore.so`（Linux）、
`vpn-client-android-*.apk`（Android）。
Scope: `vpn-gui.exe` (Windows), `vpn-cli` / `libvpncore.so` (Linux) and
`vpn-client-android-*.apk` (Android).

---

## 1. 本项目自有内容 / Project's own material

除下列第三方组件外，`core/`、`cli/`、`platform/`、`tests/`、`scripts/` 下的全部
源代码、界面资源与图标均为本项目原创，版权归版权持有人所有，按仓库根目录的
`LICENSE` 授权。

All source code under `core/`, `cli/`, `platform/`, `tests/` and `scripts/`, as
well as all UI resources and the application icon (`app.ico`, generated in-house
from original artwork), are original works of this project, owned by the
copyright holder and licensed under the `LICENSE` file in the repository root.

- `app.ico` — 自绘图标，含 7 种尺寸，无第三方素材（不含图标库、字体或图库资源）。
  `app.ico` is an in-house generated icon (7 sizes). No stock icon, font or
  clip-art asset is embedded.

---

## 2. Wintun（Windows 虚拟网卡驱动 / Windows TUN driver）

| 项 / Item | 内容 / Details |
|---|---|
| 文件 / File | `wintun.dll` (Windows only) |
| 版本 / Version | 0.14.1 (official signed build, amd64) |
| SHA-256 | `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce` |
| 权利人 / Owner | WireGuard LLC / Jason A. Donenfeld |
| 许可 / License | Prebuilt Binaries License，全文见 `LICENSES/Wintun-Prebuilt-Binaries-License.txt` |

使用方式符合该许可第 3(b) 条"仅通过 `wintun.h` 提供的 API 接口使用"的要求：
本项目只通过 `WintunCreateAdapter` / `WintunStartSession` / `WintunReceivePacket` /
`WintunSendPacket` 等公开导出函数访问该 DLL，未修改、未逆向、未去除任何版权声明。

The DLL is used only through the published API surface declared in `wintun.h`
(License §3(b)). It is not modified, reverse engineered, nor are any proprietary
notices removed.

商标：Wintun™ 是 WireGuard LLC 的商标。本项目与 WireGuard 项目及 WireGuard LLC
无隶属或合作关系，其名称仅用于指明驱动来源，不构成任何背书。
Trademark: Wintun™ is a trademark of WireGuard LLC. This project is not
affiliated with, endorsed by or sponsored by the WireGuard project or
WireGuard LLC; the name is used solely to identify the driver component.

---

## 3. OpenSSL

| 项 / Item | 内容 / Details |
|---|---|
| 使用方式 / Usage | Linux 动态链接 `libssl`/`libcrypto`；Android 与 Windows **静态链接** |
| 版本 / Version | 3.0.2（Android/Windows 构建所用版本） |
| 许可 / License | Apache License 2.0，全文见 `LICENSES/Apache-2.0.txt` |
| 版权 / Copyright | Copyright 1998-2022 The OpenSSL Project Authors; Copyright 1995-1998 Eric A. Young, Tim J. Hudson |

Apache-2.0 要求保留版权与许可声明（§4）。静态链接进 `libvpncore.so` / `vpn-gui.exe`
的部分同样适用，声明随安装包内本文件提供。

---

## 4. Android NDK / libc++ / Kotlin

| 组件 / Component | 许可 / License |
|---|---|
| Android NDK（`libvpncore_jni.so` 编译工具链、`liblog`） | Apache-2.0 |
| libc++（NDK 内 C++ 运行时，静态链接） | Apache-2.0 with LLVM exception |
| Kotlin standard library（`classes.dex`） | Apache-2.0 |
| AndroidX / Google 支持库（若构建引入） | Apache-2.0 |

---

## 5. 协议规范 / Protocol specifications

协议实现为独立编写，未包含任何第三方协议栈源码。规范与授权依据：
The protocol implementations are written independently and contain no
third-party protocol stack code. The relevant specifications and their
licensing terms are:

- MS-SSTP：Microsoft Open Specification Promise（可免授权实现）
- L2TP：RFC 2661 / RFC 3931（IETF IPR 声明为免费）
- PPTP：RFC 2637
- PPP / LCP / IPCP：RFC 1661 / 1570 / 1332
- MS-CHAPv2：RFC 2759
- PPP ECP / MPPE：RFC 1968 / RFC 3078

DES（FIPS 46-3）、MD4（RFC 1320）、RC4 等算法的实现为本项目自写（见
`core/src/vpn_md4.c`、`core/src/vpn_des.c`、`core/src/vpn_crypto.c`），未复制
OpenSSL、pppd 或其他实现的代码。

---

## 6. 无其他第三方代码 / No other third-party code

仓库内除上述二进制与运行库外，未包含第三方源代码、图标、字体、音频或数据文件。
除了 `wintun.dll` 之外，代码中没有从 pppd、sstp-client、SoftEther、OpenVPN、
WireGuard 等项目复制而来的源文件；协议行为上的注释引用不构成代码复制。

Apart from the components listed above, no third-party source code, icons,
fonts, audio or data files are included. No source file other than `wintun.dll`
is copied from pppd, sstp-client, SoftEther, OpenVPN or WireGuard; comments
referencing protocol behaviour of those implementations are not code copying.

---

## 7. 更新方式 / How this file is maintained

新增或升级任何第三方组件时，必须同步更新本文件与 `LICENSES/` 目录，并在
`scripts/package_all.sh` 的打包清单中带上该文件，确保每个发布包内都含声明。
When adding or upgrading a third-party component, update this file and
`LICENSES/` accordingly and keep it in the packaging list of
`scripts/package_all.sh` so that every release bundle carries the notices.
