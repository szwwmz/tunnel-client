# Android 外壳接入说明

本目录是最小可运行的 Android 外壳骨架，协议栈完全复用 `core/`（同一份 C 代码，
与 CLI / Windows 行为一致）。

## 目录

```
app/src/main/cpp/vpn_jni.c                            JNI 桥（C）
app/src/main/java/com/example/vpnclient/VpnCore.kt     核心库门面（loadLibrary + 配置打包）
app/src/main/java/com/example/vpnclient/VpnClientService.kt  VpnService 生命周期
app/src/main/java/com/example/vpnclient/MainActivity.kt      最简连接界面
app/src/main/AndroidManifest.xml                     VpnService 声明（BIND_VPN_SERVICE）
```

## 关键时序（与桌面端不同）

Android 的 `VpnService.Builder` 必须先有 IP 地址才能 `establish()`，而 SSTP/L2TP/PPTP
的地址是服务器在 IPCP 阶段分配的。因此分两步：

1. `VpnCore.connect(cfg)` 以 **无 TUN** 模式跑协议栈（`cc.tun_fd = -1`）；
2. 回调进入 `STATE_CONNECTED`（PPP 已 up、地址已知），此时用
   `VpnCore.tunnelInfo().localIp/dns1` 构造 `Builder` → `establish()`；
3. `pfd.detachFd()` 后调用 `VpnCore.attachTun(fd)`，fd 所有权转给核心，
   IP 包从此刻起经 PPP 隧道转发。

核心侧对应接口：`vpn_capi_attach_tun_fd()`（capi）→ `vpn_client_attach_tun()`（client），
只能在尚未挂接 TUN 时成功，避免并发替换。

## 编译核心库

```bash
export NDK=$ANDROID_NDK_HOME
cmake -S . -B build-android \
  -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-24 \
  -DVPN_BUILD_TESTS=OFF -DCMAKE_BUILD_TYPE=Release
cmake --build build-android -j
```

产物 `libvpncore.so`。JNI 桥另行编译为 `libvpncore_jni.so`：

```bash
$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang \
  -shared -fPIC -Icore/include \
  platform/android/app/src/main/cpp/vpn_jni.c \
  -Lbuild-android -lvpncore -lssl -lcrypto -llog -o libvpncore_jni.so
```

## 依赖注意

- `core/src/vpn_tls.c` 用的是 OpenSSL 3，Android 需预先交叉编译 OpenSSL（或用
  Termux/`openssl-ndk` 的预编译产物），并把 `libssl.so`/`libcrypto.so` 放进 `jniLibs`。
- 若要避开 OpenSSL 授权/体积问题，可替换 `vpn_tls.h` 背后的实现为 mbedTLS，
  其余代码不需要改动（TLS 接口已经抽象）。
- `vpn_tun.c` / `vpn_net.c` 的 POSIX 分支在 Android 上可直接工作，但 `vpn_tun_create`
  不要调用——Android 一律走"外部 fd"路径。
- 忽略证书的风险：`cert_mode = CERT_IGNORE` 时 UI 必须明确提示（需求要求），
  当前骨架在 `VpnCore.buildConfig(certMode = ...)` 保留该开关。
- 端口非 443 时（SSTP）应在界面上提示穿透性下降，与 CLI 的提示一致。
