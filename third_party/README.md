# third_party —— 构建依赖的第三方资源

本目录保存三端构建所需的第三方库与工具链。**只有本说明入库**，目录内的二进制、
SDK、头文件都由 `.gitignore` 忽略（体积大，且可按下文重新获取）。

服务器上这些资源原先散落在 `/tmp`、`/opt` 各处，容器重启或清理 `/tmp` 后构建会失败，
因此统一固化到这里；`/opt/android-sdk`、`/opt/kotlinc` 保留同名符号链接指向本目录，
旧脚本或命令行工具仍可正常使用。

## 目录内容

| 路径 | 内容 | 版本 / 来源 |
|---|---|---|
| `openssl-mingw-x64/` | Windows 静态库 `libssl.a` / `libcrypto.a`（`lib64/`）+ 头文件 | OpenSSL 3.3.1（2024-06-04） |
| `openssl-android-arm64/` | Android arm64 静态库（`lib/`）+ 头文件 | OpenSSL 3.3.1 |
| `wintun/bin/amd64/wintun.dll` | Windows TUN 驱动 DLL | Wintun（https://www.wintun.net） |
| `wintun/include/wintun.h` | Wintun 头文件 | 同上 |
| `wintun/LICENSE.txt` | Wintun Prebuilt Binaries License | 同上（仓库 `LICENSES/` 内另有一份） |
| `android-sdk/` | Android SDK：platform-tools / platforms;android-34 / build-tools;34.0.0 / ndk;26.1.10909125 | Google Android SDK |
| `kotlinc/` | Kotlin 命令行编译器（`bin/kotlinc` + `lib/kotlin-stdlib.jar`） | JetBrains Kotlin |

## 重建方法

Windows 版 OpenSSL（交叉编译，静态库）：

```bash
./Configure mingw64 no-shared no-tests no-asm \
    --cross-compile-prefix=x86_64-w64-mingw32- --prefix=/opt/vpn/third_party/openssl-mingw-x64
make -j4 && make install_sw
```

Android 版 OpenSSL（arm64，NDK 工具链）：

```bash
export PATH=/opt/vpn/third_party/android-sdk/ndk/26.1.10909125/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH
./Configure android-arm64 no-shared no-tests \
    --prefix=/opt/vpn/third_party/openssl-android-arm64
make -j4 && make install_sw
```

Wintun：从 https://www.wintun.net 下载，取 `bin/amd64/wintun.dll`、`include/wintun.h`
与 `LICENSE.txt` 放入 `wintun/`。

Android SDK：`sdkmanager` 安装 `platform-tools`、`platforms;android-34`、
`build-tools;34.0.0`、`ndk;26.1.10909125` 到 `android-sdk/`。

## 构建脚本如何定位这些资源

`scripts/build_windows.sh`、`scripts/build_android.sh` 均**优先使用本目录**，
环境变量 `OPENSSL_WIN_DIR` / `OPENSSL_ANDROID_DIR` / `ANDROID_SDK_ROOT` / `KOTLINC`
可覆盖；找不到时会回退旧的系统路径（`/opt/mingw-ssl`、`/tmp/android-ssl`、`/opt/android-sdk`）。
`build_windows.sh` 编译完成后会把 `wintun/bin/amd64/wintun.dll` 自动复制到 `dist/windows/`。

## 许可

第三方组件的许可全文见仓库 `LICENSES/` 与根目录 `THIRD-PARTY-NOTICES.md`，
最终用户分发包（`dist/` 与 Release 附件）中已随附对应声明。
