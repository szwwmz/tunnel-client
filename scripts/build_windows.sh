#!/usr/bin/env bash
# 交叉编译 Windows 版（Linux 上用 mingw-w64），产物：dist/windows/vpn-gui.exe
#
# 依赖（第三方资源统一固化在 third_party/，见 third_party/README.md）：
#   apt install mingw-w64
#   third_party/openssl-mingw-x64   OpenSSL 静态库（mingw 版，include + lib64）
#   third_party/wintun/bin/amd64    wintun.dll（https://www.wintun.net，构建时自动拷到 dist）
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
THIRD="$ROOT/third_party"
CC="${CC:-x86_64-w64-mingw32-gcc}"
OUT="$ROOT/dist/windows"

# 依次尝试多个候选路径，取第一个存在的
pick_path() {
    for p in "$@"; do [ -e "$p" ] && { printf '%s' "$p"; return 0; }; done
    return 1
}

SSL_DIR="${OPENSSL_WIN_DIR:-}"
[ -n "$SSL_DIR" ] || SSL_DIR="$(pick_path "$THIRD/openssl-mingw-x64" /opt/mingw-ssl /tmp/mingw-ssl)" || {
    echo "找不到 mingw 版 OpenSSL：请放到 $THIRD/openssl-mingw-x64 或设置 OPENSSL_WIN_DIR" >&2
    exit 1
}

for d in "$SSL_DIR/lib64" "$SSL_DIR/lib"; do
    [ -f "$d/libssl.a" ] && SSL_LIB="$d" && break
done
if [ -z "${SSL_LIB:-}" ]; then
    echo "在 $SSL_DIR 下找不到 libssl.a，请检查 OpenSSL 安装" >&2
    exit 1
fi

mkdir -p "$OUT"

# 图标与版本信息资源
RC="${RC:-x86_64-w64-mingw32-windres}"
"$RC" --codepage=65001 -I"$ROOT/platform/windows" \
    "$ROOT/platform/windows/vpn-gui.rc" "$OUT/vpn-gui-res.o"

$CC -std=c11 -O2 -Wall -Wextra \
    -DWIN32_LEAN_AND_MEAN -D_WIN32_WINNT=0x0601 \
    -I"$ROOT/core/include" -I"$SSL_DIR/include" \
    "$ROOT"/core/src/*.c \
    "$ROOT/platform/windows/gui_win32.c" \
    "$OUT/vpn-gui-res.o" \
    -o "$OUT/vpn-gui.exe" \
    -L"$SSL_LIB" -lssl -lcrypto \
    -lws2_32 -lcrypt32 -ladvapi32 -liphlpapi -luser32 -lgdi32 -lcomctl32 -lshell32 \
    -mwindows -static-libgcc

# wintun.dll：运行时必需（TUN 设备），从 third_party 同步到分发目录
if [ -f "$THIRD/wintun/bin/amd64/wintun.dll" ]; then
    cp -f "$THIRD/wintun/bin/amd64/wintun.dll" "$OUT/wintun.dll"
else
    echo "警告: 缺少 $THIRD/wintun/bin/amd64/wintun.dll，Windows 版运行时需要它" >&2
fi

echo "生成: $OUT/vpn-gui.exe"
