#!/usr/bin/env bash
# 交叉编译 Windows 版（Linux 上用 mingw-w64），产物：dist/windows/vpn-gui.exe
#
# 依赖：
#   apt install mingw-w64
#   OpenSSL 静态库（mingw 版），默认取 $OPENSSL_WIN_DIR/lib64 或 lib
#     ./Configure mingw64 no-shared no-tests no-asm --cross-compile-prefix=x86_64-w64-mingw32- \
#         --prefix=/opt/mingw-ssl && make -j4 && make install_sw
#   wintun.dll（放 dist/windows/ 下，从 https://www.wintun.net 下载）
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CC="${CC:-x86_64-w64-mingw32-gcc}"
SSL_DIR="${OPENSSL_WIN_DIR:-/opt/mingw-ssl}"
OUT="$ROOT/dist/windows"

for d in "$SSL_DIR/lib64" "$SSL_DIR/lib"; do
    [ -f "$d/libssl.a" ] && SSL_LIB="$d" && break
done
if [ -z "${SSL_LIB:-}" ]; then
    echo "找不到 mingw 版 libssl.a，请设置 OPENSSL_WIN_DIR" >&2
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

echo "生成: $OUT/vpn-gui.exe"
