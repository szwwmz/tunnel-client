#!/usr/bin/env bash
# 汇总打包：把 Android / Windows / Linux 三端产物打成一个包。
# 包名带版本号：dist/vpn-client-all-<版本>.zip
#
# 用法：scripts/package_all.sh [版本号]
#   不传版本号时自动从 MainActivity.kt 的 VERSION 读取
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"

VER="${1:-}"
if [ -z "$VER" ]; then
    VER="$(grep -o 'const val VERSION = "[^"]*"' \
        "$ROOT/platform/android/app/src/main/java/com/example/vpnclient/MainActivity.kt" \
        | head -1 | sed 's/.*"\(.*\)"/\1/')"
fi
if [ -z "$VER" ]; then
    echo "无法确定版本号，请显式传入：scripts/package_all.sh 1.3.9" >&2
    exit 1
fi

APK="$DIST/android/vpn-client-android-$VER.apk"
if [ ! -f "$APK" ]; then
    # 允许刚编完还没按版本号改名的旧产物
    if [ -f "$DIST/android/vpn-client-android.apk" ]; then
        APK="$DIST/android/vpn-client-android.apk"
    else
        echo "缺少 Android 产物，请先运行 scripts/build_android.sh" >&2
        exit 1
    fi
fi

OUT="$DIST/vpn-client-all-$VER.zip"
rm -f "$OUT"
[ -f "$DIST/vpn-client-all.zip" ] && rm -f "$DIST/vpn-client-all.zip"

# 第三方组件声明：与二进制同包分发，且放在 exe 同目录便于查阅
# （Wintun Prebuilt Binaries License 要求随附许可文本）
cp -f "$ROOT/THIRD-PARTY-NOTICES.md" "$DIST/windows/THIRD-PARTY-NOTICES.txt"
cp -f "$ROOT/LICENSES/Wintun-Prebuilt-Binaries-License.txt" "$DIST/windows/LICENSE-wintun.txt"
cp -f "$ROOT/LICENSES/Apache-2.0.txt" "$DIST/windows/LICENSE-Apache-2.0.txt"
cp -f "$ROOT/THIRD-PARTY-NOTICES.md" "$DIST/linux/THIRD-PARTY-NOTICES.txt"
cp -f "$ROOT/LICENSE" "$DIST/linux/LICENSE.txt"

( cd "$DIST" && zip -qr "$OUT" \
    "$(realpath --relative-to="$DIST" "$APK")" \
    android/README.txt \
    windows/vpn-gui.exe windows/wintun.dll windows/app.ico windows/README.txt \
    windows/THIRD-PARTY-NOTICES.txt windows/LICENSE-wintun.txt windows/LICENSE-Apache-2.0.txt \
    linux/vpn-cli linux/libvpncore.so linux/README.md \
    linux/THIRD-PARTY-NOTICES.txt linux/LICENSE.txt )

echo "生成: $OUT"
ls -lh "$OUT"
