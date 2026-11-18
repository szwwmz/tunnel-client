#!/usr/bin/env bash
# 纯命令行构建 Android APK（不依赖 Gradle）
#
# 依赖（第三方资源统一固化在 third_party/，见 third_party/README.md）：
#   third_party/android-sdk   platform-tools / platforms;android-34 /
#                             build-tools;34.0.0 / ndk;26.1.10909125
#   third_party/kotlinc       Kotlin 编译器
#   third_party/openssl-android-arm64  OpenSSL (arm64, 静态库)
#
# 产物：dist/android/tunnel-client-android-<版本>.apk
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
THIRD="$ROOT/third_party"
# 依次尝试多个候选路径，取第一个存在的
pick_path() {
    for p in "$@"; do [ -e "$p" ] && { printf '%s' "$p"; return 0; }; done
    return 1
}

SDK="${ANDROID_SDK_ROOT:-}"
[ -n "$SDK" ] || SDK="$(pick_path "$THIRD/android-sdk" /opt/android-sdk)" || {
    echo "找不到 Android SDK：请放到 $THIRD/android-sdk 或设置 ANDROID_SDK_ROOT" >&2
    exit 1
}
NDK="$SDK/ndk/26.1.10909125"
TC="$NDK/toolchains/llvm/prebuilt/linux-x86_64"
CC="$TC/bin/aarch64-linux-android24-clang"
KOTLINC="${KOTLINC:-$THIRD/kotlinc/bin/kotlinc}"
[ -x "$KOTLINC" ] || KOTLINC="$(pick_path /opt/kotlinc/bin/kotlinc)" || {
    echo "找不到 kotlinc：请放到 $THIRD/kotlinc 或设置 KOTLINC" >&2
    exit 1
}
# kotlinc 只是编译器，运行时要靠 stdlib；不打进 dex 就会
# NoClassDefFoundError: kotlin/jvm/internal/Intrinsics（启动即闪退）
KOTLIN_STDLIB="${KOTLIN_STDLIB:-$(cd "$(dirname "$KOTLINC")/../lib" && pwd)/kotlin-stdlib.jar}"
ANDROID_JAR="$SDK/platforms/android-34/android.jar"
BUILD_TOOLS="$SDK/build-tools/34.0.0"
SSL_DIR="${OPENSSL_ANDROID_DIR:-$(pick_path "$THIRD/openssl-android-arm64" /tmp/android-ssl)}"
APP="$ROOT/platform/android/app/src/main"
# 与 Windows 端同一版本号（platform/windows/vpn-gui.rc 同步升）
APK_VERSION_NAME="${APK_VERSION_NAME:-1.4.0}"
APK_VERSION_CODE="${APK_VERSION_CODE:-150}"
OUT="$ROOT/build-android"
# 产物名带版本号，避免多个版本混在一个固定文件名里
APK_FILE="tunnel-client-android-${APK_VERSION_NAME}.apk"
DIST="$ROOT/dist/android"

ABI=arm64-v8a
mkdir -p "$OUT/lib/$ABI" "$OUT/classes" "$OUT/dex" "$OUT/res" "$DIST"

echo "== 1/6 编译 libvpncore.so =="
"$CC" -shared -fPIC -O2 -std=c11 -D_GNU_SOURCE -D__ANDROID_API__=24 \
    -I"$ROOT/core/include" -I"$SSL_DIR/include" \
    "$ROOT"/core/src/*.c \
    -o "$OUT/lib/$ABI/libvpncore.so" \
    -L"$SSL_DIR/lib" -lssl -lcrypto -llog -ldl \
    -s -Wl,--gc-sections -ffunction-sections -fdata-sections

echo "== 2/6 编译 libvpncore_jni.so =="
"$CC" -shared -fPIC -O2 -std=c11 -D_GNU_SOURCE -D__ANDROID_API__=24 \
    -I"$ROOT/core/include" \
    "$APP/cpp/vpn_jni.c" \
    -o "$OUT/lib/$ABI/libvpncore_jni.so" \
    -L"$OUT/lib/$ABI" -lvpncore -llog -s

echo "== 3/6 编译 Kotlin =="
"$KOTLINC" -nowarn -jvm-target 17 \
    -classpath "$ANDROID_JAR" \
    "$APP"/java/com/example/vpnclient/*.kt \
    -d "$OUT/classes"

echo "== 4/6 aapt2 链接资源 =="
if [ -d "$APP/res" ]; then
    "$BUILD_TOOLS/aapt2" compile --dir "$APP/res" -o "$OUT/res.zip"
    RES_ARG=(-R "$OUT/res.zip")
else
    RES_ARG=()
fi
# assets 必须显式喂给 aapt2（-A），否则「关于 → 第三方组件」读不到许可文本
if [ -d "$APP/assets" ]; then
    ASSET_ARG=(-A "$APP/assets")
else
    ASSET_ARG=()
fi
"$BUILD_TOOLS/aapt2" link \
    -o "$OUT/base.apk" \
    -I "$ANDROID_JAR" \
    --manifest "$APP/AndroidManifest.xml" \
    --min-sdk-version 24 --target-sdk-version 34 \
    --version-code "$APK_VERSION_CODE" --version-name "$APK_VERSION_NAME" \
    --auto-add-overlay \
    "${ASSET_ARG[@]}" \
    "${RES_ARG[@]}"

echo "== 5/6 dex =="
if [ ! -f "$KOTLIN_STDLIB" ]; then
    echo "缺少 kotlin-stdlib: $KOTLIN_STDLIB" >&2
    exit 1
fi
# 除业务 class 外必须把 kotlin-stdlib 一并 dex，否则运行期找不到
# Intrinsics / Lazy / ArrayDeque 等，进程一启动就闪退
"$BUILD_TOOLS/d8" --min-api 24 --lib "$ANDROID_JAR" \
    --output "$OUT/dex" $(find "$OUT/classes" -name '*.class') "$KOTLIN_STDLIB"

cp "$OUT/dex/classes.dex" "$OUT/"
( cd "$OUT" && zip -q -u base.apk classes.dex )
mkdir -p "$OUT/apk/lib/$ABI"
cp "$OUT/lib/$ABI/"*.so "$OUT/apk/lib/$ABI/"
( cd "$OUT/apk" && zip -q -r ../base.apk lib )
"$BUILD_TOOLS/zipalign" -f -p 4 "$OUT/base.apk" "$OUT/base-aligned.apk"

echo "== 6/6 签名 =="
if [ ! -f "$OUT/debug.keystore" ]; then
    keytool -genkeypair -keystore "$OUT/debug.keystore" -storepass android \
        -keypass android -alias androiddebugkey -keyalg RSA -keysize 2048 \
        -validity 10000 -dname "CN=Android Debug,O=Android,C=US" > /dev/null 2>&1
fi
"$BUILD_TOOLS/apksigner" sign --ks "$OUT/debug.keystore" \
    --ks-pass pass:android --key-pass pass:android \
    --v1-signing-enabled true --v2-signing-enabled true \
    --out "$DIST/$APK_FILE" "$OUT/base-aligned.apk"

"$BUILD_TOOLS/apksigner" verify --print-certs "$DIST/$APK_FILE" | head -4
ls -lh "$DIST/$APK_FILE"
echo "生成: $DIST/$APK_FILE"
