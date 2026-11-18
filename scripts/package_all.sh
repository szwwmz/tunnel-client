#!/usr/bin/env bash
# 汇总打包：把 Android / Windows / Linux 三端产物打成一个包。
# 包名带版本号：dist/tunnel-client-all-<版本>.zip
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

APK="$DIST/android/tunnel-client-android-$VER.apk"
if [ ! -f "$APK" ]; then
    # 允许刚编完还没按版本号改名的旧产物
    if [ -f "$DIST/android/tunnel-client-android.apk" ]; then
        APK="$DIST/android/tunnel-client-android.apk"
    else
        echo "缺少 Android 产物，请先运行 scripts/build_android.sh" >&2
        exit 1
    fi
fi

OUT="$DIST/tunnel-client-all-$VER.zip"
rm -f "$OUT"
[ -f "$DIST/tunnel-client-all.zip" ] && rm -f "$DIST/tunnel-client-all.zip"

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

# 上传到 GitHub Release（附件形式，不入库）
# 需要 GH_TOKEN 或 GITHUB_TOKEN（classic: repo；fine-grained: Contents 读写）
# 跳过方式：SKIP_RELEASE=1 scripts/package_all.sh
upload_release() {
    local token="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
    local url owner repo tag api rel_id asset_id
    url="$(git -C "$ROOT" remote get-url origin 2>/dev/null || true)"
    [ -n "$url" ] || { echo "无 origin，跳过 Release 上传"; return 0; }
    owner="$(printf '%s' "$url" | sed -E 's#.*[:/]([^/]+)/([^/]+?)(\.git)?$#\1#')"
    repo="$(printf '%s' "$url"  | sed -E 's#.*[:/]([^/]+)/([^/]+?)(\.git)?$#\2#')"
    tag="v$VER"
    api="https://api.github.com/repos/$owner/$repo"

    if [ -z "$token" ]; then
        echo "未设置 GH_TOKEN/GITHUB_TOKEN，跳过 Release 上传（手动命令见 README）" >&2
        return 0
    fi

    # 复用同 tag 的 Release，没有则创建
    rel_id="$(curl -sf -H "Authorization: Bearer $token" \
        -H "Accept: application/vnd.github+json" "$api/releases/tags/$tag" \
        | python3 -c 'import sys,json;print(json.load(sys.stdin).get("id",""))' 2>/dev/null || true)"
    if [ -z "$rel_id" ]; then
        rel_id="$(curl -sf -X POST -H "Authorization: Bearer $token" \
            -H "Accept: application/vnd.github+json" \
            -d "{\"tag_name\":\"$tag\",\"name\":\"$tag\",\"body\":\"Release $tag\",\"draft\":false,\"prerelease\":false}" \
            "$api/releases" \
            | python3 -c 'import sys,json;print(json.load(sys.stdin).get("id",""))' 2>/dev/null || true)"
    fi
    [ -n "$rel_id" ] || { echo "警告：Release 创建/获取失败（检查 token 权限）" >&2; return 1; }

    # 同名附件已存在则先删除，保证可重复上传
    asset_id="$(curl -sf -H "Authorization: Bearer $token" \
        -H "Accept: application/vnd.github+json" "$api/releases/$rel_id/assets" \
        | NAME="$(basename "$OUT")" python3 -c 'import sys,json,os;print(next((a["id"] for a in json.load(sys.stdin) if a["name"]==os.environ["NAME"]),""))' 2>/dev/null || true)"
    if [ -n "$asset_id" ]; then
        curl -sf -X DELETE -H "Authorization: Bearer $token" \
            -H "Accept: application/vnd.github+json" "$api/releases/assets/$asset_id" >/dev/null || true
    fi

    if curl -sf -X POST -H "Authorization: Bearer $token" \
        -H "Accept: application/vnd.github+json" \
        -H "Content-Type: application/zip" \
        --data-binary "@$OUT" \
        "https://uploads.github.com/repos/$owner/$repo/releases/$rel_id/assets?name=$(basename "$OUT")" >/dev/null; then
        echo "已上传 Release 附件: $tag / $(basename "$OUT")"
        echo "https://github.com/$owner/$repo/releases/tag/$tag"
    else
        echo "警告：Release 附件上传失败" >&2
        return 1
    fi
}

if [ "${SKIP_RELEASE:-0}" != "1" ]; then
    upload_release || true
fi
