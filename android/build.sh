#!/usr/bin/env bash
# 构建「短信同步」Android APK（不使用 Gradle / AndroidX）
# 依赖：JDK 11（javac）+ Android SDK build-tools 34 + platforms;android-34
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
SDK="${ANDROID_SDK_ROOT:-/opt/android-sdk}"
BT="$SDK/build-tools/34.0.0"
ANDROID_JAR="$SDK/platforms/android-34/android.jar"
KEYSTORE="/www/wwwroot/apk-build/keystore/release.keystore"
KEY_PASS_FILE="/www/wwwroot/apk-build/keystore/password.txt"
OUT="$ROOT/build/linyuyang-sms.apk"

if [ ! -x "$BT/aapt2" ]; then
  echo "找不到 Android build-tools：$BT" >&2
  exit 1
fi
if [ ! -f "$ANDROID_JAR" ]; then
  echo "找不到 android.jar：$ANDROID_JAR" >&2
  exit 1
fi
if [ ! -f "$KEYSTORE" ] || [ ! -f "$KEY_PASS_FILE" ]; then
  echo "缺少签名文件：$KEYSTORE 或 $KEY_PASS_FILE" >&2
  exit 1
fi

PASS="$(cat "$KEY_PASS_FILE")"
rm -rf "$ROOT/build"
mkdir -p "$ROOT/build/gen" "$ROOT/build/classes" "$ROOT/build/dex"

echo "[1/6] 编译资源"
"$BT/aapt2" compile --dir "$ROOT/res" -o "$ROOT/build/res.zip"

echo "[2/6] 链接资源与清单"
"$BT/aapt2" link \
  -o "$ROOT/build/base.apk" \
  -I "$ANDROID_JAR" \
  --manifest "$ROOT/AndroidManifest.xml" \
  -R "$ROOT/build/res.zip" \
  --java "$ROOT/build/gen" \
  --auto-add-overlay

echo "[3/6] 编译 Java"
javac -source 8 -target 8 \
  -bootclasspath "$ANDROID_JAR" \
  -encoding UTF-8 \
  -d "$ROOT/build/classes" \
  "$ROOT/build/gen/top/linyuyang/sms/R.java" \
  $(find "$ROOT/java" -name '*.java' | sort) > "$ROOT/build/javac.log" 2>&1 || {
    grep -v 'bootstrap class path' "$ROOT/build/javac.log" >&2 || true
    echo "Java 编译失败" >&2
    exit 1
  }
grep -v 'bootstrap class path' "$ROOT/build/javac.log" || true

echo "[4/6] 生成 classes.dex"
"$BT/d8" --lib "$ANDROID_JAR" --min-api 21 --output "$ROOT/build/dex" \
  $(find "$ROOT/build/classes" -name '*.class' | sort)

echo "[5/6] 打包并对齐"
( cd "$ROOT/build" && zip -q -j base.apk dex/classes.dex )
"$BT/zipalign" -f -p 4 "$ROOT/build/base.apk" "$ROOT/build/aligned.apk"

echo "[6/6] 签名"
"$BT/apksigner" sign \
  --ks "$KEYSTORE" \
  --ks-key-alias linyuyang \
  --ks-pass "pass:$PASS" \
  --key-pass "pass:$PASS" \
  --out "$OUT" \
  "$ROOT/build/aligned.apk"

"$BT/apksigner" verify --print-certs "$OUT"
echo "构建完成：$OUT"
