#!/usr/bin/env bash
# Builds the k5 Android app (crates/k5android) into an APK, inside a Docker
# image with Rust, cargo-apk and the Android SDK and NDK
# (docker/android.Dockerfile), so nothing Android has to be installed here.
#
# The image is built once. The cargo registry and the signing key are kept in
# Docker volumes, and the build in target/android/ (apart from the host's
# target/), so later builds are incremental. On Apple Silicon the image runs
# emulated (x86_64): the first build takes a long while.
#
# The APK is signed with a debug key: fine to install on your own devices,
# not to publish.
#
# Usage: ./k5-android.sh [--install]
#   --install  also install it on the device connected over adb (needs adb
#              on this machine, e.g. `brew install android-platform-tools`).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
IMAGE=k5-android-build
APK=target/android/release/apk/k5.apk

INSTALL=0
if [ "${1:-}" = "--install" ]; then
    INSTALL=1
fi

# Docker Desktop's per-user install and OrbStack keep the CLI off the PATH.
for dir in "$HOME/.docker/bin" /Applications/Docker.app/Contents/Resources/bin \
    "$HOME/.orbstack/bin"; do
    if ! command -v docker >/dev/null && [ -x "$dir/docker" ]; then
        PATH="$dir:$PATH"
    fi
done
if ! command -v docker >/dev/null; then
    echo "Docker is needed: install Docker Desktop (or OrbStack), with Rosetta" >&2
    echo "for x86_64 images on Apple Silicon." >&2
    exit 1
fi
if ! docker info >/dev/null 2>&1; then
    echo "Docker is installed but not running: start Docker Desktop (or OrbStack)." >&2
    exit 1
fi

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "Building the $IMAGE image (Rust, Android SDK and NDK; only once) ..."
    docker build --platform linux/amd64 -t "$IMAGE" \
        -f "$ROOT/docker/android.Dockerfile" "$ROOT/docker"
fi

echo "Building the APK ..."
docker run --rm --platform linux/amd64 \
    -v "$ROOT:/k5" -w /k5 \
    -v k5-android-cargo-registry:/usr/local/cargo/registry \
    -v k5-android-cargo-git:/usr/local/cargo/git \
    -v k5-android-keys:/root/.android \
    -e CARGO_TARGET_DIR=/k5/target/android \
    "$IMAGE" bash -euo pipefail -c '
        # The signing key, kept in its volume: updates install over the
        # previous version.
        KEYSTORE=/root/.android/debug.keystore
        if [ ! -f "$KEYSTORE" ]; then
            keytool -genkeypair -keystore "$KEYSTORE" -storepass android \
                -keypass android -alias androiddebugkey -keyalg RSA \
                -keysize 2048 -validity 10000 \
                -dname "CN=Android Debug,O=Android,C=US" >/dev/null
        fi
        export CARGO_APK_RELEASE_KEYSTORE="$KEYSTORE"
        export CARGO_APK_RELEASE_KEYSTORE_PASSWORD=android
        # 16 KB memory pages (see .cargo/config.toml, which cargo-apk
        # overrides with its own flags).
        export CARGO_ENCODED_RUSTFLAGS="-Clink-arg=-Wl,-z,max-page-size=16384"

        cargo apk build --release -p k5android --lib
    '

echo
echo "APK: $ROOT/$APK"

if [ "$INSTALL" = 1 ]; then
    if ! command -v adb >/dev/null; then
        echo "adb not found: install it (brew install android-platform-tools)," >&2
        echo "or copy the APK to the phone and open it there." >&2
        exit 1
    fi
    adb install -r "$ROOT/$APK"
    echo "Installed: open K5 on the phone. Logs: adb logcat -s k5"
fi
