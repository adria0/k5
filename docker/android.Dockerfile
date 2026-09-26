# Android build environment for k5android (the k5 window on Android), used by
# k5-android.sh: Rust with the aarch64-linux-android target, cargo-apk, and
# the Android SDK and NDK, so none of it has to be installed on the host.
#
# linux/amd64 only: Google publishes the NDK for x86_64 Linux hosts only (on
# Apple Silicon, Docker runs it with Rosetta).

FROM --platform=linux/amd64 rust:1.97-bookworm

# Java for the SDK tools and keytool; clang, python3 and git in case Skia
# (Slint's Android renderer) has to be built from source.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openjdk-17-jdk-headless unzip wget clang libclang-dev python3 git \
    && rm -rf /var/lib/apt/lists/*

ENV ANDROID_HOME=/opt/android-sdk
ENV ANDROID_SDK_ROOT=/opt/android-sdk
ARG CMDLINE_TOOLS=11076708
ARG NDK_VERSION=27.2.12479018
RUN mkdir -p "$ANDROID_HOME/cmdline-tools" \
    && wget -q "https://dl.google.com/android/repository/commandlinetools-linux-${CMDLINE_TOOLS}_latest.zip" -O /tmp/tools.zip \
    && unzip -q /tmp/tools.zip -d "$ANDROID_HOME/cmdline-tools" \
    && mv "$ANDROID_HOME/cmdline-tools/cmdline-tools" "$ANDROID_HOME/cmdline-tools/latest" \
    && rm /tmp/tools.zip \
    && (yes | "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" --licenses > /dev/null) \
    && "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" \
        "platform-tools" "platforms;android-34" "build-tools;34.0.0" "ndk;${NDK_VERSION}"
ENV ANDROID_NDK_ROOT=/opt/android-sdk/ndk/27.2.12479018

RUN rustup target add aarch64-linux-android \
    && cargo install cargo-apk --version 0.10.0 --locked

WORKDIR /k5
