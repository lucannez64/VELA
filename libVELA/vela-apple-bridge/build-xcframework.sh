#!/usr/bin/env bash
# Build the VELA Rust core as an iOS XCFramework (device + Apple-Silicon simulator).
# Requires macOS + Xcode + the Rust iOS targets. Output: VelaCore.xcframework.
set -euo pipefail
cd "$(dirname "$0")"

LIB=libvela_apple_bridge.a
OUT=VelaCore.xcframework
HEADERS=include

rustup target add aarch64-apple-ios aarch64-apple-ios-sim >/dev/null 2>&1 || true

echo "==> building for iOS device (aarch64-apple-ios)"
cargo build --release --target aarch64-apple-ios
echo "==> building for iOS simulator (aarch64-apple-ios-sim)"
cargo build --release --target aarch64-apple-ios-sim

rm -rf "$OUT"
xcodebuild -create-xcframework \
  -library "target/aarch64-apple-ios/release/$LIB" -headers "$HEADERS" \
  -library "target/aarch64-apple-ios-sim/release/$LIB" -headers "$HEADERS" \
  -output "$OUT"

echo "==> created $OUT"
