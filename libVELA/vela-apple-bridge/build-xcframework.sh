#!/usr/bin/env bash
# Build the VELA Rust core as an iOS XCFramework (device + Apple-Silicon simulator).
# Requires macOS + Xcode + the Rust iOS targets. Output: VelaCore.xcframework.
set -euo pipefail
cd "$(dirname "$0")"

LIB=libvela_apple_bridge.a
OUT=VelaCore.xcframework
HEADERS=include

rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios >/dev/null 2>&1 || true

echo "==> building for iOS device (aarch64-apple-ios)"
cargo build --release --target aarch64-apple-ios
echo "==> building for iOS simulator arm64 (aarch64-apple-ios-sim)"
cargo build --release --target aarch64-apple-ios-sim
echo "==> building for iOS simulator x86_64 (x86_64-apple-ios)"
cargo build --release --target x86_64-apple-ios

# A simulator slice in an XCFramework must be universal (arm64 + x86_64);
# lipo the two simulator builds into one fat library.
echo "==> lipo universal simulator library"
mkdir -p target/ios-sim-universal
lipo -create \
  "target/aarch64-apple-ios-sim/release/$LIB" \
  "target/x86_64-apple-ios/release/$LIB" \
  -output "target/ios-sim-universal/$LIB"

rm -rf "$OUT"
xcodebuild -create-xcframework \
  -library "target/aarch64-apple-ios/release/$LIB" -headers "$HEADERS" \
  -library "target/ios-sim-universal/$LIB" -headers "$HEADERS" \
  -output "$OUT"

echo "==> created $OUT"
