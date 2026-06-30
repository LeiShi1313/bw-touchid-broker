#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SWIFT_PACKAGE="$ROOT/macos/BWBrokerApp"
APP_NAME="BW Broker"
APP_DIR="$ROOT/build/macos/$APP_NAME.app"

cargo build --release --manifest-path "$ROOT/Cargo.toml"
swift build -c release --package-path "$SWIFT_PACKAGE"

rm -rf "$APP_DIR"
mkdir -p "$APP_DIR/Contents/MacOS" "$APP_DIR/Contents/Resources"

cp "$SWIFT_PACKAGE/.build/release/BWBrokerApp" "$APP_DIR/Contents/MacOS/BWBrokerApp"
cp "$ROOT/target/release/bw-broker" "$APP_DIR/Contents/Resources/bw-broker"
chmod +x "$APP_DIR/Contents/MacOS/BWBrokerApp" "$APP_DIR/Contents/Resources/bw-broker"

cat > "$APP_DIR/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleDisplayName</key>
  <string>BW Broker</string>
  <key>CFBundleExecutable</key>
  <string>BWBrokerApp</string>
  <key>CFBundleIdentifier</key>
  <string>io.github.leishi1313.bw-broker</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>BW Broker</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>0.1.0</string>
  <key>CFBundleVersion</key>
  <string>1</string>
  <key>LSMinimumSystemVersion</key>
  <string>13.0</string>
  <key>LSUIElement</key>
  <true/>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
PLIST

echo "Built $APP_DIR"
