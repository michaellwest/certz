#!/usr/bin/env bash
# Build certz for Linux (linux-x64)
# Run this on a Linux machine or inside a Linux container.
set -e

OUTPUT_DIR="${1:-linux-release}"
CONFIGURATION="${2:-Release}"

echo "Building certz for linux-x64 -> $OUTPUT_DIR/"

dotnet publish src/certz/certz.csproj \
  -c "$CONFIGURATION" \
  -r linux-x64 \
  --self-contained true \
  -p:PublishSingleFile=true \
  -p:PublishTrimmed=true \
  -o "$OUTPUT_DIR"

chmod +x "$OUTPUT_DIR/certz"

HASH=$(sha256sum "$OUTPUT_DIR/certz" | awk '{print $1}')

# Write checksums.txt (sha256sum-compatible format)
VERSION=$(grep -oP '(?<=<Version>)[^<]+' src/certz/certz.csproj 2>/dev/null || echo "")
if [ -n "$VERSION" ]; then
    BINARY_NAME="certz-${VERSION}-linux-x64"
else
    BINARY_NAME="certz"
fi
echo "$HASH  $BINARY_NAME" >> "$OUTPUT_DIR/checksums.txt"

echo ""
echo "Build complete: $OUTPUT_DIR/certz"
echo "SHA256: $HASH"
echo "Checksums: $OUTPUT_DIR/checksums.txt"
