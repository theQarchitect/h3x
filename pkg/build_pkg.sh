#!/bin/bash
# Build signed macOS installer package for H3X
# Installs tools to /usr/local/bin, daemon to /Library/LaunchDaemons
set -e
cd "$(dirname "$0")/.."

VERSION="1.3.0"
IDENTIFIER="ai.qompute.h3x.sentinel"
SIGN_ID="${SIGN_ID:-Developer ID Installer: qomputeai inc (4HMYMNKRGB)}"
APP_SIGN_ID="${APP_SIGN_ID:-Developer ID Application: qomputeai inc (4HMYMNKRGB)}"

echo "═══════════════════════════════════════════════════════════════════"
echo "  H3X Package Builder v${VERSION}"
echo "═══════════════════════════════════════════════════════════════════"
echo

# Step 1: Build hardened binaries
echo "  [1/5] Building hardened binaries..."
if [ ! -f build/h3x_analyze ]; then
    bash build.sh
else
    echo "    (using existing build/)"
fi

# Step 2: Create package payload structure
echo "  [2/5] Creating package payload..."
PKG_ROOT=$(mktemp -d)
mkdir -p /usr/local/bin
mkdir -p /usr/local/lib
mkdir -p /usr/local/include
mkdir -p "$HOME/Library/LaunchAgents"

# Copy binaries
cp build/h3x_* /usr/local/bin/
cp build/libh3x.dylib /usr/local/lib/ 2>/dev/null || true
cp include/h3x_format.h /usr/local/include/

# Copy LaunchDaemon
cp ./pkg/ai.qompute.h3x.sentinel.plist "$HOME/Library/LaunchAgents/"

# Set permissions
chmod 755 /usr/local/bin/h3x_*
chmod 644 "$HOME/Library/LaunchAgents/"*.plist
chmod 644 /usr/local/include/*.h

# Step 3: Create component package
echo "  [3/5] Building component package..."
mkdir -p dist

pkgbuild \
    --root "$PKG_ROOT" \
    --identifier "$IDENTIFIER" \
    --version "$VERSION" \
    --ownership recommended \
    --scripts pkg/scripts \
    dist/h3x-component.pkg

# Step 4: Create distribution package (signed)
echo "  [4/5] Creating signed distribution package..."

cat > /tmp/h3x_distribution.xml << DISTXML
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>H3X Quaternionic Binary Geometry Toolkit</title>
    <organization>ai.qompute</organization>
    <domains enable_localSystem="true"/>
    <options customize="never" require-scripts="true" rootVolumeOnly="true"/>
    <welcome file="welcome.html"/>
    <license file="LICENSE"/>
    <pkg-ref id="$IDENTIFIER"/>
    <choices-outline>
        <line choice="default">
            <line choice="$IDENTIFIER"/>
        </line>
    </choices-outline>
    <choice id="default"/>
    <choice id="$IDENTIFIER" visible="false">
        <pkg-ref id="$IDENTIFIER"/>
    </choice>
    <pkg-ref id="$IDENTIFIER" version="$VERSION" onConclusion="none">h3x-component.pkg</pkg-ref>
</installer-gui-script>
DISTXML

productbuild \
    --distribution /tmp/h3x_distribution.xml \
    --package-path dist \
    --resources pkg/resources \
    --sign "$SIGN_ID" \
    "dist/H3X-${VERSION}.pkg"

# Step 5: Verify
echo "  [5/5] Verifying package..."
pkgutil --check-signature "dist/H3X-${VERSION}.pkg"

echo
echo "═══════════════════════════════════════════════════════════════════"
echo "  Package: dist/H3X-${VERSION}.pkg"
echo "  Signed:  $SIGN_ID"
echo "  Install: sudo installer -pkg dist/H3X-${VERSION}.pkg -target /"
echo "═══════════════════════════════════════════════════════════════════"

# Cleanup
rm -rf "$PKG_ROOT"
rm -f dist/h3x-component.pkg
