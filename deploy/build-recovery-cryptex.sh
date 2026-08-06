#!/bin/bash
set -euo pipefail
# ═══════════════════════════════════════════════════════════════════════════
# build-recovery-cryptex.sh — Build + install a Cryptex1 containing
# platform_ctl and the h3x security toolkit so they are available in
# recoveryOS (before the main volume mounts).
#
# This uses Apple's supported cryptexctl workflow:
#   1. Create an APFS disk image containing the signed binaries
#   2. Create a Cryptex1 bundle (sealed, personalized to this host)
#   3. Install the cryptex via cryptexctl install
#
# The result: platform_ctl, h3x_sentinel, h3x_lsof are available at
# /System/Volumes/Preboot/Cryptexes/OS/usr/local/bin/ during both
# normal boot and recovery boot.
#
# Requirements:
#   - macOS 14+ (Cryptex1 support)
#   - Developer ID Application cert in keychain (for signing binaries)
#   - Root (cryptexctl install requires root)
#   - SIP reduced security or developer mode for research cryptexes
#     (production cryptexes need Apple personalization server)
#
# Author: Derek Hinch | QomputeAI
# ═══════════════════════════════════════════════════════════════════════════

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${REPO_DIR}/build"
WORK="$(mktemp -d /tmp/h3x-cryptex.XXXXXX)"
trap 'rm -rf "${WORK}"' EXIT

CRYPTEXCTL="/System/Library/SecurityResearch/usr/bin/cryptexctl"
SIGN_ID="Developer ID Application: qomputeai inc (4HMYMNKRGB)"
ENTITLEMENTS="${REPO_DIR}/entitlements.plist"

CRYPTEX_ID="ai.qompute.platform-ctl"
CRYPTEX_VERSION="1.0.0"
CRYPTEX_VARIANT="PlatformSecurity"

# Binaries to include in the cryptex
BINS=(platform_ctl h3x_sentinel h3x_lsof h3x_rootsh)

log() { echo "[cryptex] $*"; }
fail() { echo "[cryptex] ERROR: $*" >&2; exit 1; }

# ── Preflight ──────────────────────────────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || fail "must run as root (cryptexctl install requires it)"
[ -x "$CRYPTEXCTL" ] || fail "cryptexctl not found at $CRYPTEXCTL"
[ -f "$ENTITLEMENTS" ] || fail "entitlements.plist not found"

for bin in "${BINS[@]}"; do
    [ -f "${BUILD_DIR}/${bin}" ] || fail "${bin} not built. Run: cd ${REPO_DIR} && make"
    codesign --verify --strict "${BUILD_DIR}/${bin}" 2>/dev/null || fail "${bin} not validly signed"
done

log "Building cryptex: ${CRYPTEX_ID} v${CRYPTEX_VERSION}"
log "  Binaries: ${BINS[*]}"

# ── Step 1: Create APFS disk image with the payload ──────────────────────────
DMG="${WORK}/payload.dmg"
MNT="${WORK}/mnt"
mkdir -p "$MNT"

# Size: 20MB is generous for these binaries
log "Step 1/4: Creating APFS disk image..."
hdiutil create -size 20m -fs APFS -volname "PlatformCTL" \
    -type SPARSE "$DMG" >/dev/null 2>&1
DMG="${DMG}.sparseimage"

# Mount it
hdiutil attach "$DMG" -mountpoint "$MNT" -nobrowse -noverify >/dev/null 2>&1

# Layout: /usr/local/bin/<binaries>
#         /usr/local/share/h3x/audit_launchd.sh
BIN_DST="${MNT}/usr/local/bin"
SHARE_DST="${MNT}/usr/local/share/h3x"
mkdir -p "$BIN_DST" "$SHARE_DST"

for bin in "${BINS[@]}"; do
    cp "${BUILD_DIR}/${bin}" "${BIN_DST}/${bin}"
    chmod 755 "${BIN_DST}/${bin}"
    # platform_ctl needs setuid even inside the cryptex
    if [ "$bin" = "platform_ctl" ] || [ "$bin" = "h3x_lsof" ] || [ "$bin" = "h3x_rootsh" ]; then
        chmod 4755 "${BIN_DST}/${bin}"
    fi
done

# Include the audit script
AUDIT_SRC="/Users/q/code/sentientNS/deploy/audit_launchd.sh"
if [ -f "$AUDIT_SRC" ]; then
    cp "$AUDIT_SRC" "${SHARE_DST}/audit_launchd.sh"
    chmod 755 "${SHARE_DST}/audit_launchd.sh"
fi

# Include a recovery-mode launcher script
cat > "${BIN_DST}/platform_ctl_recovery" << 'EOF'
#!/bin/ksh
# platform_ctl_recovery — recovery-mode entry point
# Runs platform_ctl with status + audit when invoked from recoveryOS terminal.
set -e
echo "═══ QomputeAI Platform Security — Recovery Mode ═══"
echo ""
/usr/local/bin/platform_ctl status 2>/dev/null || echo "(no services loaded in recovery — expected)"
echo ""
echo "Available commands:"
echo "  platform_ctl search -f <filter>"
echo "  platform_ctl info <service>"
echo "  platform_ctl mitigate -f <filter>"
echo "  h3x_lsof weights"
echo "  h3x_lsof net"
echo ""
echo "To verify main volume integrity before boot:"
echo "  diskutil verifyVolume /Volumes/Macintosh\\ HD"
echo "═════════════════════════════════════════════════════"
EOF
chmod 755 "${BIN_DST}/platform_ctl_recovery"

log "  Payload staged: $(du -sh "$MNT" | awk '{print $1}')"

# Detach
hdiutil detach "$MNT" >/dev/null 2>&1

# Convert sparse to read-only compressed DMG (required for cryptex sealing)
SEALED_DMG="${WORK}/platform_ctl.dmg"
hdiutil convert "$DMG" -format UDZO -o "$SEALED_DMG" >/dev/null 2>&1
log "  DMG created: $(du -sh "$SEALED_DMG" | awk '{print $1}')"

# ── Step 2: Create the Cryptex1 bundle ───────────────────────────────────────
log "Step 2/4: Creating Cryptex1 bundle..."
CRYPTEX_OUT="${WORK}/output"
mkdir -p "$CRYPTEX_OUT"

$CRYPTEXCTL create \
    --host-identity \
    --use-cryptex1-format \
    --identifier "$CRYPTEX_ID" \
    --version "$CRYPTEX_VERSION" \
    --variant "$CRYPTEX_VARIANT" \
    --output-directory "$CRYPTEX_OUT" \
    --replace \
    "$SEALED_DMG" 2>&1 | sed 's/^/  /'

CRYPTEX_BUNDLE="$(find "$CRYPTEX_OUT" -name "*.cxbd" -type d | head -1)"
if [ -z "$CRYPTEX_BUNDLE" ] || [ ! -d "$CRYPTEX_BUNDLE" ]; then
    fail "cryptex bundle not created (check cryptexctl output above)"
fi
log "  Bundle: $CRYPTEX_BUNDLE"

# ── Step 2b: Personalize via Apple's TSS (gs.apple.com) ──────────────────────
log "Step 2b/4: Personalizing cryptex via Apple TSS..."
SIGNED_OUT="${WORK}/signed"
mkdir -p "$SIGNED_OUT"
$CRYPTEXCTL personalize \
    --variant "$CRYPTEX_VARIANT" \
    --output-directory "$SIGNED_OUT" \
    --replace \
    "$CRYPTEX_BUNDLE" 2>&1 | sed 's/^/  /'

SIGNED_BUNDLE="$(find "$SIGNED_OUT" -name "*.cxbd" -type d | head -1)"
if [ -n "$SIGNED_BUNDLE" ] && [ -d "$SIGNED_BUNDLE" ]; then
    log "  Personalized bundle: $SIGNED_BUNDLE"
    CRYPTEX_BUNDLE="$SIGNED_BUNDLE"
else
    log "  (personalization failed or not available — attempting install with unsigned bundle)"
fi

# ── Step 3: Install the cryptex ──────────────────────────────────────────────
log "Step 3/4: Installing cryptex..."
$CRYPTEXCTL install \
    --print-info \
    "$CRYPTEX_BUNDLE" 2>&1 | sed 's/^/  /'

# ── Step 4: Verify ───────────────────────────────────────────────────────────
log "Step 4/4: Verifying installation..."
$CRYPTEXCTL list 2>&1 | grep -A2 "$CRYPTEX_ID" | sed 's/^/  /'

# Also copy the bundle to a persistent location for re-installs
PERSIST_DIR="${REPO_DIR}/dist/cryptex"
mkdir -p "$PERSIST_DIR"
rm -rf "${PERSIST_DIR}/${CRYPTEX_ID}.cxbd"
cp -R "$CRYPTEX_BUNDLE" "${PERSIST_DIR}/"
log "  Bundle persisted to: ${PERSIST_DIR}/"

log ""
log "═══════════════════════════════════════════════════════"
log "  CRYPTEX INSTALLED: ${CRYPTEX_ID} v${CRYPTEX_VERSION}"
log ""
log "  The following are now available in BOTH normal and"
log "  recovery boot at /usr/local/bin/:"
log "    platform_ctl          — service controller (always root)"
log "    h3x_sentinel          — runtime memory monitor"
log "    h3x_lsof              — privilege-separated lsof"
log "    h3x_rootsh            — restricted root broker"
log "    platform_ctl_recovery — recovery-mode entry point"
log ""
log "  In recoveryOS Terminal:"
log "    /usr/local/bin/platform_ctl_recovery"
log "═══════════════════════════════════════════════════════"
