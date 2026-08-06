#!/bin/bash
set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════════
# h3x_sentinel redeploy — install the freshly signed binary and repair the
# LaunchDaemon set on THIS machine.
#
# Fixes two bugs:
#   1. crash loop  — the installed binary never implemented --watch-system
#                    (the flag the canonical plist passes), so every spawn
#                    hit the argc<3 usage path and exit(1)'d in ~12ms.
#   2. empty scans — every shipped binary was ad-hoc signed with no
#                    entitlements (the old entitlements.plist had an illegal
#                    double hyphen inside an XML comment, so codesign failed
#                    under `set -e`). Without com.apple.security.cs.debugger,
#                    task_for_pid was refused even as root.
#
# It also removes the stale DUPLICATE daemon com.qomputeai.h3x.sentinel, which
# is not part of the current package (canonical label is ai.qompute.h3x.sentinel).
#
# Run:  sudo bash pkg/redeploy_sentinel.sh
# ═══════════════════════════════════════════════════════════════════════════

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
SRC_BIN="$REPO_DIR/build/h3x_sentinel"
DEST_BIN="/usr/local/bin/h3x_sentinel"

CANONICAL_LABEL="ai.qompute.h3x.sentinel"
STALE_LABEL="com.qomputeai.h3x.sentinel"
CANONICAL_PLIST="/Library/LaunchDaemons/${CANONICAL_LABEL}.plist"
STALE_PLIST="/Library/LaunchDaemons/${STALE_LABEL}.plist"
SRC_PLIST="$SCRIPT_DIR/${CANONICAL_LABEL}.plist"

if [ "$(id -u)" -ne 0 ]; then
    echo "error: must run as root — try: sudo bash $0" >&2
    exit 1
fi

if [ ! -x "$SRC_BIN" ]; then
    echo "error: $SRC_BIN not found. Build it first:" >&2
    echo "  cd $REPO_DIR && make build/h3x_sentinel && \\" >&2
    echo "    codesign --force --options runtime --timestamp \\" >&2
    echo "      --entitlements entitlements.plist \\" >&2
    echo "      --identifier $CANONICAL_LABEL \\" >&2
    echo "      -s 'Developer ID Application: qomputeai inc (4HMYMNKRGB)' build/h3x_sentinel" >&2
    exit 1
fi

echo "[1/6] Verifying the new binary is signed with a real TeamIdentifier..."
if ! codesign --verify --strict "$SRC_BIN" 2>/dev/null; then
    echo "  error: $SRC_BIN fails codesign --verify. Refusing to install." >&2
    exit 1
fi
if ! codesign -dvvv "$SRC_BIN" 2>&1 | grep -q "TeamIdentifier=4HMYMNKRGB"; then
    echo "  error: $SRC_BIN is not signed with TeamIdentifier 4HMYMNKRGB (still ad-hoc?)." >&2
    exit 1
fi
if ! codesign -d --entitlements :- "$SRC_BIN" 2>/dev/null | grep -q "com.apple.security.cs.debugger"; then
    echo "  error: $SRC_BIN is missing com.apple.security.cs.debugger; task_for_pid would fail." >&2
    exit 1
fi
echo "  ok — Developer ID, hardened runtime, debugger entitlement present."

echo "[2/6] Confirming the new binary accepts --watch-system..."
if ! "$SRC_BIN" 2>&1 | grep -q -- "--watch-system"; then
    echo "  error: $SRC_BIN does not advertise --watch-system. Wrong build." >&2
    exit 1
fi
echo "  ok."

echo "[3/6] Tearing down BOTH current daemons (canonical + stale duplicate)..."
launchctl bootout system "$CANONICAL_PLIST" 2>/dev/null || true
launchctl bootout system "$STALE_PLIST"     2>/dev/null || true
# Older loader syntax, just in case the boot-time jobs were legacy-loaded:
launchctl remove "$CANONICAL_LABEL" 2>/dev/null || true
launchctl remove "$STALE_LABEL"     2>/dev/null || true
echo "  ok — services stopped; crash-loop halted."

echo "[4/6] Installing the signed binary to $DEST_BIN..."
install -o root -g wheel -m 755 "$SRC_BIN" "$DEST_BIN"
xattr -dr com.apple.quarantine "$DEST_BIN" 2>/dev/null || true
echo "  ok."

echo "[5/6] Removing the stale duplicate daemon, ensuring canonical plist..."
if [ -f "$STALE_PLIST" ]; then
    rm -f "$STALE_PLIST"
    echo "  removed $STALE_PLIST"
fi
if [ -f "$SRC_PLIST" ]; then
    install -o root -g wheel -m 644 "$SRC_PLIST" "$CANONICAL_PLIST"
    echo "  installed canonical plist from repo."
elif [ -f "$CANONICAL_PLIST" ]; then
    echo "  canonical plist already present (repo copy not found; leaving in place)."
else
    echo "  error: no canonical plist at $CANONICAL_PLIST and none in repo ($SRC_PLIST)." >&2
    exit 1
fi

echo "[6/6] Loading the canonical daemon..."
launchctl bootstrap system "$CANONICAL_PLIST"
launchctl enable "system/$CANONICAL_LABEL"
launchctl kickstart -k "system/$CANONICAL_LABEL" 2>/dev/null || true

echo ""
echo "Waiting 12s to confirm it stays up (no respawn)..."
sleep 12
echo ""
echo "=== launchctl print system/$CANONICAL_LABEL (key lines) ==="
launchctl print "system/$CANONICAL_LABEL" 2>/dev/null \
    | grep -E "state|pid|last exit code|runs" || true

echo ""
echo "=== recent daemon log (should be scan cycles, not exit(1)) ==="
log show --predicate "eventMessage CONTAINS \"h3x_sentinel\"" --last 30s --style compact 2>/dev/null \
    | grep -iE "scan cycle|watch-system|exited due to exit" | tail -15 || true

echo ""
echo "Done. If 'state = running' with a stable pid and you see 'scan cycle' lines,"
echo "the sentinel is fixed. Stop it any time with:"
echo "  sudo launchctl bootout system/$CANONICAL_LABEL"
