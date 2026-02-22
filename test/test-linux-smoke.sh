#!/bin/sh
# certz Linux Smoke Tests
# Verifies the self-contained linux-x64 binary runs on a minimal Linux image.
# Mirrors test-nanoserver.cmd. Store operations (install/list/verify) are
# excluded -- those require distro tools tested in the full Ubuntu suite.

set -e

echo "========================================"
echo "  certz Linux Smoke Tests"
echo "========================================"
echo ""

CERTZ=/app/certz
WORK=/tmp/certz-smoke
mkdir -p "$WORK"
cd "$WORK"

fail() {
    echo ""
    echo "========================================"
    echo "  SMOKE TEST FAILED: $1"
    echo "========================================"
    exit 1
}

run() {
    STEP="$1"
    shift
    echo "$STEP"
    "$@" || fail "$STEP"
    echo ""
}

# ---- BASIC COMMANDS ----

run "[1/19] --version"         "$CERTZ" --version
run "[2/19] --help"            "$CERTZ" --help > /dev/null
run "[3/19] examples"          "$CERTZ" examples > /dev/null

# ---- CREATE COMMANDS ----

run "[4/19] create dev"        "$CERTZ" create dev test.local --file dev.pfx --cert dev.pem --key dev.key --password TestPass123
run "[5/19] create ca"         "$CERTZ" create ca --name "Test CA" --file ca.pfx --cert ca.pem --key ca.key --password CaPass123
run "[6/19] create dev --ephemeral" "$CERTZ" create dev ephemeral.local --ephemeral

# ---- INSPECT COMMANDS ----

run "[7/19] inspect pem"       "$CERTZ" inspect dev.pem
run "[8/19] inspect pfx"       "$CERTZ" inspect dev.pfx --password TestPass123
run "[9/19] inspect --format json" "$CERTZ" inspect dev.pem --format json > /dev/null

# ---- LINT COMMANDS ----

run "[10/19] lint"             "$CERTZ" lint dev.pfx --password TestPass123
run "[11/19] lint --format json" "$CERTZ" lint dev.pfx --password TestPass123 --format json > /dev/null

# ---- CONVERT COMMANDS ----

run "[12/19] convert pem to der"  "$CERTZ" convert dev.pem --to der
run "[13/19] convert der to pem"  "$CERTZ" convert dev.der --to pem --output roundtrip.pem
run "[14/19] convert pem to pfx"  "$CERTZ" convert dev.pem --to pfx --key dev.key --password ConvertPass123 --output converted.pfx

# ---- RENEW COMMAND ----

run "[15/19] renew"            "$CERTZ" renew dev.pfx --password TestPass123 --out renewed.pfx --out-password RenewPass123

# ---- MONITOR COMMANDS ----

run "[16/19] monitor ."        "$CERTZ" monitor .
run "[17/19] monitor . --format json" "$CERTZ" monitor . --format json > /dev/null

# ---- PASSWORD MAP TESTS ----

printf 'dev.pfx=TestPass123\nca.pfx=CaPass123\nconverted.pfx=ConvertPass123\nrenewed.pfx=RenewPass123\n' > passwords.txt

run "[18/19] monitor --password-map"             "$CERTZ" monitor . --password-map passwords.txt
run "[19/19] monitor --password-map --format json" "$CERTZ" monitor . --password-map passwords.txt --format json > /dev/null

# ---- DONE ----

echo "========================================"
echo "  All 19 smoke tests passed!"
echo "========================================"
