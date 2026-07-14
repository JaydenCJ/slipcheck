#!/usr/bin/env bash
# Smoke test: builds slipcheck, then exercises the real CLI end to end
# against the committed fixture archives (hostile tars and a sneaky zip)
# plus a freshly created real-world tarball from the system tar. Offline,
# idempotent, temp dirs only.
set -euo pipefail

cd "$(dirname "$0")/.."

fail() { echo "SMOKE FAIL: $*" >&2; exit 1; }

echo "[smoke] building..."
cargo build --quiet
BIN=target/debug/slipcheck
FIX=examples/fixtures

WORK=$(mktemp -d "${TMPDIR:-/tmp}/slipcheck-smoke.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

# --- 1. version/help/checks sanity -------------------------------------------
"$BIN" --version | grep -q '^slipcheck 0\.1\.0$' || fail "--version mismatch"
"$BIN" help | grep -q 'COMMANDS:' || fail "help missing sections"
"$BIN" checks | grep -q 'link-indirection' || fail "checks table incomplete"

# --- 2. clean archive passes --------------------------------------------------
echo "[smoke] clean fixture"
"$BIN" scan "$FIX/clean.tar.gz" | grep -q 'clean' || fail "clean.tar.gz not clean"

# --- 3. each hostile fixture fails with the right check -----------------------
echo "[smoke] hostile fixtures"
expect_fail() { # <fixture> <check-id>
  local out
  out=$("$BIN" scan "$FIX/$1" || true)
  set +e; "$BIN" scan "$FIX/$1" >/dev/null 2>&1; local code=$?; set -e
  [ "$code" -eq 1 ] || fail "$1: expected exit 1, got $code"
  echo "$out" | grep -q "$2" || fail "$1: expected finding '$2'"
}
expect_fail traversal.tar traversal
expect_fail absolute.tar absolute-path
expect_fail symlink-escape.tar link-indirection
expect_fail setuid.tar setuid
expect_fail sneaky.zip name-mismatch
("$BIN" scan "$FIX/sneaky.zip" || true) | grep -q '\.\./\.\./evil\.sh' \
  || fail "sneaky.zip: smuggled local name not audited"

# --- 4. a real tarball from the system tar ------------------------------------
echo "[smoke] real-world tar"
mkdir -p "$WORK/pkg/bin"
echo "hello" > "$WORK/pkg/README"
printf '#!/bin/sh\n' > "$WORK/pkg/bin/tool"
chmod 755 "$WORK/pkg/bin/tool"
tar -C "$WORK" -czf "$WORK/pkg.tgz" pkg
"$BIN" scan "$WORK/pkg.tgz" | grep -q 'clean' || fail "system tarball should be clean"

# --- 5. exit-code policy -------------------------------------------------------
echo "[smoke] exit codes and flags"
set +e
"$BIN" scan "$FIX/setuid.tar" --allow setuid >/dev/null; ALLOW=$?
"$BIN" scan "$FIX/traversal.tar" --fail-on never >/dev/null; NEVER=$?
"$BIN" scan "$WORK/does-not-exist.tar" >/dev/null 2>&1; MISSING=$?
echo "not an archive" > "$WORK/garbage.bin"
"$BIN" scan "$WORK/garbage.bin" >/dev/null 2>&1; GARBAGE=$?
set -e
[ "$ALLOW" -eq 0 ] || fail "--allow setuid should pass (got $ALLOW)"
[ "$NEVER" -eq 0 ] || fail "--fail-on never should exit 0 (got $NEVER)"
[ "$MISSING" -eq 2 ] || fail "missing file should exit 2 (got $MISSING)"
[ "$GARBAGE" -eq 2 ] || fail "garbage should exit 2 (got $GARBAGE)"

# --- 6. JSON output ------------------------------------------------------------
echo "[smoke] json"
JSON=$("$BIN" scan "$FIX/traversal.tar" --json || true)
echo "$JSON" | grep -q '"check": "traversal"' || fail "json missing finding"
echo "$JSON" | grep -q '"critical": 1' || fail "json missing totals"

# --- 7. stdin and quiet mode ----------------------------------------------------
echo "[smoke] stdin + quiet"
"$BIN" scan - < "$FIX/clean.tar.gz" | grep -q '(stdin)' || fail "stdin scan failed"
QUIET=$("$BIN" scan "$FIX/traversal.tar" --quiet || true)
[ -z "$QUIET" ] || fail "--quiet must print nothing"

# --- 8. bomb guard ---------------------------------------------------------------
echo "[smoke] bomb guard"
("$BIN" scan "$FIX/clean.tar.gz" --max-unpacked 1K || true) | grep -q 'unpack-limit' \
  || fail "bomb guard did not trip"

echo "SMOKE OK"
