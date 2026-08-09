#!/usr/bin/env bash
# tools/mutants.sh — manual mutation gauntlet for the B1/B2/B3 fixes.
#
# Background: Go has no mature default mutation-testing tool, so we
# introduce plausible bugs into the new/changed code one at a time, run
# the suite, and confirm each mutant is KILLED by at least one test.
#
# If a mutant SURVIVES (no test fails), the test suite has a hole and a
# new assertion must be added before the fix can be declared done.
#
# Re-run-safe: each mutant is applied via python3 literal substitution,
# the test suite is run, then `git checkout` restores the file.
# IMPORTANT: the implementation must already be COMMITTED for restore
# to be a no-op for our changes; otherwise `git checkout` reverts
# working-tree changes and breaks the next steps. Run after the
# [GREEN] commit, not during RED.

set -euo pipefail

cd "$(dirname "$0")/.."

# Sanity: working tree must be either clean or have only untracked files
# relative to HEAD, so that `git checkout -- file` is a no-op for files
# we didn't intend to revert.
git status --porcelain | awk '{print $1}' | grep -v '^??' | grep -v 'M$' && {
  echo "ERROR: working tree has staged or modified files; commit first." >&2
  exit 2
} || true

TRACKED=(
  app/upstream.go
  modules/handler/handler.go
  pkgs/trojan/trojan_tcp.go
  pkgs/trojan/trojan_udp.go
)
cleanup() { git checkout -- "${TRACKED[@]}" 2>/dev/null || true; }
trap cleanup EXIT

apply_mutant() {
  local file="$1" find="$2" replace="$3"
  python3 - "$file" "$find" "$replace" <<'PY'
import sys, io
p, find, rep = sys.argv[1], sys.argv[2], sys.argv[3]
with io.open(p, 'r', encoding='utf-8') as f:
    src = f.read()
n = src.count(find)
if n == 0:
    print(f"  SKIP: pattern not present in {p}")
    sys.exit(0)
if n > 1:
    print(f"  ERROR: pattern matches {n} times in {p}; aborting")
    sys.exit(2)
with io.open(p, 'w', encoding='utf-8') as f:
    f.write(src.replace(find, rep, 1))
PY
}

run_focused() { go test -run "$2" "$1" >/dev/null 2>&1; }

declare -i killed=0 survived=0
mutant_status() {
  if [ "$1" -ne 0 ]; then
    echo "    KILLED"; killed=$((killed+1))
  else
    echo "    SURVIVED"; survived=$((survived+1))
  fi
}

# M1: weaken validStorageKey's hex check
echo "--- M1: validStorageKey accepts any byte ---"
apply_mutant app/upstream.go \
  "if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {" \
  "if false { // MUTANT M1"
run_focused ./app/ 'TestCaddyUpstream' && mutant_status 0 || mutant_status $?
git checkout -- app/upstream.go

# M2: weaken the length check
echo "--- M2: length check removed ---"
apply_mutant app/upstream.go \
  "if len(k) != trojan.HeaderLen {
		return false
	}" \
  "// MUTANT M2: length check removed
	if false { return false; }
	if len(k) != trojan.HeaderLen {"
run_focused ./app/ 'TestCaddyUpstream' && mutant_status 0 || mutant_status $?
git checkout -- app/upstream.go

# M3: never block (rate-limit disabled)
echo "--- M3: rate-limit block-check disabled ---"
apply_mutant modules/handler/handler.go \
  "if time.Now().Before(rec.blockedUntil) {
		return true
	}" \
  "// MUTANT M3: always fall through
	if false { return true; }
	if time.Now().Before(rec.blockedUntil) {"
run_focused ./modules/handler/ 'TestHandlerConnect' && mutant_status 0 || mutant_status $?
git checkout -- modules/handler/handler.go

# M4: threshold check defeated
echo "--- M4: threshold check unreachable ---"
apply_mutant modules/handler/handler.go \
  "if rec.count >= threshold && rec.blockedUntil.IsZero() {
		rec.blockedUntil = now.Add(cooldown)
	}" \
  "// MUTANT M4: never block
	if false { rec.blockedUntil = now.Add(cooldown); }
	if rec.count >= threshold && rec.blockedUntil.IsZero() {"
run_focused ./modules/handler/ 'TestHandlerConnect' && mutant_status 0 || mutant_status $?
git checkout -- modules/handler/handler.go

# M5: HandleTCP: disable the test-injected allocShortCircuit (so the test
# must reach the real-alloc path), then neutralize the post-alloc error
# return. With both halves applied the test MUST observe an error; without
# the hook being honored the test would see nil and fail.
echo "--- M5: HandleTCP dispatches around allocByteErr short-circuit ---"
apply_mutant pkgs/trojan/trojan_tcp.go \
  "if err := allocByteErr; err != nil {
		return 0, 0, fmt.Errorf(\"memory alloc error: %w\", err)
	}" \
  "// MUTANT M5: short-circuit disabled
	if false { return 0, 0, fmt.Errorf(\"memory alloc error: %w\", allocByteErr) }"
run_focused ./pkgs/trojan/ 'TestHandleTCPAllocFailure' && mutant_status 0 || mutant_status $?
git checkout -- pkgs/trojan/trojan_tcp.go

echo
echo "=== mutation summary: $killed killed, $survived survived ==="
[ "$survived" -eq 0 ] || exit 1
