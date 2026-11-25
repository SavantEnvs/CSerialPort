#!/usr/bin/env bash
# mayhem/test.sh — run upstream's doctest suites (built by build.sh) and emit a CTRF report.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Upstream's doctest suites, built by build.sh with normal flags. doctest prints
#   [doctest] test cases: T | P passed | F failed | S skipped
# and exits non-zero on any failure; the CHECKs assert exact buffer contents / parsed frames.
total_p=0; total_f=0; total_s=0
run_suite() {
  local bin="$1" out rc line p f s; shift
  if [ ! -x "$bin" ]; then echo "missing test runner $bin (build.sh bug)" >&2; total_f=$((total_f+1)); return; fi
  out="$("$bin" "$@" 2>&1)"; rc=$?
  printf '%s\n' "$out"
  line="$(printf '%s\n' "$out" | grep -E '^\[doctest\] test cases:' | tail -1)"
  if [ -z "$line" ]; then echo "no doctest summary from $bin (rc=$rc)" >&2; total_f=$((total_f+1)); return; fi
  p="$(sed -E 's/.*\| *([0-9]+) passed.*/\1/' <<<"$line")"
  f="$(sed -E 's/.*\| *([0-9]+) failed.*/\1/' <<<"$line")"
  s="$(sed -E 's/.*\| *([0-9]+) skipped.*/\1/' <<<"$line")"
  [[ "$s" =~ ^[0-9]+$ ]] || s=0
  if [ "$p" -eq 0 ]; then echo "$bin ran no passing test cases" >&2; f=$((f+1)); fi
  if [ "$rc" -ne 0 ] && [ "$f" -eq 0 ]; then f=1; fi
  total_p=$((total_p+p)); total_f=$((total_f+f)); total_s=$((total_s+s))
}
# upstream's main() filters to the perf case only; --test-case=* adds back every unit test
run_suite "$SRC/build/rbtest/RingBufferTest" "--test-case=*"
run_suite "$SRC/build/test/CSerialPortTest"
emit_ctrf "doctest" "$total_p" "$total_f" "$total_s"
