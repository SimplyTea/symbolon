#!/bin/sh
# Run every end-to-end script and report each. A script counts as passing only if
# it exits 0, prints no line starting with FAIL / containing "SOME FAILED", and
# prints at least one PASS (or "ALL OK") line. (Most scripts print PASS/FAIL
# lines rather than setting an exit status, so the exit code alone proves nothing.)
cd "$(dirname "$0")" || exit 1
fail=0
for f in one_to_one_e2e padding_e2e resume_e2e group_e2e group_late bot_e2e bot_script_e2e bot_catchup bot_wrong_addr; do
  log="/tmp/e2e-$f.log"
  if timeout 240 python3 "$f.py" >"$log" 2>&1 \
     && ! grep -qE '^FAIL|SOME FAILED' "$log" \
     && grep -qE '^PASS|ALL OK' "$log"; then
    echo "PASS $f ($(grep -cE '^PASS|^ok|OK ' "$log") checks)"
  else
    echo "FAIL $f  (see $log)"; fail=1
  fi
done
exit $fail
