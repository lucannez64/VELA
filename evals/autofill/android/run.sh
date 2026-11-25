#!/usr/bin/env bash
# Build + install the lab app and its UiAutomator runner, then sweep.
#   android/run.sh [surfaces] [tier] [extra instrumentation args...]
#   android/run.sh native,webview,chrome,firefox fixture
#   android/run.sh chrome live limit 40
#   android/run.sh - live-app
# Results: evals/autofill/results/<runId>/results.jsonl (written by the server).
set -euo pipefail
cd "$(dirname "$0")"
SURFACES="${1:-native,webview,chrome}"; TIER="${2:-fixture}"; shift $(( $# > 2 ? 2 : $# )) || true
RUN_ID="${RUN_ID:-android-$(date +%Y%m%dT%H%M%S)}"
./gradlew -q :lab:installDebug :lab:installDebugAndroidTest
EXTRA=()
while [ $# -ge 2 ]; do EXTRA+=(-e "$1" "$2"); shift 2; done
adb ${ANDROID_SERIAL:+-s "$ANDROID_SERIAL"} shell am instrument -w -r \
  -e runId "$RUN_ID" -e surfaces "$SURFACES" -e tier "$TIER" "${EXTRA[@]}" \
  -e class com.vela.autofilleval.lab.AutofillEvalTest \
  com.vela.autofilleval.lab.test/androidx.test.runner.AndroidJUnitRunner | grep -E "AUTOFILL_EVAL|FAILURES|OK \(" || true
echo "report: (cd .. && node lib/report.mjs $RUN_ID)"
