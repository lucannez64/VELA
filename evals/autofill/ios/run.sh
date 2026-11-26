#!/usr/bin/env bash
# ios/run.sh [surfaces] [tier] [simulator name]
#   ios/run.sh safari,webview,native fixture "iPhone 16"
#   ios/run.sh safari live
# Start the server first, with host actions for Face ID:
#   node lib/server.mjs --allow-host-actions
set -euo pipefail
cd "$(dirname "$0")"
SURFACES="${1:-safari,webview,native}"; TIER="${2:-fixture}"; SIM="${3:-iPhone 16}"
RUN_ID="${RUN_ID:-ios-$(date +%Y%m%dT%H%M%S)}"
command -v xcodegen >/dev/null || { echo "brew install xcodegen"; exit 1; }
xcodegen -q
TEST_RUNNER_EVAL_SERVER="${EVAL_SERVER:-http://localhost:8080}" \
TEST_RUNNER_EVAL_RUN_ID="$RUN_ID" TEST_RUNNER_EVAL_SURFACES="$SURFACES" TEST_RUNNER_EVAL_TIER="$TIER" \
TEST_RUNNER_EVAL_ONLY="${EVAL_ONLY:-}" TEST_RUNNER_EVAL_PORT="${EVAL_PORT:-8443}" \
xcodebuild test -project VELAAutofillEval.xcodeproj -scheme AutofillEval \
  -destination "platform=iOS Simulator,name=$SIM" -only-testing:AutofillEvalUITests 2>&1 \
  | grep -E "AUTOFILL_EVAL|Test Suite|error:" || true
echo "report: (cd .. && node lib/report.mjs $RUN_ID)"
