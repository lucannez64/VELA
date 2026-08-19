#!/usr/bin/env bash
#
# Live verification of the in-core login recipes (Tier A) against real sites.
#
# Run from the repo root:
#   ./security/live-login.sh steam
#   ./security/live-login.sh riot
#   ./security/live-login.sh both
#
# Credentials are read from the environment if present, otherwise prompted for.
# Nothing is written to disk or to the transcript; the password only ever sits
# in this shell's environment and is handed straight to the test harness.
#
# A "clean refusal" (wrong password, captcha or two-factor demand from the
# site) is a SUCCESS: it proves the flow works and the credential was simply
# not accepted. Only a transport/parse bug fails.

set -u
cd "$(dirname "$0")/.."
ROOT="$(pwd)"

run_cargo_test() {
  local filter="$1"; shift
  # Run from the workspace root so the already-built dependency tree is reused.
  ( cd "$ROOT/desktopVELA" && cargo test -p vela-desktop-core --lib -- --ignored "live::$filter" --nocapture )
}

ask() {
  local prompt="$1" var="$2" secret="${3:-}"
  if [ -n "${!var:-}" ]; then return; fi
  if [ "$secret" = "secret" ]; then
    read -r -s -p "$prompt" "$var"; echo
  else
    read -r -p "$prompt" "$var"
  fi
  export "$var"
}

run_steam() {
  echo
  echo "== Steam =="
  echo "Use an account you're willing to actually sign in with."
  echo "If Steam Guard uses the phone-app approval, approve the login there"
  echo "when it appears — the harness polls until you do."
  ask "Steam username:   " VELA_LIVE_STEAM_USER
  ask "Steam password:   " VELA_LIVE_STEAM_PASS secret
  read -r -p "Steam Guard: TOTP secret (otpauth://...), or the 6-digit code the app shows now, or leave empty: " VELA_LIVE_STEAM_TOTP
  # If the user pasted a 6-digit code rather than a secret, hand it to the
  # harness as the code path instead.
  case "$VELA_LIVE_STEAM_TOTP" in
    ""|otpauth://*) ;;
    *) VELA_LIVE_STEAM_CODE="$VELA_LIVE_STEAM_TOTP"; VELA_LIVE_STEAM_TOTP="";;
  esac
  export VELA_LIVE_STEAM_TOTP VELA_LIVE_STEAM_CODE
  run_cargo_test steam
}

run_riot() {
  echo
  echo "== Riot =="
  echo "The Riot login is gated by an hCaptcha you must solve yourself, in a"
  echo "real browser, seconds before the attempt (the token lives ~2 minutes)."
  ask "Riot e-mail or Riot ID: " VELA_LIVE_RIOT_USER
  ask "Riot password:          " VELA_LIVE_RIOT_PASS secret
  read -r -p "Riot TOTP secret, if 2FA uses an authenticator app (or leave empty): " VELA_LIVE_RIOT_TOTP
  export VELA_LIVE_RIOT_TOTP
  run_cargo_test riot
}

case "${1:-both}" in
  steam) run_steam ;;
  riot)  run_riot ;;
  both)  run_steam && run_riot ;;
  *)     echo "usage: $0 [steam|riot|both]" >&2; exit 2 ;;
esac
