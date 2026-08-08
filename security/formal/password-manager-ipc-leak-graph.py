#!/usr/bin/env python3
"""
Cumulative-leak log-time graph for the VELA IPC solutions (M1-M6 + current).

Quantitative companion to the symbolic results in
`password-manager-ipc-tamarin-results.md`. The six Tamarin models certify
WHICH items can leak and WHICH cannot; this script turns those verdicts into
"how many items have leaked by time t" for a 200-item vault over 2 months,
and is deliberately keyed one-to-one to the verified/falsified lemmas:

  M1  in-domain, no escape   -> `secrecy` FALSIFIED            : everything
                                 is releasable, the attacker drains the vault.
  M2  storage-escape alone   -> `secrecy` FALSIFIED            : same as M1,
                                 the decision is still forgeable.
  M3  decision+storage escape-> `secrecy_unused` VERIFIED      : only items the
                                 user actually uses ever reach the domain.
  M4  naive boolean          -> `unintended_item_leaks` trace  : one unbound
                                 'yes' replayed for every item -> full vault,
                                 delayed until the first human approval.
  M5  target-redefinition    -> `no_cross_origin` VERIFIED     : nothing
                                 persists; a stolen signature is useless at
                                 another origin -> zero leaked items.
  M6  real IPC handshake     -> per-client key + bound grant; `unused_item_secret`
                                 VERIFIED, `release_requires_client_request`
                                 VERIFIED. Cumulative leak = the working set
                                 (same ceiling as M3); the live/attacker-
                                 triggerable exposure is bounded by the grant
                                 TTL, which is the difference the right panel
                                 shows.
  M7  one-shot assertion     -> passkey/WebAuthn-style: the broker never
                                 releases a reusable secret, only a single-use
                                 origin-bound assertion (`credential_never_leaks`
                                 VERIFIED). Cumulative leak = 0, even for items
                                 in active use; residual is presence-only.
  M8  hybrid                 -> M7 for passkey-capable origins (the popular
                                 minority), M6 for everything else. The vault is
                                 split by origin auth-mode at minting time
                                 (`passkey_item_never_leaks` and
                                 `legacy_unused_item_secret` VERIFIED). Here the
                                 top PASSKEY_FRACTION of popular origins are
                                 passkey-capable; only the legacy half of the
                                 working set leaks.
  M9a in-core login          -> desktop-mediated login WITHOUT an engine: the
                                 desktop core submits the credential to the site
                                 over its own TLS connection, and only a session
                                 artifact reaches the domain
                                 (`credential_never_leaks` and
                                 `used_item_still_secret` VERIFIED). Zero vault
                                 items leak, even for sites logged into daily -
                                 for plain-form sites only.
  M9b engine login           -> the same idea done THROUGH an embedded browser
                                 engine (Selenium-like). The engine is a new
                                 domain member the same-UID adversary can watch
                                 (`credential_never_leaks` FALSIFIED,
                                 `credential_leaks_via_engine` verified): it
                                 collapses to the working set, exactly the
                                 design-review prediction. Here: every legacy
                                 fill that needs JS/fingerprinting runs through
                                 the engine, so the whole legacy working set is
                                 exposed to the engine.
  Current                    -> the shipped broker (ipc.rs): same-UID peer +
                                 presence proof with PLAINTEXT_RELEASE_TTL=120s,
                                 auto-lock on idle. On the no-biometric path
                                 (presence Unavailable) the release proceeds on
                                 the peer check + unlocked session, so a
                                 co-resident process can trigger releases while
                                 the vault is unlocked (audit D-4). That path is
                                 modelled here; the biometric path collapses to
                                 the M3/M6 working-set curve.

User activity is identical across all solutions (Poisson fills, Zipf item
popularity). The only solution-specific parameter is the attacker's drain rate,
which is a modelling choice (the models certify ceilings, not rates); all are
"patient attacker" rates and are stated in the legend.

Run:  python3 password-manager-ipc-leak-graph.py
"""

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FixedLocator, FixedFormatter

rng = np.random.default_rng(42)

# ---- parameters -----------------------------------------------------------
N = 200                 # vault capacity (items)
DAYS = 60               # horizon: 2 months
MIN = DAYS * 1440       # 86400 minutes
DT = 1                  # minute resolution

FILLS_PER_DAY = 10.0            # user autofill rate
ZIPF_ALPHA = 1.5                # item popularity skew (realistic long tail)

PASSKEY_FRACTION = 0.25         # share of origins that accept passkey/SSO auth;
                                # the popular minority (items ranked highest)
PLAIN_FORM_FRACTION = 0.5       # of the legacy remainder, the share with plain
                                # form logins (M9a-able); the rest are JS-bound

# attacker drain rates (items per elapsed minute) - modelling choice, see header
DRAIN_PER_MIN_FAST = 1.0        # M1, M2, M4: nothing gates the attacker
DRAIN_PER_MIN_SLOW = 1.0 / 10.0 # current (no biometric): only during unlocked windows

# current implementation: unlocked windows (vault session active + idle not hit)
# 9-13, 14-18, 19-23 -> 12 h/day
def unlocked(minute):
    h = (minute // 60) % 24
    return (9 <= h < 13) or (14 <= h < 18) or (19 <= h < 23)

# ---- user activity (shared by every solution) ------------------------------
n_fills = rng.poisson(FILLS_PER_DAY * DAYS)
fill_times = np.sort(rng.integers(0, MIN, n_fills))
weights = 1.0 / np.arange(1, N + 1) ** ZIPF_ALPHA
weights /= weights.sum()
fill_items = rng.choice(N, n_fills, p=weights)

# distinct-items-used series: +1 at the minute an item is first filled
first_fill = np.full(N, MIN + 1, dtype=np.int64)
for it, tm in zip(fill_items, fill_times):
    if tm < first_fill[it]:
        first_fill[it] = tm
inc = np.zeros(MIN + 1, dtype=np.int64)
for it in range(N):
    if first_fill[it] <= MIN:
        inc[first_fill[it]] += 1
used_cum = np.cumsum(inc)[:MIN]

t_first_fill = int(fill_times[0])

# ---- per-solution cumulative leak curves -----------------------------------
t = np.arange(MIN)

# M1 / M2: attacker drains 1 item/min, 24/7
m12 = np.minimum(N, t * DRAIN_PER_MIN_FAST).astype(float)

# M4: nothing until the first human approval, then same drain
m4 = np.where(t >= t_first_fill,
              np.minimum(N, (t - t_first_fill) * DRAIN_PER_MIN_FAST),
              0.0).astype(float)

# M3 / M6: the used set (working set, whole vault)
m3 = used_cum.astype(float)
m6 = used_cum.astype(float)  # cumulative identical; see right panel for the TTL win

# M7: zero persistent leak - only one-shot origin-bound assertions leave; the
# credential never reaches the domain, even for items in active use.
m7 = np.zeros(MIN)

# M8: hybrid - the popular origins are passkey-capable (M7 path, leak 0), the
# rest are legacy (M6 path, leak on use). Leak = legacy half of the working set.
passkey_n = int(N * PASSKEY_FRACTION)          # items 0..passkey_n-1 are passkey
legacy_first = np.full(N, MIN + 1, dtype=np.int64)
for it, tm in zip(fill_items, fill_times):
    if it >= passkey_n and tm < legacy_first[it]:
        legacy_first[it] = tm
inc_legacy = np.zeros(MIN + 1, dtype=np.int64)
for it in range(passkey_n, N):
    if legacy_first[it] <= MIN:
        inc_legacy[legacy_first[it]] += 1
m8 = np.cumsum(inc_legacy)[:MIN].astype(float)

# M9a: in-core login - the desktop core submits the credential to the site over
# its own TLS leg; only a session artifact reaches the domain. Zero vault items
# leak, even for sites logged into daily (plain-form sites only).
m9a = np.zeros(MIN)

# M9b: engine login - the embedded browser engine is a domain member the
# adversary can watch, so the credential transits an observable channel and the
# working-set floor returns: exactly the legacy half of the working set leaks.
m9b = m8.copy()

# M10 / full ladder: M7 for passkey origins (0), M9a for plain-form legacy (0),
# M6 for the JS/fingerprint-bound remainder (working set of that subset only).
passkey_n = int(N * PASSKEY_FRACTION)
plain_n = int(N * PASSKEY_FRACTION + (N - passkey_n) * PLAIN_FORM_FRACTION)
js_first = np.full(N, MIN + 1, dtype=np.int64)
for it, tm in zip(fill_items, fill_times):
    if it >= plain_n and tm < js_first[it]:
        js_first[it] = tm
inc_js = np.zeros(MIN + 1, dtype=np.int64)
for it in range(plain_n, N):
    if js_first[it] <= MIN:
        inc_js[js_first[it]] += 1
m10 = np.cumsum(inc_js)[:MIN].astype(float)

# M5: zero persistent value
m5 = np.zeros(MIN)

# current (no biometric, D-4 path): drain only while the vault is unlocked
unlocked_min = np.array([unlocked(m) for m in range(MIN)])
cum_unlocked = np.cumsum(unlocked_min)
cur = np.minimum(N, cum_unlocked * DRAIN_PER_MIN_SLOW).astype(float)

# ---- live attacker-triggerable exposure (right panel) -----------------------
# items a co-resident process could obtain RIGHT NOW without a fresh human action
live_m12 = np.full(MIN, N)
live_m4 = np.where(t >= t_first_fill, N, 0)
live_cur = np.where(unlocked_min, N, 0)
live_m3 = np.zeros(MIN)
live_m5 = np.zeros(MIN)
live_m6 = np.zeros(MIN)  # needs the client's enrolled key + a live single-use grant
live_m7 = np.zeros(MIN)  # needs the hardware-held assertion key
live_m8 = np.zeros(MIN)  # either key, none of which the adversary holds
live_m9a = np.zeros(MIN)  # in-core login: the password never reaches the domain
live_m9b = np.zeros(MIN)  # engine is observable but needs a fresh human grant
live_m10 = np.zeros(MIN)  # every tier needs a key or a human grant the adversary lacks

# ---- figure ----------------------------------------------------------------
def log_ticks():
    return [1, 10, 60, 360, 1440, 4320, 10080, 20160, 43200, 86400]

def log_labels():
    return ["1m", "10m", "1h", "6h", "1d", "3d", "1w", "2w", "1mo", "2mo"]

fig, axes = plt.subplots(1, 2, figsize=(14, 5.6), dpi=150,
                         gridspec_kw={"width_ratios": [1.25, 1]})

palette = {
    "M1": "#d62728",
    "M2": "#f2a0a0",
    "M4": "#ff7f0e",
    "current": "#d6279f",
    "M3": "#2ca02c",
    "M6": "#1f77b4",
    "M7": "#17becf",
    "M8": "#9467bd",
    "M9a": "#3cb44b",
    "M9b": "#e6194b",
    "M10": "#4363d8",
    "M5": "#111111",
}

ax = axes[0]
ax.axhline(N, color="#999999", lw=1, ls=":", zorder=1)
ax.text(2, N - 6, f"vault capacity ({N})", color="#666666", fontsize=8, va="top")

ax.plot(t, m12, color=palette["M1"], lw=2, label="M1 (in-domain, no escape) = M2 (SE alone)")
ax.plot(t, m4, color=palette["M4"], lw=2, ls="--", label="M4 (unbound boolean)")
ax.plot(t, cur, color=palette["current"], lw=2, ls="-.",
        label="current VELA, no-biometric path (D-4): drain while unlocked")
ax.plot(t, m3, color=palette["M3"], lw=2,
        label="M3 (DE+SE): working set = items the user uses")
ax.plot(t, m6, color=palette["M6"], lw=3, alpha=0.85,
        label="M6 (handshake): same ceiling, TTL-bounded live window (right)")
ax.plot(t, m9b, color=palette["M9b"], lw=2, ls="--",
        label="M9b (engine login): collapses to the legacy working set")
ax.plot(t, m8, color=palette["M8"], lw=2, ls="--",
        label="M8 (hybrid): M7 for passkey origins, M6 for the rest "
              f"({PASSKEY_FRACTION:.0%} passkey)")
ax.plot(t, m7, color=palette["M7"], lw=2, ls=":",
        label="M7 (one-shot assertion / passkey): zero, even for used items")
ax.plot(t, m9a, color=palette["M9a"], lw=2, ls=":",
        label="M9a (in-core login): zero, plain-form sites only")
ax.plot(t, m10, color=palette["M10"], lw=3,
        label="M10 (full ladder): M7 if not M9a if not M6 - only the "
              f"JS-bound subset leaks ({PASSKEY_FRACTION:.0%} passkey, "
              f"{PLAIN_FORM_FRACTION:.0%} of the rest plain-form)")
ax.plot(t, m5, color=palette["M5"], lw=2, label="M5 (target redefinition): zero")

ax.set_xscale("log")
ax.set_xlim(1, MIN)
ax.xaxis.set_major_locator(FixedLocator(log_ticks()))
ax.xaxis.set_major_formatter(FixedFormatter(log_labels()))
ax.set_xlabel("time since first exposure (log)")
ax.set_ylabel("cumulative items leaked")
ax.set_ylim(-5, 210)
ax.set_title("Cumulative items leaked over 2 months (200-item vault)")
ax.grid(True, which="major", alpha=0.3)
ax.legend(fontsize=8, loc="lower right")

ax = axes[1]
ax.plot(t, live_m12, color=palette["M1"], lw=2, label="M1 / M2")
ax.plot(t, live_m4, color=palette["M4"], lw=2, ls="--", label="M4 (after 1st approval)")
ax.plot(t, live_cur, color=palette["current"], lw=1.2, alpha=0.8,
        label="current no-biometric (unlocked windows)")
ax.plot(t, live_m3, color=palette["M3"], lw=2, label="M3")
ax.plot(t, live_m6, color=palette["M6"], lw=2, ls=":", label="M6")
ax.plot(t, live_m9b, color=palette["M9b"], lw=2, ls="--", label="M9b")
ax.plot(t, live_m8, color=palette["M8"], lw=2, ls="--", label="M8")
ax.plot(t, live_m9a, color=palette["M9a"], lw=2, ls=":", label="M9a")
ax.plot(t, live_m10, color=palette["M10"], lw=2, ls="--", label="M10")
ax.plot(t, live_m7, color=palette["M7"], lw=2, ls=":", label="M7")
ax.plot(t, live_m5, color=palette["M5"], lw=2, label="M5")

ax.set_xscale("log")
ax.set_xlim(1, MIN)
ax.xaxis.set_major_locator(FixedLocator(log_ticks()))
ax.xaxis.set_major_formatter(FixedFormatter(log_labels()))
ax.set_xlabel("time since first exposure (log)")
ax.set_ylabel("items attacker can trigger right now")
ax.set_ylim(-5, 210)
ax.set_title("Live attacker-triggerable exposure")
ax.grid(True, which="major", alpha=0.3)
ax.legend(fontsize=8, loc="center right")

fig.suptitle("VELA IPC: leaked items vs time (symbolic verdicts made quantitative)\n"
             "User activity identical across solutions (10 fills/day, Zipf "
             r"$\alpha$=1.5); attacker drain 1 item/min (M1/M2/M4) or 1 item/10 min "
             "unlocked (current). M8: passkey-capable origins = the popular "
             f"{PASSKEY_FRACTION:.0%}. M9a = in-core login (plain-form sites); "
             "M9b = engine login (collapses, as predicted). M10 = full ladder: "
             "M7 if not M9a if not M6.",
             fontsize=9)
fig.tight_layout(rect=[0, 0, 1, 0.94])
out = "password-manager-ipc-leak-graph.png"
fig.savefig(out, bbox_inches="tight")
print(f"wrote {out}")

# ---- printed summary -------------------------------------------------------
print(f"\n2-month cumulative leaked items (vault = {N}, horizon = {DAYS} days):")
for name, y in [("M1 (in-domain)", m12), ("M2 (SE alone)", m12),
                ("M3 (DE+SE)", m3), ("M4 (unbound boolean)", m4),
                ("M5 (TR)", m5),
                ("current (no biometric)", cur),
                ("M6 (handshake)", m6),
                ("M7 (one-shot assertion)", m7),
                ("M8 (hybrid)", m8),
                ("M9a (in-core login)", m9a),
                ("M9b (engine login)", m9b),
                ("M10 (full ladder)", m10)]:
    print(f"  {name:<24} {y[-1]:6.0f}")
print(f"\nworking set (distinct items the user filled): {used_cum[-1]:.0f}")
print(f"  passkey (top {PASSKEY_FRACTION:.0%}): used {used_cum[-1] - m8[-1]:.0f}, leaked 0")
print(f"  plain-form legacy ({PLAIN_FORM_FRACTION:.0%} of the rest): "
      f"used {m8[-1] - m10[-1]:.0f}, leaked 0 (M9a)")
print(f"  JS-bound legacy: used {m10[-1]:.0f}, leaked {m10[-1]:.0f} (M6)")
print(f"first human approval at minute {t_first_fill} "
      f"(day {t_first_fill / 1440:.2f})")
