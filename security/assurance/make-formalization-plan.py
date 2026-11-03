#!/usr/bin/env python3
"""Build the full-formalization plan: a dependency DAG and one topological order.

Edit NODES below, then run:
    python3 -I security/assurance/make-formalization-plan.py
It checks that every dependency exists and that the graph has no cycle, then
writes formalization-plan.json, 20-formalization-plan.md and the interactive
graph formalization-plan.html (from formalization-plan.template.html).

Node fields: id, area, size (S < 1 day, M 1-3 days, L ~1 week, XL > 1 week),
hard (proof risk: may need a redesign), title, done (exit check), deps.
"""
import json
import pathlib
import sys

AREAS = {
    "B": "Baseline and bookkeeping",
    "T": "F-6 trusted base",
    "O": "F-1 observation origins",
    "H": "F-1/F-2 full handlers and server composition",
    "P": "F-3 client persistence and recovery",
    "C": "F-4 construction security",
    "N": "F-5 native clients and protocol composition",
    "Z": "Closing",
}

# (id, size, hard, title, done-when, deps)
NODES = [
    # ---------------- Baseline ----------------
    ("B0", "S", False, "Get PR #175 green",
     "Cancelled formal run on 654a0ee rerun; vela-box runners healthy; every PR check passes", []),
    ("B1", "S", False, "Merge PR #175 into main",
     "main contains the F-1/F-2 work; 08 baseline section points at the merge commit", ["B0"]),
    ("B2", "S", False, "Link this plan from 08",
     "08 'Remaining obligations' rows each list their plan node ids", ["B1"]),
    ("B3", "M", False, "Dedupe the copied Sql/Faulty harnesses",
     "One shared Rust test harness crate; all executor conformance suites use it and pass", ["B1"]),
    ("B4", "M", True, "One shared F* store/SQL model",
     "All executor proofs import one Vela.Store.Model module (txn, faults, rows); per-crate copies deleted; all gates green", ["B3"]),
    ("B5", "S", False, "Plan-node check in check-correspondence",
     "check-correspondence.py fails if a correspondence pair cites an unknown plan node", ["B2"]),

    # ---------------- F-6 trusted base ----------------
    ("T1", "S", False, "Inventory imported model contracts",
     "Script lists every hax/std/F* library symbol the corpus relies on, with use counts; output committed", ["B1"]),
    ("T2", "S", False, "Zero-assumption gate over all F*",
     "check-proof-boundary rejects assume/admit/axiom in extracted AND handwritten modules; mutation fixture rejected", ["T1"]),
    ("T3", "M", False, "Review the Vec model",
     "Review note maps each used Vec op (len/index/push/extend/slice) to Rust std semantics incl. panics", ["T1"]),
    ("T4", "M", False, "Review the String/UTF-8 model",
     "Review note for String/str/from_utf8 ops used; gaps listed as nodes or excluded", ["T1"]),
    ("T5", "M", False, "Review integer and overflow models",
     "Every u8..u128/i64 op used is checked against Rust release-mode semantics (wrapping vs panic)", ["T1"]),
    ("T6", "S", False, "Review Option/Result/slice models", "Review note committed", ["T1"]),
    ("T7", "L", True, "Differential tests of the std models",
     "Extracted F* model functions run (OCaml extraction) against Rust on random inputs; zero mismatches over 10^6 cases per op", ["T3", "T4", "T5", "T6"]),
    ("T8", "M", False, "Proof stability gate",
     "Every F* module verifies with 3 Z3 seeds and z3 pinned; rlimits recorded; flaky modules split", ["T2"]),
    ("T9", "S", False, "List OS/library interface assumptions",
     "09 lists each assumed interface (entropy, clock, fs, locks, DB isolation) with its call sites", ["T1"]),
    ("T10", "M", False, "Pin the rest of the environment (G-3)",
     "opam lock, action SHAs and OS packages pinned; G-3 closed", ["B1"]),
    ("T11", "M", False, "One proof container",
     "A pinned image runs run-all.sh end to end; hosted CI uses it", ["T10"]),
    ("T12", "S", False, "Update the trusted-base docs",
     "07/09 updated from T7-T9; F-6 row reads closed except independent review", ["T7", "T8", "T9", "T11"]),

    # ---------------- F-1 origins ----------------
    ("O1", "S", False, "Inventory observation producers",
     "Table: every observation field -> producing code (SQL query, store get, verifier, token, clock); committed", ["B1"]),
    ("O2", "M", False, "Schema check for every rendered SQL",
     "Gate parses migrations into a schema model and checks every byte-pinned statement's tables/columns/types", ["O1"]),
    ("O3a", "S", False, "Row decoders: sharing", "Row->observation decoders extracted and proved against the row model", ["O1", "B4"]),
    ("O3b", "S", False, "Row decoders: send links", "As O3a for send", ["O3a"]),
    ("O3c", "M", False, "Row decoders: session and web sessions", "As O3a for session", ["O3a"]),
    ("O3d", "M", False, "Row decoders: enrollment and pairing", "As O3a for enrollment", ["O3a"]),
    ("O3e", "M", False, "Row decoders: recovery", "As O3a for all four recovery families", ["O3a"]),
    ("O3f", "M", False, "Row decoders: vault, rotation, capsules", "As O3a for vault", ["O3a"]),
    ("O4", "M", False, "Store key builders are injective",
     "Proof that every store key builder (rl:*, challenge, grant, ...) is injective and namespaces are disjoint", ["O1"]),
    ("O5", "M", True, "Store value codecs round-trip",
     "decode(encode v) = v and encode injective for every stored value type", ["O4", "T3"]),
    ("O6", "S", False, "Grant store-key user binding",
     "Proof that a grant key read in a handler is bound to the session user (open item from 15)", ["O4"]),
    ("O7", "M", False, "Signature-verifier wrapper",
     "Extracted wrapper proved: Ok iff both components verify on the exact signed bytes; components trusted", ["O1"]),
    ("O8", "M", False, "Token and session-id producer",
     "Claims construction and parse->session observation proved; PASETO crypto trusted", ["O1"]),
    ("O9", "M", True, "Epoch freshness",
     "Epoch read/normalize composed with the vault row model proves freshness, not just normalization", ["O3f"]),
    ("O10", "M", False, "TTL expiry as adversarial deletion",
     "Store model lets expiry delete any TTL key at any step; driver and executor theorems still hold", ["B4"]),
    ("O11", "S", False, "Nonce source contract",
     "Nonce length and single use proved; entropy trusted per T9", ["T9"]),
    ("O12", "S", False, "Prove the EnrollmentAccountView adapter",
     "Adapter extracted and proved; conformance test kept as backup", ["O3d"]),
    ("O13a", "M", False, "Context origins: sharing",
     "Every context field used in sharing admission is proved to come from the session or a DB row, never the body", ["O3a", "O8"]),
    ("O13b", "S", False, "Context origins: send links", "As O13a", ["O3b", "O8"]),
    ("O13c", "M", False, "Context origins: session", "As O13a", ["O3c", "O8"]),
    ("O13d", "M", False, "Context origins: enrollment", "As O13a", ["O3d", "O8", "O12"]),
    ("O13e", "M", False, "Context origins: recovery", "As O13a; includes WebAuthn verdict origin", ["O3e", "O8", "O7", "O6"]),
    ("O13f", "M", False, "Context origins: vault", "As O13a", ["O3f", "O8", "O9"]),
    ("O14a", "M", False, "Share-envelope encoder inverse",
     "parse(encode x) = x over the checked byte-frame grammar", ["T4"]),
    ("O14b", "M", False, "UTF-8/object conversion",
     "Opened bytes -> object conversion proved against the String model", ["T4", "O14a"]),
    ("O14c", "L", True, "Authenticated-open composition",
     "frame parse ; signature check ; open ; object decode composed into one theorem for the production opener", ["O14b", "O7"]),
    ("O15", "M", False, "Recovery fact construction leftovers",
     "Decoders, verifiers, storage effects and restoration for recovery covered (open items from 13/15)", ["O3e", "O7"]),

    # ---------------- Full handlers ----------------
    ("H1", "S", False, "Handler inventory",
     "Every route (about 60 route entries) tagged: parse / origins / interpreter / reply, each covered or not", ["B1"]),
    ("H2", "M", False, "Fix U-24 (lost recovery-redemption reply)",
     "Device row records its grant, replay recovers the device id; proved in the redemption driver; U-24 closed", ["B1"]),
    ("H3", "S", False, "Cancellation lemma for the U-24 fix", "Cancellation README shows no lost-reply case left", ["H2"]),
    ("H4", "M", False, "Request validation",
     "For each handler, typed request -> validated input proved (JSON decode itself trusted per T9)", ["H1", "T4"]),
    ("H5", "M", False, "Reply construction",
     "Verdict -> status/body mapping proved total and leak-free for every handler", ["H1"]),
    ("H6", "M", False, "Auth middleware",
     "Middleware session extraction proved; composed with O8", ["O8", "H1"]),
    ("H7", "M", False, "Read-only and leftover routes",
     "Routes with no driver (GET /devices, /sends, /vault/events, /health, ...) proved write-free and auth-correct", ["H1", "B4"]),
    ("H8a", "L", False, "Whole-handler theorem: sharing",
     "parse ; middleware ; origins ; interpreter ; reply refines the M19b/M21 state machine", ["H4", "H5", "H6", "O13a"]),
    ("H8b", "M", False, "Whole-handler theorem: send links", "As H8a", ["H4", "H5", "H6", "O13b"]),
    ("H8c", "L", False, "Whole-handler theorem: session and web sessions", "As H8a", ["H4", "H5", "H6", "O13c"]),
    ("H8d", "L", False, "Whole-handler theorem: enrollment and pairing", "As H8a (M13)", ["H4", "H5", "H6", "O13d"]),
    ("H8e", "L", True, "Whole-handler theorem: recovery", "As H8a (M18/M26a)", ["H4", "H5", "H6", "O13e", "O15", "H3"]),
    ("H8f", "L", True, "Whole-handler theorem: vault and rekey", "As H8a (M11)", ["H4", "H5", "H6", "O13f", "O10"]),
    ("H8g", "M", False, "Whole-handler theorem: account deletion", "As H8a", ["H4", "H5", "H6", "O13c"]),
    ("H9", "M", False, "Early returns and panic freedom",
     "Every early-return path proved to match the spec's state; deny(unwrap/expect/indexing) in handlers", ["H8a", "H8b", "H8c", "H8d", "H8e", "H8f", "H8g"]),
    ("H10", "M", False, "DB isolation stated and tested",
     "Turso/sled linearizability kept as a named trusted interface, backed by a concurrency conformance suite", ["T9"]),
    ("H11a", "M", False, "Cross-driver world: add vault and rekey", "Composition theorem re-proved with the new drivers", ["H8f", "H10"]),
    ("H11b", "M", False, "Cross-driver world: add sharing and send", "As H11a", ["H11a", "H8a", "H8b"]),
    ("H11c", "M", False, "Cross-driver world: add web sessions and enrollment", "As H11a", ["H11b", "H8c", "H8d"]),
    ("H11d", "L", True, "Drop the 'four reads are one step' assumption",
     "Admission reads interleave freely; theorem still holds or a fix lands", ["H11c"]),
    ("H11e", "L", True, "Revocation landing mid-request",
     "Remove the 'checked at start/decision' assumption for revocation and pairing", ["H11d"]),
    ("H12", "S", False, "Close F-1 and F-2 in 08", "Both rows say closed under the boundary; evidence READMEs and correspondence pairs updated", ["H9", "H11e", "O2", "O14c"]),

    # ---------------- F-3 persistence ----------------
    ("P1", "S", False, "Journal implementation inventory",
     "Map vela-desktop-core store/sharing/sync journal ops to M28 rules", ["B1"]),
    ("P2a", "M", False, "Tamarin bridge: source term representation", "F* type for Tamarin terms used by M28", ["B1"]),
    ("P2b", "M", False, "Tamarin bridge: slot projection", "Proved projection from multi-slot traces to single-slot", ["P2a"]),
    ("P2c", "M", True, "Tamarin bridge: derivability and freshness", "Input derivability and global freshness encoded", ["P2a"]),
    ("P2d", "L", True, "Tamarin bridge theorem",
     "Source traces embed into the core encoding and lifts are admissible; M28 lemmas transfer", ["P2b", "P2c"]),
    ("P3a", "M", False, "Extract the journal step function",
     "Pure journal step in Rust, called by the real code, extracted by hax", ["P1"]),
    ("P3b", "L", True, "Journal step refines M28", "Every Rust step maps to an M28 rule or a stutter", ["P3a", "P2d"]),
    ("P3c", "M", True, "Filesystem model",
     "F* model of write/rename/fsync/crash under the T9 interface", ["T9"]),
    ("P3d", "L", True, "File operations implement durability phases",
     "Proof that the fs calls realize Persist/Clear phases under any crash point", ["P3a", "P3c"]),
    ("P4", "M", False, "Collection equality", "Formal definition and proof used by sync/journal", ["P3a"]),
    ("P5", "M", False, "Compose local edits and deletions", "Edits/deletions composed with the journal refinement", ["P3b", "P4"]),
    ("P6", "M", False, "Compose RMS migration", "Migration path proved to preserve journal invariants", ["P3b"]),
    ("P7", "M", False, "Independent processes",
     "Either a lock with a proved mutual-exclusion argument, or an explicit exclusion in 09", ["P3c"]),
    ("P8", "M", False, "Uncertain-write re-arm ordering", "The fixed re-arm ordering proved, regression kept", ["P3d"]),
    ("P9", "S", False, "Close F-3 in 08", "Gate in CI; F-3 row closed", ["P5", "P6", "P7", "P8"]),

    # ---------------- F-4 crypto ----------------
    ("C1", "M", False, "SHA-256 bridge as a game", "Collision step for ct_mlkem/pk_mlkem machine-checked in CryptoVerif", ["B1"]),
    ("C2", "L", True, "X25519 cofactor and low-order inputs", "Game models cofactor-8 group and the kem.rs reject check", ["B1"]),
    ("C3a", "M", False, "kem.rs encoding checks in Rust", "hax proof that kem.rs rejects low-order/non-canonical inputs as claimed", ["T5"]),
    ("C3b", "M", False, "Link wire encodings to the game", "Encoding->group-element map proved injective modulo the rejected set", ["C3a", "C2"]),
    ("C4", "M", True, "Clamped scalar distribution", "Machine-checked collision bound for the clamped distribution", ["B1"]),
    ("C5", "L", True, "Concrete X25519 combiner theorem", "One theorem replacing the model-level COMP-5", ["C1", "C3b", "C4"]),
    ("C6", "L", True, "Multi-user, multi-challenge KEM", "Game or hybrid argument with stated loss", ["C1"]),
    ("C7a", "S", False, "Decide quantum-query scope", "Choice recorded in 09: QROM proof, paper reduction, or excluded", ["B1"]),
    ("C7b", "XL", True, "Quantum-query composition", "Per C7a decision; skipped if excluded", ["C7a", "C5"]),
    ("C8", "M", False, "Instantiate KEM-DEM with the combiner", "Composition lemma checked, not manual", ["C5", "C6"]),
    ("C9", "M", True, "AAD and signed share-envelope game", "Encryption theorem covers the real envelope with AAD", ["C8", "O14a"]),
    ("C10", "L", True, "HKDF beyond the random oracle", "Reductions under named PRF/extractor assumptions", ["B1"]),
    ("C11", "M", False, "Envelope framing game", "Framing injectivity (from wire proofs) used in the game", ["C9"]),
    ("C12", "M", False, "Hybrid-signature Rust wrapper correspondence", "Wrapper <-> game composition closed (open item in 10)", ["O7"]),
    ("C13", "M", False, "Recovery KDF and password-hashing constructions", "Game for recovery key derivation", ["C10"]),
    ("C14", "M", False, "Application randomness", "Keys/nonces drawn from the OS RNG with right lengths; AEAD nonce uniqueness proved", ["T9"]),
    ("C15", "M", False, "Uniform decryption errors", "No error-oracle: all decrypt failures map to one error, proved at the wrapper", ["B1"]),
    ("C16", "M", False, "Secret erasure", "Zeroize gate: secret types implement ZeroizeOnDrop; lint plus review", ["B1"]),
    ("C17", "S", False, "Legacy v1 decision", "decapsulate_legacy_v1 removed or explicitly excluded", ["B1"]),
    ("C18", "S", False, "Close F-4 in 08", "CryptoVerif README open list empty or excluded", ["C7b", "C11", "C12", "C13", "C14", "C15", "C16", "C17"]),

    # ---------------- F-5 native ----------------
    ("N1", "S", False, "FFI call-site inventory", "Every Kotlin/Swift/TS call into the bridges listed", ["B1"]),
    ("N2a", "M", False, "Android bridge is a thin wrapper", "hax proof: bridge fns call verified policies, no extra logic", ["N1"]),
    ("N2b", "M", False, "Apple bridge is a thin wrapper", "As N2a", ["N1"]),
    ("N2c", "M", False, "WASM bridge is a thin wrapper", "As N2a", ["N1"]),
    ("N3", "M", False, "FFI type mapping", "Bytes, errors and nullability mapping reviewed and tested both ways", ["N2a", "N2b", "N2c"]),
    ("N4", "S", False, "Choose the caller-verification method", "Decision recorded (e.g. model-extracted state machines + trace refinement)", ["N1"]),
    ("N5a", "M", False, "Android sync caller", "Caller proved to reach admission only via the bridge", ["N4", "N3"]),
    ("N5b", "M", False, "Android sharing caller", "As N5a", ["N5a"]),
    ("N5c", "M", False, "Android enrollment/recovery caller", "As N5a", ["N5a"]),
    ("N5d", "L", True, "Android persistence", "EncryptedVaultStore writes refine the journal contract", ["N5a", "P3d"]),
    ("N6a", "M", False, "iOS sync caller", "As N5a", ["N4", "N3"]),
    ("N6b", "M", False, "iOS sharing caller", "As N5a", ["N6a"]),
    ("N6c", "M", False, "iOS enrollment/recovery caller", "As N5a", ["N6a"]),
    ("N6d", "L", True, "iOS persistence", "As N5d", ["N6a", "P3d"]),
    ("N7a", "M", False, "Desktop callers (gpui and Tauri)", "As N5a", ["N4", "N3"]),
    ("N7b", "M", False, "Web and extension callers", "As N5a", ["N4", "N3"]),
    ("N8", "M", True, "Unbounded native trace refinement", "Bounded download-gate conformance lifted to a proof", ["N5a", "N6a"]),
    ("N9", "M", True, "Enrollment UI trust", "Tamarin model of the human code comparison (extends M13)", ["B1"]),
    ("N10a", "M", False, "Joint model skeleton", "One Tamarin theory with shared accounts/devices/keys", ["B1"]),
    ("N10b", "M", False, "Joint model: enrollment and recovery", "Rules imported, lemmas re-proved", ["N10a", "N9"]),
    ("N10c", "M", False, "Joint model: sync", "As N10b", ["N10b"]),
    ("N10d", "M", False, "Joint model: sharing", "As N10b", ["N10c"]),
    ("N10e", "L", True, "Joint model: revocation and claims", "TC-6 claims proved in the joint model", ["N10d"]),
    ("N11", "S", False, "Close F-5 in 08", "F-5 row closed; U-8 closed", ["N5b", "N5c", "N5d", "N6b", "N6c", "N6d", "N7a", "N7b", "N8", "N10e"]),

    # ---------------- Closing ----------------
    ("Z1", "M", False, "Automate model<->policy correspondence (G-5)", "Drift gate covers every family and mobile call site", ["H12", "N11"]),
    ("Z2", "S", False, "Whole-system claim in 08", "08 header replaced by a scoped completion claim with its boundary", ["Z1", "T12", "P9", "C18"]),
    ("Z3", "S", False, "Hosted full run", "run-all.sh green in the proof container on the claim commit", ["Z2"]),
    ("Z4", "L", False, "Independent review (G-6)", "Third party reproduces Z3 and reviews models; G-6 closed", ["Z3"]),
]


def build():
    ids = [n[0] for n in NODES]
    if len(ids) != len(set(ids)):
        sys.exit("duplicate node id")
    known = set(ids)
    for nid, *_rest, deps in NODES:
        for d in deps:
            if d not in known:
                sys.exit(f"{nid}: unknown dependency {d}")
    # Kahn's algorithm; ties keep definition order so areas stay grouped.
    pos = {nid: i for i, nid in enumerate(ids)}
    deps = {n[0]: list(n[5]) for n in NODES}
    users = {nid: [] for nid in ids}
    for nid, ds in deps.items():
        for d in ds:
            users[d].append(nid)
    indeg = {nid: len(ds) for nid, ds in deps.items()}
    ready = sorted((nid for nid in ids if indeg[nid] == 0), key=pos.get)
    order = []
    while ready:
        nid = ready.pop(0)
        order.append(nid)
        for u in users[nid]:
            indeg[u] -= 1
            if indeg[u] == 0:
                ready.append(u)
        ready.sort(key=pos.get)
    if len(order) != len(ids):
        sys.exit("cycle among: " + ", ".join(sorted(set(ids) - set(order))))
    level = {}
    for nid in order:
        level[nid] = 1 + max((level[d] for d in deps[nid]), default=-1)
    # Critical path weighted by size.
    weight = {"S": 1, "M": 2, "L": 5, "XL": 10}
    size = {n[0]: n[1] for n in NODES}
    best, prev = {}, {}
    for nid in order:
        b = max(deps[nid], key=lambda d: best[d], default=None)
        best[nid] = weight[size[nid]] + (best[b] if b else 0)
        prev[nid] = b
    tail = max(order, key=best.get)
    crit = []
    while tail:
        crit.append(tail)
        tail = prev[tail]
    return order, level, deps, list(reversed(crit))


def main():
    here = pathlib.Path(__file__).resolve().parent
    order, level, deps, crit = build()
    by_id = {n[0]: n for n in NODES}
    nodes_json = [
        {"id": nid, "area": nid[0], "size": n[1], "hard": n[2], "title": n[3],
         "done": n[4], "deps": n[5], "level": level[nid], "step": i + 1}
        for i, nid in enumerate(order) for n in [by_id[nid]]
    ]
    plan = {"areas": AREAS, "critical_path": crit, "nodes": nodes_json}
    (here / "formalization-plan.json").write_text(json.dumps(plan, indent=1) + "\n")
    # Self-contained interactive graph: open the file directly, no server needed.
    page = (here / "formalization-plan.template.html").read_text()
    data = json.dumps(plan).replace("</", "<\\/")
    (here / "formalization-plan.html").write_text(page.replace("__PLAN_DATA__", data))

    out = []
    w = out.append
    w("# 20. Plan to full formalization\n")
    w("Generated by `make-formalization-plan.py` from the open items in")
    w("[08](08-formalization-status.md), [05](05-known-limitations.md) and the")
    w("[CryptoVerif README](../formal/cryptoverif/README.md). Edit the script, not this file.")
    w("Open [formalization-plan.html](formalization-plan.html) in a browser for the")
    w("interactive graph (zoom, search, dependency highlighting, progress tracking).\n")
    w("**Live progress.** Run `./plan-live.py serve` and open http://127.0.0.1:4318.")
    w("Whoever works on a step reports it with `./plan-live.py start|log|retry|block|done <id> \"message\"`")
    w("(`--who <name>`) from any worktree; the dashboard refreshes every 3 seconds.")
    w("Progress is stored outside the repo, in `~/.cache/vela-plan/formalization-status.json`.\n")
    w(f"{len(order)} steps, {max(level.values()) + 1} dependency levels. Sizes: S < 1 day,")
    w("M 1-3 days, L about a week, XL more. **hard** marks proofs that may need a")
    w("redesign. Any step whose dependencies are all done can start, so steps on the")
    w("same level can run in parallel.\n")
    w("Critical path (by size): " + " -> ".join(crit) + "\n")
    w("## Topological order\n")
    w("| # | Id | Lvl | Size | Step | Done when | After |")
    w("|---|---|---|---|---|---|---|")
    for j in nodes_json:
        hard = " **hard**" if j["hard"] else ""
        w(f"| {j['step']} | {j['id']} | {j['level']} | {j['size']}{hard} | {j['title']} | "
          f"{j['done']} | {', '.join(j['deps']) or '-'} |")
    w("\n## Dependency DAG\n")
    w("```mermaid\nflowchart TB")
    for a, name in AREAS.items():
        w(f'  subgraph {a}["{name}"]')
        for j in nodes_json:
            if j["area"] == a:
                shape = ("{{", "}}") if j["hard"] else ("[", "]")
                w(f'    {j["id"]}{shape[0]}"{j["id"]} {j["title"]}"{shape[1]}')
        w("  end")
    for j in nodes_json:
        for d in j["deps"]:
            w(f"  {d} --> {j['id']}")
    w("```\n")
    w("## Levels\n")
    for lv in range(max(level.values()) + 1):
        w(f"- **{lv}**: " + ", ".join(n for n in order if level[n] == lv))
    (here / "20-formalization-plan.md").write_text("\n".join(out) + "\n")
    print(f"{len(order)} nodes, {max(level.values()) + 1} levels; critical path {' -> '.join(crit)}")


if __name__ == "__main__":
    main()
