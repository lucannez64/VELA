#!/usr/bin/env python3
"""List every call site of a trusted OS or library interface (plan step T9).

09-target-contract.md trusts OS entropy, clocks, the filesystem,
synchronization and the database/store under stated contracts. This script
finds where production code reaches each of them, so every proof that leans on
one of those contracts can cite the exact call sites, and new uses show up in
review.

Usage:
  python3 -I security/assurance/list-os-interfaces.py [--out DIR]

Writes inventory.json and README.md to --out (default:
security/assurance/proof-logs/current/os-interface-inventory). Test code
(tests/, benches/, examples/, `#[cfg(test)]` modules) and build output are
skipped. Matching is textual, so a hit is a place to review, not a proof that
the interface is used there.
"""
import argparse
import collections
import json
import pathlib
import re
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[2]

# (category, 09 contract it relies on, language, regex)
INTERFACES = [
    ("entropy", "OS entropy returns independent unpredictable bytes or reports failure", "rust",
     r"\bOsRng\b|\bgetrandom\b|\bthread_rng\b|rand::random|\.fill_bytes\(|try_fill_bytes|rand_core::OsRng|SystemRandom"),
    ("entropy", "OS entropy", "kotlin", r"\bSecureRandom\b"),
    ("entropy", "OS entropy", "swift", r"\bSecRandomCopyBytes\b|SystemRandomNumberGenerator"),
    ("entropy", "OS entropy", "web", r"crypto\.getRandomValues|crypto\.randomUUID"),
    ("clock", "time interfaces obey stated contracts (wall clock may jump; Instant is monotonic)", "rust",
     r"SystemTime::now|Instant::now|Utc::now|OffsetDateTime::now|UNIX_EPOCH|chrono::Local::now"),
    ("clock", "time", "kotlin", r"System\.currentTimeMillis|System\.nanoTime|Instant\.now\(|Clock\."),
    ("clock", "time", "swift", r"\bDate\(\)|Date\.now|ProcessInfo\.processInfo\.systemUptime|DispatchTime\.now"),
    ("filesystem", "file sync + atomic replace + directory sync has the advertised durability", "rust",
     r"std::fs::|tokio::fs::|\bfs::(?:write|read|rename|remove_file|create_dir|File|OpenOptions|copy)\b|File::(?:create|open)|OpenOptions::new|\.sync_all\(|\.sync_data\(|\bfsync\b|persist\("),
    ("filesystem", "filesystem", "kotlin", r"\bFileOutputStream\b|\bFileInputStream\b|\bAtomicFile\b|\.renameTo\(|\bFile\(|openFileOutput|\.sync\(\)"),
    ("filesystem", "filesystem", "swift", r"FileManager|\.write\(to:|replaceItemAt|FileHandle|\.synchronize\("),
    ("synchronization", "standard synchronization obeys its contract", "rust",
     r"\bMutex\b|\bRwLock\b|\bAtomic(?:U|I|Bool)\w*|\bflock\b|fs2::|fd_lock|\bSemaphore\b|\bNotify\b"),
    ("synchronization", "synchronization", "kotlin", r"\bsynchronized\b|\bMutex\b|ReentrantLock|\bAtomic(?:Integer|Long|Boolean|Reference)\b|@Volatile"),
    ("synchronization", "synchronization", "swift", r"NSLock|os_unfair_lock|DispatchQueue\(|\bactor\b|DispatchSemaphore"),
    ("database", "SQL/store operations are linearizable; transactions are atomic (H10)", "rust",
     r"\blibsql\b|\bturso\b|\bsled::|BEGIN IMMEDIATE|\.transaction\(|\bexecute_batch\b|\bget_del\b|compare_and_swap|\.execute\(|\.query\("),
    ("database", "store", "kotlin", r"SharedPreferences|\bRoom\b|SQLiteDatabase|DataStore"),
    ("database", "store", "swift", r"UserDefaults|\bSecItem(?:Add|Update|CopyMatching|Delete)\b|CoreData|NSPersistentContainer"),
    ("network", "the network is adversary-controlled (no trust; listed for completeness)", "rust",
     r"\breqwest\b|TcpListener|TcpStream|hyper::|axum::serve|tokio_tungstenite"),
]
EXT = {"rust": (".rs",), "kotlin": (".kt",), "swift": (".swift",), "web": (".ts", ".tsx", ".js")}
SKIP_PARTS = {"target", "tests", "test", "benches", "examples", "node_modules", "build", "dist", ".gradle",
              "androidTest", "fuzz", "proofs", "vendor", "vela-e2e"}


def files():
    out = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"], capture_output=True, check=True).stdout.decode()
    for rel in out.split("\0"):
        p = pathlib.Path(rel)
        if rel and not (set(p.parts) & SKIP_PARTS) and not p.name.endswith(("tests.rs", "_test.rs", "Test.kt", "Tests.swift", ".test.ts", ".spec.ts")):
            yield p


def production_lines(path, text):
    """Lines outside #[cfg(test)] modules and comments, with 1-based numbers."""
    lines = text.splitlines()
    skip_depth = None
    depth = 0
    pending_cfg_test = False
    for n, line in enumerate(lines, 1):
        s = line.strip()
        if path.suffix == ".rs":
            if s.startswith("#[cfg(test)]"):
                pending_cfg_test = True
                continue
            if pending_cfg_test and skip_depth is None and re.match(r"(pub\s+)?mod\s+\w+\s*\{", s):
                skip_depth = depth
            pending_cfg_test = pending_cfg_test and not s.startswith(("mod", "pub mod", "fn", "use")) and not s
        opened, closed = line.count("{"), line.count("}")
        in_test = skip_depth is not None
        depth += opened - closed
        if skip_depth is not None and depth <= skip_depth:
            skip_depth = None
        if in_test or s.startswith(("//", "///", "*", "/*")):
            continue
        yield n, line


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "security/assurance/proof-logs/current/os-interface-inventory"))
    a = ap.parse_args()
    pats = [(c, contract, lang, re.compile(rx)) for c, contract, lang, rx in INTERFACES]
    hits = []
    for rel in files():
        langs = [lang for lang, exts in EXT.items() if rel.suffix in exts]
        if not langs:
            continue
        try:
            text = (ROOT / rel).read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError):
            continue
        for n, line in production_lines(rel, text):
            for c, _contract, lang, rx in pats:
                if lang in langs and (m := rx.search(line)):
                    hits.append({"category": c, "lang": lang, "file": str(rel), "line": n,
                                 "match": m.group(), "code": line.strip()[:160]})
    contracts = {c: contract for c, contract, lang, _ in INTERFACES if lang == "rust"}
    out = pathlib.Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "inventory.json").write_text(json.dumps({"contracts": contracts, "hits": hits}, indent=1) + "\n")

    def component(f):
        parts = pathlib.Path(f).parts
        return "/".join(parts[:2]) if len(parts) > 2 else parts[0]

    md = ["# Trusted OS and library interfaces: call sites (plan step T9)", "",
          "Generated by `security/assurance/list-os-interfaces.py`; do not edit by hand. The contracts",
          "are stated in [09](../../../09-target-contract.md#trusted-interfaces). Textual matches in",
          "production code (tests, benches, examples and `#[cfg(test)]` modules skipped): each is a",
          "place to review, not proof of use. Full file:line list in `inventory.json`.", ""]
    by_cat = collections.defaultdict(list)
    for h in hits:
        by_cat[h["category"]].append(h)
    md += ["| Interface | Contract relied on | Call sites | Files |", "|---|---|---|---|"]
    for c in contracts:
        hs = by_cat.get(c, [])
        md.append(f"| {c} | {contracts[c]} | {len(hs)} | {len({h['file'] for h in hs})} |")
    for c in contracts:
        hs = by_cat.get(c, [])
        md += ["", f"## {c}", "", "| Component | Language | Call sites | Files | Matched |", "|---|---|---|---|---|"]
        groups = collections.defaultdict(list)
        for h in hs:
            groups[(component(h["file"]), h["lang"])].append(h)
        for (comp, lang), g in sorted(groups.items(), key=lambda kv: -len(kv[1])):
            kinds = collections.Counter(h["match"] for h in g).most_common(4)
            md.append(f"| `{comp}` | {lang} | {len(g)} | {len({h['file'] for h in g})} | "
                      + ", ".join(f"`{k}` {v}" for k, v in kinds) + " |")
    (out / "README.md").write_text("\n".join(md) + "\n")
    print(", ".join(f"{c} {len(by_cat.get(c, []))}" for c in contracts))


if __name__ == "__main__":
    main()
