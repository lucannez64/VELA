#!/usr/bin/env python3
"""Fail on unpinned CI environment inputs (assurance T10).

This is a source-policy check, not a hermeticity proof. It rejects the
specific ways the proof/security workflows used to drift:

  1. a remote ``uses:`` that is not a full 40-hex commit SHA with a trailing
     version comment;
  2. a floating runner label (``*-latest``) in a proof/security workflow;
  3. a tool install with no exact version (taiki-e ``tool@version``,
     ``cargo install --version``, ``pip ==``, ``npm @version``);
  4. an apt install outside the fixed Ubuntu snapshot in a proof/security
     workflow;
  5. a proof-image reference, opam lock or install script that no longer
     matches what the workflows and README describe.

Run from anywhere: python3 -I security/assurance/check-env-pins.py
Exit status is 1 on the first batch of violations printed.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = ROOT / ".github/workflows"
# Workflows whose whole point is the security/proof evidence: their runners,
# apt sources and tool installs must be pinned here.
PROOF_WORKFLOWS = {"security.yml", "proof-image.yml", "fuzz.yml"}
ALL_WORKFLOWS = sorted(WORKFLOW_DIR.glob("*.yml"))
SHA = re.compile(r"[0-9a-f]{40}")
USES = re.compile(r"^(?P<pre>\s*(?:-\s*)?uses:\s*)(?P<value>\S+)(?P<tail>.*)$")
RUNS_ON = re.compile(r"^\s*runs-on:\s*(?P<value>[^#]+?)\s*(?:#.*)?$")
SNAPSHOT_STAMP = re.compile(r"snapshot\.ubuntu\.com/ubuntu/(\d{8}T\d{6}Z)/")
IMAGE_RE = re.compile(r"^ghcr\.io/lucannez64/vela-proof@sha256:(?:[0-9a-f]{64}|PLACEHOLDER)$")
LOCK = ROOT / "security/assurance/opam-lock/hax-engine.opam.locked"
IMAGE_FILE = ROOT / "security/assurance/proof-image/IMAGE"
SNAPSHOT_CONF = ROOT / "security/assurance/proof-image/apt-snapshot.conf"
DOCKERFILE = ROOT / "security/assurance/proof-image/Dockerfile"

failures: list[str] = []


def fail(where: str, message: str) -> None:
    failures.append(f"{where}: {message}")


def check_uses() -> None:
    for path in ALL_WORKFLOWS:
        for number, line in enumerate(path.read_text().splitlines(), 1):
            match = USES.match(line)
            if not match:
                continue
            value, tail = match.group("value"), match.group("tail")
            if value.startswith("./") or value.startswith("docker://"):
                continue  # local composite action or a pinned OCI reference
            where = f"{path.relative_to(ROOT)}:{number}"
            if "@" not in value:
                fail(where, f"unpinned action {value!r} (add @<40-hex sha> # vX.Y.Z)")
                continue
            ref = value.rsplit("@", 1)[1]
            if not SHA.fullmatch(ref):
                fail(where, f"action {value!r} is not pinned to a full commit SHA")
            if "#" not in tail:
                fail(where, f"action {value!r} needs a trailing '# vX.Y.Z' comment")


def check_runners() -> None:
    for name in sorted(PROOF_WORKFLOWS):
        path = WORKFLOW_DIR / name
        if not path.exists():
            fail(name, "proof/security workflow is missing")
            continue
        for number, line in enumerate(path.read_text().splitlines(), 1):
            match = RUNS_ON.match(line)
            if not match:
                continue
            value = match.group("value").strip()
            if value.startswith("${{"):
                continue  # resolved from a pinned matrix / picker output
            if "latest" in value:
                fail(
                    f"{name}:{number}",
                    f"floating runner {value!r}; pin a fixed image (ubuntu-24.04)",
                )


def _run_texts(path: Path):
    """Yield (job, step-name, run-text) for every run: block, without PyYAML
    re-serialising the file (comments and ordering are irrelevant here)."""
    try:
        import yaml  # noqa: PLC0415 - optional at import time for --help paths
    except ImportError:  # pragma: no cover - CI installs PyYAML
        return
    data = yaml.safe_load(path.read_text())
    for job, body in (data.get("jobs") or {}).items():
        for step in (body or {}).get("steps") or []:
            if isinstance(step, dict) and isinstance(step.get("run"), str):
                yield job, step.get("name", "run"), step["run"]


def check_tool_installs() -> None:
    for path in ALL_WORKFLOWS:
        where_file = str(path.relative_to(ROOT))
        for job, step, text in _run_texts(path):
            where = f"{where_file}:{job}:{step}"
            # cargo install must name an exact crate version.
            for command in re.findall(r"cargo install[^\n]*", text):
                if "--version" not in command:
                    fail(where, f"cargo install without --version: {command.strip()!r}")
            # pip packages must be exact.
            for match in re.finditer(r"(?:python3? -m )?pip3? install(?P<args>[^\n]*)", text):
                for arg in match.group("args").split():
                    arg = arg.strip("'\"")
                    if arg.startswith("-") or not arg:
                        continue
                    if arg.startswith(("git+", "http", ".")):
                        continue
                    if "==" not in arg:
                        fail(where, f"pip package without ==version: {arg!r}")
            # npm globals must pin a version.
            for match in re.finditer(r"npm (?:install|i)(?P<args>[^\n]*)", text):
                for arg in match.group("args").split():
                    arg = arg.strip("'\"")
                    if arg.startswith("-") or not arg:
                        continue
                    if "@" not in arg.lstrip("@"):
                        fail(where, f"npm package without @version: {arg!r}")
        # taiki-e/install-action tool specs.
        import yaml  # noqa: PLC0415
        data = yaml.safe_load(path.read_text())
        for job, body in (data.get("jobs") or {}).items():
            for step in (body or {}).get("steps") or []:
                if not isinstance(step, dict):
                    continue
                if not str(step.get("uses", "")).startswith("taiki-e/install-action"):
                    continue
                tools = str((step.get("with") or {}).get("tool", ""))
                for tool in re.split(r"[,\s]+", tools):
                    if tool and "@" not in tool:
                        fail(
                            f"{where_file}:{job}",
                            f"taiki-e tool without @version: {tool!r}",
                        )


def check_apt_snapshot() -> None:
    stamp = None
    if SNAPSHOT_CONF.exists():
        match = re.search(r"(\d{8}T\d{6}Z)", SNAPSHOT_CONF.read_text())
        stamp = match.group(1) if match else None
    if not stamp:
        fail(str(SNAPSHOT_CONF.relative_to(ROOT)), "missing fixed snapshot stamp")
        return
    for name in sorted(PROOF_WORKFLOWS):
        path = WORKFLOW_DIR / name
        if not path.exists():
            continue
        for job, step, text in _run_texts(path):
            if not re.search(r"apt(?:-get)? install", text):
                continue
            found = SNAPSHOT_STAMP.search(text)
            where = f"{name}:{job}:{step}"
            if not found:
                fail(where, "apt install without snapshot.ubuntu.com sources")
            elif found.group(1) != stamp:
                fail(
                    where,
                    f"apt snapshot {found.group(1)} != {stamp} in "
                    f"{SNAPSHOT_CONF.relative_to(ROOT)}",
                )


def check_proof_image() -> None:
    if not IMAGE_FILE.exists():
        fail(str(IMAGE_FILE.relative_to(ROOT)), "missing image reference file")
    else:
        lines = IMAGE_FILE.read_text().splitlines()
        if len([line for line in lines if line.strip()]) != 1:
            fail(str(IMAGE_FILE.relative_to(ROOT)), "must hold exactly one line")
        elif not IMAGE_RE.fullmatch(lines[0].strip()):
            fail(
                str(IMAGE_FILE.relative_to(ROOT)),
                "must be ghcr.io/lucannez64/vela-proof@sha256:<64 hex> "
                "(or the bootstrap placeholder)",
            )
    if not DOCKERFILE.exists():
        fail(str(DOCKERFILE.relative_to(ROOT)), "missing proof Dockerfile")
        return
    dockerfile = DOCKERFILE.read_text()
    for number, line in enumerate(dockerfile.splitlines(), 1):
        if re.match(r"^\s*FROM\s", line) and "@sha256:" not in line:
            fail(f"{DOCKERFILE.relative_to(ROOT)}:{number}", "FROM without digest")
    stamp_match = SNAPSHOT_STAMP.search(dockerfile)
    if not stamp_match:
        fail(str(DOCKERFILE.relative_to(ROOT)), "apt is not pinned to a snapshot")
    elif SNAPSHOT_CONF.exists():
        conf = re.search(r"(\d{8}T\d{6}Z)", SNAPSHOT_CONF.read_text())
        if conf and conf.group(1) != stamp_match.group(1):
            fail(
                str(DOCKERFILE.relative_to(ROOT)),
                f"snapshot {stamp_match.group(1)} != {conf.group(1)}",
            )


def check_opam_lock() -> None:
    installer = ROOT / "security/assurance/install-hax.sh"
    text = installer.read_text()
    if "opam-lock/hax-engine.opam.locked" not in text or "--locked" not in text:
        fail(
            str(installer.relative_to(ROOT)),
            "must install the engine with opam-lock/hax-engine.opam.locked "
            "and --locked",
        )
    if not LOCK.exists():
        fail(str(LOCK.relative_to(ROOT)), "missing frozen hax engine resolution")
        return
    lock = LOCK.read_text()
    deps = lock.split("depends: [", 1)[-1].split("]", 1)[0]
    for line in deps.splitlines():
        line = line.strip()
        if not line:
            continue
        if not re.fullmatch(r'"[^"]+" \{= "[^"]+"\}', line):
            fail(str(LOCK.relative_to(ROOT)), f"unpinned dependency {line!r}")
    for package in ("ocaml", "ocaml-base-compiler", "dune"):
        if not re.search(rf'"{package}" \{{= "', deps):
            fail(str(LOCK.relative_to(ROOT)), f"{package} is not pinned")


def main() -> int:
    check_uses()
    check_runners()
    check_tool_installs()
    check_apt_snapshot()
    check_proof_image()
    check_opam_lock()
    if failures:
        print("environment pin check FAILED:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print(
        f"environment pins OK: {len(ALL_WORKFLOWS)} workflows, "
        f"{len(PROOF_WORKFLOWS)} proof/security, opam lock and proof image"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
