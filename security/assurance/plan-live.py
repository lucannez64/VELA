#!/usr/bin/env python3
"""Live progress for the formalization plan (20-formalization-plan.md).

Progress lives in ~/.cache/vela-plan/formalization-status.json ($VELA_PLAN_STATE
overrides the directory), shared by every worktree on this machine. Anyone
working on a step (you, Claude, a delegate) records milestones with:

    plan-live.py start  O9 "split the freshness lemma" [--who name]
    plan-live.py log    O9 "vault row model verifies"
    plan-live.py retry  O9 "rlimit blow-up, splitting again"
    plan-live.py block  O9 "needs a schema change first"
    plan-live.py done   O9 "gate green" [--commit SHA]   (default: HEAD)
    plan-live.py undo   O9                                (forget the step)
    plan-live.py show                                     (table in the terminal)

and the dashboard shows them live:

    plan-live.py serve [--port 4318] [--tailscale]  ->  http://127.0.0.1:4318
                                   (--tailscale also serves http://<tailscale-ip>:4318
                                    to your other tailnet devices, e.g. a phone on 5G)

Writes take a file lock and replace the file atomically, so several agents can
report at once. Waiting and ready are not stored: they follow from the plan's
dependencies and the done steps.
"""
import argparse
import datetime as dt
import fcntl
import json
import os
import pathlib
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = pathlib.Path(__file__).resolve().parent
PLAN = HERE / "formalization-plan.json"
# Progress is shared by every worktree on this machine, so it lives outside the repo.
STATE_DIR = pathlib.Path(os.environ.get("VELA_PLAN_STATE", pathlib.Path.home() / ".cache/vela-plan"))
STATE_DIR.mkdir(parents=True, exist_ok=True)
STATUS = STATE_DIR / "formalization-status.json"
PAGE = HERE / "formalization-plan.html"
LOCK = STATE_DIR / "formalization-status.lock"
BOX = os.environ.get("VELA_BOX", "hirew@192.168.1.10")
MAX_LOG = 1000


def now():
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def plan_ids():
    return {n["id"] for n in json.loads(PLAN.read_text())["nodes"]}


def read_status():
    try:
        return json.loads(STATUS.read_text())
    except FileNotFoundError:
        return {"steps": {}, "log": []}


def update(fn):
    """Run fn(status) under the lock and write the result atomically."""
    with open(LOCK, "w") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        st = read_status()
        fn(st)
        st["log"] = st["log"][-MAX_LOG:]
        tmp = STATUS.with_suffix(".tmp")  # same directory, so os.replace is atomic
        tmp.write_text(json.dumps(st, indent=1) + "\n")
        os.replace(tmp, STATUS)


def git(*args):
    try:
        return subprocess.run(["git", "-C", str(HERE), *args], capture_output=True,
                              text=True, timeout=5).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def apply(action, sid, msg="", who="", commit=""):
    if sid not in plan_ids():
        raise ValueError(f"unknown step {sid}")
    if action == "done" and not commit:
        commit = git("rev-parse", "HEAD")

    def fn(st):
        t = now()
        if action == "undo":
            st["steps"].pop(sid, None)
            st["log"].append({"t": t, "step": sid, "kind": "undo", "msg": msg or "reset"})
            return
        e = st["steps"].setdefault(sid, {"state": "in_progress", "started": t, "retries": 0})
        e["updated"] = t
        if who:
            e["who"] = who
        if action == "start":
            if e.get("state") != "in_progress":
                e.update(state="in_progress", started=t)
                e.pop("finished", None)
        elif action == "retry":
            e["retries"] = e.get("retries", 0) + 1
            e["state"] = "in_progress"
        elif action == "block":
            e["state"] = "blocked"
        elif action == "done":
            e.update(state="done", finished=t, commit=commit)
        if msg:
            e["note"] = msg
        st["log"].append({"t": t, "step": sid, "kind": action, "msg": msg, **({"who": who} if who else {})})

    update(fn)


# ---------------------------------------------------------------- server ----
class Facts:
    """Git and load facts, refreshed in the background so requests stay fast."""

    def __init__(self):
        self.data = {}
        self.box = None
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        n = 0
        while True:
            try:
                self.refresh(box=(n % 4 == 0))
            except Exception as exc:  # keep serving even if git misbehaves
                self.data["error"] = str(exc)
            n += 1
            time.sleep(5)

    def refresh(self, box):
        if box:
            try:
                out = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=3", BOX,
                                      "cat /proc/loadavg; nproc"], capture_output=True,
                                     text=True, timeout=8).stdout.split()
                self.box = [float(x) for x in out[:3]] + [int(out[5])] if len(out) >= 6 else None
            except (OSError, subprocess.TimeoutExpired, ValueError):
                self.box = None
        head = git("rev-parse", "--short", "HEAD")
        up = git("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")
        ahead = git("rev-list", "--count", "@{u}..HEAD") if up else ""
        pushed = {}
        for sid, e in read_status()["steps"].items():
            c = e.get("commit")
            if e.get("state") == "done" and c:
                ok = up and subprocess.run(["git", "-C", str(HERE), "merge-base", "--is-ancestor", c, up],
                                           capture_output=True).returncode == 0
                pushed[sid] = bool(ok)
        self.data = {
            "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
            "head": head,
            "upstream": up,
            "origin": git("rev-parse", "--short", "@{u}") if up else "",
            "ahead": int(ahead) if ahead.isdigit() else None,
            "pushed": pushed,
            "load": list(os.getloadavg()) + [os.cpu_count()],
            "box": self.box,
            "box_host": BOX,
            "checked": now(),
        }


def tailscale_ip():
    try:
        out = subprocess.run(["tailscale", "ip", "-4"], capture_output=True, text=True, timeout=5).stdout.split()
        return out[0] if out else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def serve(port, tailscale=False):
    facts = Facts()

    class H(BaseHTTPRequestHandler):
        def send(self, code, body, ctype):
            b = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                self.send(200, PAGE.read_bytes(), "text/html; charset=utf-8")
            elif self.path == "/api/state":
                st = read_status()
                st["facts"] = facts.data
                st["status_mtime"] = STATUS.stat().st_mtime if STATUS.exists() else 0
                self.send(200, json.dumps(st), "application/json")
            else:
                self.send(404, "not found", "text/plain")

        def do_POST(self):
            if self.path != "/api/step":
                return self.send(404, "not found", "text/plain")
            # Only accept same-origin requests from the dashboard itself: a page
            # on another site cannot send an Origin matching this Host.
            origin = self.headers.get("Origin", "")
            host = self.headers.get("Host", "")
            if origin and origin not in (f"http://{host}", f"https://{host}"):
                return self.send(403, "forbidden", "text/plain")
            try:
                req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                if req.get("action") not in ("start", "done", "undo", "block", "log"):
                    raise ValueError("bad action")
                apply(req["action"], req["id"], req.get("msg", ""), "dashboard")
                self.send(200, "{}", "application/json")
            except (ValueError, KeyError, json.JSONDecodeError) as exc:
                self.send(400, json.dumps({"error": str(exc)}), "application/json")

        def log_message(self, *_):
            pass

    binds = ["127.0.0.1"]
    if tailscale:
        ip = tailscale_ip()
        if not ip:
            sys.exit("--tailscale: no Tailscale IPv4 address (is tailscaled up?)")
        binds.append(ip)  # reachable only from devices in this tailnet
    servers = [ThreadingHTTPServer((b, port), H) for b in binds]
    for b in binds:
        print(f"Formalization plan: http://{b}:{port}", flush=True)
    for srv in servers[1:]:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    servers[0].serve_forever()


def show():
    st = read_status()
    for sid, e in sorted(st["steps"].items()):
        print(f"{sid:6} {e['state']:12} {e.get('updated', ''):26} {e.get('note', '')}")
    if not st["steps"]:
        print("no steps started yet")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for c in ("start", "log", "retry", "block", "done", "undo"):
        p = sub.add_parser(c)
        p.add_argument("id")
        p.add_argument("msg", nargs="?", default="")
        p.add_argument("--who", default=os.environ.get("VELA_PLAN_WHO", ""))
        if c == "done":
            p.add_argument("--commit", default="")
    p = sub.add_parser("serve")
    p.add_argument("--port", type=int, default=4318)
    p.add_argument("--tailscale", action="store_true",
                   help="also listen on this machine's Tailscale address (tailnet devices only)")
    sub.add_parser("show")
    a = ap.parse_args()
    if a.cmd == "serve":
        serve(a.port, a.tailscale)
    elif a.cmd == "show":
        show()
    else:
        try:
            apply(a.cmd, a.id, a.msg, a.who, getattr(a, "commit", ""))
        except ValueError as exc:
            sys.exit(str(exc))


if __name__ == "__main__":
    main()
