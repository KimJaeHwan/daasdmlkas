"""Run a command under an external supervisor (docs 25.30 K1d): a transient
cgroup-v2 scope (systemd-run, delegated) with a memory limit (no swap), a
task limit, a wall deadline with a grace period, and verified cleanup of the
whole process tree on every exit path. Linux / WSL as root only (native
Windows: refused).

    run_supervised.py [--memory 12G] [--tasks 4096] [--deadline SECONDS]
                      [--grace 30] [--status FILE] -- command...

Prints one JSON status line (and writes it to --status): "status" is the
process outcome -- completed | exited | signalled | oom | deadline |
cancelled | cleanup-failed | infrastructure -- by precedence (cancelled >
deadline > oom > launcher cleanup-failed > signalled > exited > completed;
a scope the supervisor cannot show empty is cleanup-failed whatever else
happened); the raw evidence is kept. The analysis's own completeness (failed
functions ...) is the command's output, not this status. Exit code: the
command's when completed / exited, else 3 (deadline / cancelled), 4 (oom),
5 (cleanup-failed / infrastructure)."""

from __future__ import annotations

import argparse
import json
import os
import select
import shutil
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path


def _gone(error: OSError) -> bool:
    import errno

    return error.errno in (errno.ENOENT, errno.ENODEV)

LAUNCHER = Path(__file__).resolve().with_name("_launcher.py")
STARTUP_SECONDS = 10.0
REAP_SECONDS = 10.0
SCOPE_EMPTY_SECONDS = 15.0


def _bytes(text: str) -> int:
    units = {"K": 1 << 10, "M": 1 << 20, "G": 1 << 30}
    return int(float(text[:-1]) * units[text[-1].upper()]) if text[-1].upper() in units else int(text)


def _scope_path(unit: str) -> str:
    return f"/sys/fs/cgroup/system.slice/{unit}.scope"


def _populated(path: str) -> bool:
    try:
        with open(path + "/cgroup.events", encoding="ascii") as handle:
            return any(line.split() == ["populated", "1"] for line in handle)
    except OSError as error:
        if not _gone(error):
            raise
        return False   # (systemd removed the empty scope after a confirmed start)


def _kill_scope(path: str) -> None:
    try:
        with open(path + "/cgroup.kill", "w", encoding="ascii") as handle:
            handle.write("1")
    except OSError as error:
        if not _gone(error):
            raise



def _unit_result(unit: str) -> str | None:
    try:
        shown = subprocess.run(["systemctl", "show", "-P", "Result", f"{unit}.scope"], capture_output=True,
                               text=True, timeout=10)
        return shown.stdout.strip() or None
    except (OSError, subprocess.TimeoutExpired):
        return None


def supported() -> str | None:
    """Why supervision is not available here, or None."""
    if not sys.platform.startswith("linux"):
        return "not Linux"
    if os.geteuid() != 0:
        return "not root"
    if shutil.which("systemd-run") is None:
        return "systemd-run not found"
    if not os.path.exists("/sys/fs/cgroup/cgroup.controllers"):
        return "no cgroup v2 unified hierarchy"
    return None


def run(command: list[str], *, memory: str = "12G", tasks: int = 4096, deadline: float = 3600.0,
        grace: float = 30.0) -> dict:
    """Run ``command`` supervised; the status record. The caller's SIGINT /
    SIGTERM handlers are restored whatever happens (an outer finally: Astra
    K1d impl. round 2, P2)."""
    saved = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        return _run(command, memory=memory, tasks=tasks, deadline=deadline, grace=grace)
    finally:
        for sig, handler in saved.items():
            signal.signal(sig, handler)


def _run(command, *, memory, tasks, deadline, grace) -> dict:
    unit = f"tdo-{uuid.uuid4().hex[:16]}"
    record: dict = {"unit": unit, "command": command, "limits": {
        "memory_max": memory, "swap_max": 0, "tasks_max": tasks, "deadline_s": deadline, "grace_s": grace,
        "memory_high": None}, "events": []}
    reason = supported()
    if reason is not None:
        return {**record, "status": "infrastructure", "error": f"unsupervised environment: {reason}"}
    status_read, status_write = os.pipe()
    backstop = deadline + grace + 60
    argv = ["systemd-run", "--scope", "--quiet", "--expand-environment=no", "--unit", unit,
            "-p", "Delegate=yes", "-p", f"MemoryMax={_bytes(memory)}", "-p", "MemorySwapMax=0",
            "-p", "OOMPolicy=continue", "-p", f"TasksMax={tasks}", "-p", f"RuntimeMaxSec={int(backstop)}",
            "--", sys.executable, str(LAUNCHER), "--status-fd", str(status_write), "--grace", str(grace),
            "--", *command]
    cancelled = {"signal": None}

    def on_signal(signum, frame):
        cancelled["signal"] = cancelled["signal"] or signum

    for sig in (signal.SIGINT, signal.SIGTERM):   # (restored by ``run``)
        signal.signal(sig, on_signal)
    lines: list[dict] = []
    buffer = b""
    launcher = None
    try:
        launcher = subprocess.Popen(argv, pass_fds=(status_write,))
        os.close(status_write)
        start = time.monotonic()
        ready = final = None
        deadline_at = None
        terminate_sent = backstop_sent = False
        while final is None:
            now = time.monotonic()
            if ready is None and now - start > STARTUP_SECONDS:
                record["events"].append(("startup-timeout", time.time()))
                break
            if cancelled["signal"] is not None and not terminate_sent:
                record["events"].append(("cancelled", time.time()))
                launcher.send_signal(signal.SIGTERM)
                terminate_sent, deadline_at = True, now
            if ready is not None and not terminate_sent and now - start > deadline:
                record["events"].append(("deadline", time.time()))   # (recorded before signalling)
                launcher.send_signal(signal.SIGTERM)
                terminate_sent, deadline_at = True, now
            if terminate_sent and not backstop_sent and now - deadline_at > grace + 5:
                record["events"].append(("backstop-kill", time.time()))
                _kill_scope(_scope_path(unit))
                backstop_sent = True
            if backstop_sent and now - deadline_at > grace + 5 + REAP_SECONDS:
                break   # (a launcher that never reports: bounded)
            readable, _, _ = select.select([status_read], [], [], 0.2)
            if readable:
                chunk = os.read(status_read, 65536)
                if not chunk:
                    break   # (the launcher is gone)
                buffer += chunk
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    item = json.loads(line)
                    lines.append(item)
                    if item.get("kind") == "ready":
                        ready = item
                    elif item.get("kind") == "final":
                        final = item
        record["launcher"] = lines
    finally:
        # (the cancellation handlers stay installed through the cleanup: a
        # Ctrl-C here is recorded, never an exception -- Astra K1d impl. P1-2)
        os.close(status_read)
        # every exit path: reap the launcher (bounded), then show the scope empty
        if launcher is not None:
            try:
                launcher.wait(REAP_SECONDS)
            except subprocess.TimeoutExpired:
                _kill_scope(_scope_path(unit))
                try:
                    launcher.wait(REAP_SECONDS)
                except subprocess.TimeoutExpired:
                    launcher.kill()
                    try:
                        launcher.wait(REAP_SECONDS)
                    except subprocess.TimeoutExpired:
                        record["events"].append(("launcher-not-reaped", time.time()))
            record["launcher_returncode"] = launcher.returncode
        path = _scope_path(unit)
        if _populated(path):
            _kill_scope(path)
        limit = time.monotonic() + SCOPE_EMPTY_SECONDS
        while _populated(path) and time.monotonic() < limit:
            time.sleep(0.1)
        record["scope_empty"] = not _populated(path)
        record["unit_result"] = _unit_result(unit)
        if record["scope_empty"]:
            try:
                done = subprocess.run(["systemctl", "reset-failed", f"{unit}.scope"], capture_output=True,
                                      text=True, timeout=10)
                if done.returncode != 0:
                    record["events"].append(("reset-failed-error", f"rc={done.returncode}: {done.stderr.strip()}"))
            except (OSError, subprocess.TimeoutExpired) as error:
                record["events"].append(("reset-failed-error", repr(error)))
    if cancelled["signal"] is not None and ("cancelled", ) not in {(name,) for name, _ in record["events"]}:
        record["events"].append(("cancelled", time.time()))   # (a signal seen during the last read / cleanup)
    names = {name for name, _ in record["events"]}
    final = next((item for item in reversed(lines) if item.get("kind") == "final"), None)
    started = any(item.get("kind") == "ready" for item in lines) or (
        final is not None and final.get("status") != "infrastructure")
    record["final"] = final
    if not record["scope_empty"] or "launcher-not-reaped" in names:
        record["status"] = "cleanup-failed"
    elif "cancelled" in names:   # (before or after the start)
        record["status"] = "cancelled"
    elif not started:
        record["status"] = "infrastructure"
        record["error"] = (final or {}).get("error", "the launcher did not start the workload")
    elif "deadline" in names:
        record["status"] = "deadline"
    elif (final is not None and final.get("status") == "oom") or record["unit_result"] == "oom-kill":
        record["status"] = "oom"
    elif final is None:
        record["status"] = "infrastructure"
        record["error"] = "no final status from the launcher"
    else:
        record["status"] = final["status"]
    return record


def exit_code(record: dict) -> int:
    status = record["status"]
    if status in ("completed", "exited"):
        return (record.get("final") or {}).get("exit_code") or 0
    return {"deadline": 3, "cancelled": 3, "oom": 4, "signalled": 6}.get(status, 5)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--memory", default="12G")
    parser.add_argument("--tasks", type=int, default=4096)
    parser.add_argument("--deadline", type=float, default=3600.0)
    parser.add_argument("--grace", type=float, default=30.0)
    parser.add_argument("--status", type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    record = run(command, memory=args.memory, tasks=args.tasks, deadline=args.deadline, grace=args.grace)
    text = json.dumps(record, sort_keys=True, default=str)
    print(text)
    if args.status is not None:
        partial = args.status.with_name(args.status.name + ".partial")
        partial.write_text(text + "\n", encoding="utf-8")
        partial.replace(args.status)
    return exit_code(record)


if __name__ == "__main__":
    raise SystemExit(main())
