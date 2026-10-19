"""The in-scope launcher of tools/run_supervised.py (docs 25.30 K1d). Linux /
WSL, root, cgroup v2; started by systemd-run as the first process of a
delegated transient scope:

    _launcher.py --status-fd N --grace SECONDS -- command...

1. Moves itself into ``<scope>/launcher``, creates ``<scope>/work``, enables
   +memory +pids for the children (the scope keeps MemoryMax / TasksMax for
   both); refuses a cgroup mount with ``memory_localevents`` (the scope's
   memory.events must count the work subtree); sets its own oom_score_adj to
   -1000.
2. Forks the workload: the child moves itself into ``work``, setsid(),
   oom_score_adj +500, acknowledges, execs. The launcher reports "ready".
3. Waits (100 ms): the child's exit; an oom_kill increment in the scope's
   memory.events (then ``work/cgroup.kill``); SIGTERM / SIGINT from the
   supervisor (forwarded to the child's process group while the child is
   unreaped, then ``work/cgroup.kill`` after the grace).
4. After the child: ``work/cgroup.kill``, ``work`` populated 0 (bounded), THEN
   the final read of memory.events; one JSON status line; exit.

Termination never signals a numeric pid it did not fork: the work tree is
killed through ``work/cgroup.kill`` (recursive, kernel-side)."""

from __future__ import annotations

import json
import os
import signal
import sys
import time


def _gone(error: OSError) -> bool:
    import errno

    return error.errno in (errno.ENOENT, errno.ENODEV)

CLEANUP_SECONDS = 10.0


def _write(fd: int, record: dict) -> None:
    os.write(fd, (json.dumps(record, sort_keys=True) + "\n").encode())


def _scope() -> str:
    for line in open("/proc/self/cgroup", encoding="ascii"):
        if line.startswith("0::"):
            return "/sys/fs/cgroup" + line[3:].strip()
    raise RuntimeError("not on the cgroup v2 unified hierarchy")


def _read_events(path: str) -> dict:
    with open(path, encoding="ascii") as handle:
        return {key: int(value) for key, value in (line.split() for line in handle)}


def _populated(cgroup: str) -> bool:
    try:
        return _read_events(cgroup + "/cgroup.events").get("populated", 0) != 0
    except OSError as error:
        if not _gone(error):
            raise
        return False


def _kill(cgroup: str) -> None:
    try:
        with open(cgroup + "/cgroup.kill", "w", encoding="ascii") as handle:
            handle.write("1")
    except OSError as error:
        if not _gone(error):
            raise



def _local_events_mount() -> bool:
    for line in open("/proc/mounts", encoding="ascii"):
        fields = line.split()
        if len(fields) >= 4 and fields[2] == "cgroup2" and fields[1] == "/sys/fs/cgroup":
            return "memory_localevents" in fields[3].split(",")
    return True   # (no unified mount found: refuse)


def main(argv: list[str]) -> int:
    status_fd = int(argv[argv.index("--status-fd") + 1])
    os.set_inheritable(status_fd, False)   # (never the workload's: agy K1d impl. P2-1)
    grace = float(argv[argv.index("--grace") + 1])
    command = argv[argv.index("--") + 1:]
    started = time.time()
    record = {"launcher_pid": os.getpid(), "command": command, "started": started}
    try:
        if not command:
            raise RuntimeError("no command")
        if _local_events_mount():
            raise RuntimeError("cgroup2 mounted with memory_localevents (or not found): OOM evidence would miss the work subtree")
        scope = _scope()
        os.mkdir(scope + "/launcher")
        os.mkdir(scope + "/work")
        with open(scope + "/launcher/cgroup.procs", "w", encoding="ascii") as handle:
            handle.write(str(os.getpid()))
        with open(scope + "/cgroup.subtree_control", "w", encoding="ascii") as handle:
            handle.write("+memory +pids")
        with open("/proc/self/oom_score_adj", "w", encoding="ascii") as handle:
            handle.write("-1000")
        oom_before = _read_events(scope + "/memory.events").get("oom_kill", 0)
    except Exception as error:   # noqa: BLE001 -- a setup failure: the workload never starts
        _write(status_fd, {**record, "kind": "final", "status": "infrastructure", "error": f"setup: {error}"})
        return 70
    record["scope"] = scope
    # one close-on-exec pipe: "S" after the child's setup, then EOF at a
    # successful exec, or "E<error>" when the exec fails (Astra K1d impl. P2-4)
    acknowledge, confirm = os.pipe()
    child = os.fork()
    if child == 0:   # the workload
        try:
            os.close(acknowledge)
            os.close(status_fd)
            with open(scope + "/work/cgroup.procs", "w", encoding="ascii") as handle:
                handle.write(str(os.getpid()))
            os.setsid()
            with open("/proc/self/oom_score_adj", "w", encoding="ascii") as handle:
                handle.write("500")
            os.write(confirm, b"S")   # (only after migration, setsid and the score)
        except BaseException:   # noqa: BLE001 -- the launcher sees no "S"
            os._exit(127)
        try:
            os.execvp(command[0], command)
        except BaseException as error:   # noqa: BLE001 -- reported, the command never ran
            try:
                os.write(confirm, b"E" + str(error).encode(errors="replace")[:1000])
            finally:
                os._exit(127)
    os.close(confirm)
    report = b""
    while chunk := os.read(acknowledge, 4096):
        report += chunk
    os.close(acknowledge)
    if report[:1] != b"S" or report[1:2] == b"E":
        os.waitpid(child, 0)
        _kill(scope + "/work")
        error = report[2:].decode(errors="replace") if report[1:2] == b"E" else "workload setup failed"
        _write(status_fd, {**record, "kind": "final", "status": "infrastructure",
                           "error": f"exec: {error}" if report[1:2] == b"E" else error})
        return 70
    _write(status_fd, {**record, "kind": "ready", "child": child})

    terminate = {"at": None}
    reaped = {"done": False}

    def on_signal(signum, frame):
        if terminate["at"] is None:
            terminate["at"] = time.monotonic()
            if not reaped["done"]:
                try:
                    os.killpg(child, signal.SIGTERM)   # (unreaped: its group id cannot be reused)
                except ProcessLookupError:
                    pass

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    oom_seen = False
    exit_status = None
    blocked = {signal.SIGTERM, signal.SIGINT}
    while exit_status is None:
        # reaping and marking it are one step for the handler (no killpg after the reap)
        signal.pthread_sigmask(signal.SIG_BLOCK, blocked)
        try:
            pid, status = os.waitpid(child, os.WNOHANG)
            if pid == child:
                exit_status, reaped["done"] = status, True
        finally:
            signal.pthread_sigmask(signal.SIG_UNBLOCK, blocked)
        if exit_status is not None:
            break
        if not oom_seen and _read_events(scope + "/memory.events").get("oom_kill", 0) > oom_before:
            oom_seen = True
            _kill(scope + "/work")
        if terminate["at"] is not None and time.monotonic() - terminate["at"] > grace:
            _kill(scope + "/work")
        time.sleep(0.1)
    # the child is reaped: from here only the cgroup is used
    _kill(scope + "/work")
    deadline = time.monotonic() + CLEANUP_SECONDS
    while _populated(scope + "/work") and time.monotonic() < deadline:
        time.sleep(0.05)
    cleaned = not _populated(scope + "/work")
    oom_after = _read_events(scope + "/memory.events").get("oom_kill", 0)   # (after the work subtree is gone)
    peaks = {}
    for label, path in (("scope", scope), ("work", scope + "/work")):   # (read while the cgroups exist)
        try:
            with open(path + "/memory.peak", encoding="ascii") as handle:
                peaks[label] = int(handle.read().strip())
        except (OSError, ValueError):
            peaks[label] = None
    final = {
        **record, "kind": "final", "child": child,
        "exit_code": os.WEXITSTATUS(exit_status) if os.WIFEXITED(exit_status) else None,
        "signal": os.WTERMSIG(exit_status) if os.WIFSIGNALED(exit_status) else None,
        "oom_kill_before": oom_before, "oom_kill_after": oom_after,
        "terminated": terminate["at"] is not None, "cleanup": "ok" if cleaned else "failed",
        "memory_peak_scope": peaks["scope"], "memory_peak_work": peaks["work"],
        "finished": time.time(),
    }
    final["status"] = ("oom" if oom_after > oom_before else "cleanup-failed" if not cleaned
                       else "signalled" if final["signal"] is not None
                       else "exited" if final["exit_code"] else "completed")
    _write(status_fd, final)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
