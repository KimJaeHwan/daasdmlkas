"""The external supervisor (docs 25.30 K1d): tools/run_supervised.py runs a
command in a delegated transient cgroup-v2 scope; statuses, OOM evidence,
deadline / cancellation cleanup of the whole tree; and export_bundle's
bounded Ghidra run. WSL / Linux as root with systemd only."""

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(REPO / "tools" / "bundle_export"))

import run_supervised  # noqa: E402

pytestmark = pytest.mark.skipif(run_supervised.supported() is not None,
                                reason=f"supervision unavailable: {run_supervised.supported()}")


def _run(script, **limits):
    limits = {"memory": "200M", "deadline": 20.0, "grace": 2.0, **limits}
    return run_supervised.run(["bash", "-c", script], **limits)


def _no_leftovers(marker):
    found = subprocess.run(["pgrep", "-f", marker], capture_output=True, text=True).stdout.split()
    return [pid for pid in found if int(pid) != os.getpid()] == []


def test_a_normal_exit_is_completed():
    record = _run("true")
    assert record["status"] == "completed" and record["scope_empty"]
    assert run_supervised.exit_code(record) == 0


def test_an_exit_code_is_kept():
    record = _run("exit 3")
    assert record["status"] == "exited" and record["final"]["exit_code"] == 3
    assert run_supervised.exit_code(record) == 3


def test_an_oom_is_reported():
    record = _run("python3 -c 'x = bytearray(600 * 1024 * 1024)'")
    assert record["status"] == "oom" and record["scope_empty"]
    assert record["final"]["oom_kill_after"] > record["final"]["oom_kill_before"]


def test_an_oom_of_a_background_descendant_after_a_normal_exit_is_seen():
    record = _run("(sleep 0.5; python3 -c 'x = bytearray(600 * 1024 * 1024)') & exit 0")
    # the launcher kills the work tree after the main process exits: either the
    # descendant was killed first (completed, nothing left) or its OOM is counted
    assert record["scope_empty"]
    assert record["status"] in ("completed", "oom")
    if record["final"]["oom_kill_after"] > record["final"]["oom_kill_before"]:
        assert record["status"] == "oom"


def test_a_deadline_stops_a_term_ignoring_tree():
    marker = "tdo-k1d-deadline-marker"
    record = _run(f"trap '' TERM; (exec -a {marker} sleep 300) & sleep 300", deadline=2.0, grace=1.0)
    assert record["status"] == "deadline" and record["scope_empty"]
    assert run_supervised.exit_code(record) == 3
    assert _no_leftovers(marker)


def test_a_workload_creating_its_own_cgroup_is_cleaned_up():
    script = ("cg=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup); mkdir $cg/inner && "
              "(echo $BASHPID > $cg/inner/cgroup.procs 2>/dev/null; sleep 300) & sleep 0.5; exit 0")
    record = _run(script)
    assert record["scope_empty"] and record["status"] == "completed"


def test_arguments_are_passed_literally():
    out = Path("/tmp/tdo_k1d_args.txt")
    out.unlink(missing_ok=True)
    record = run_supervised.run(["python3", "-c", "import sys; open(sys.argv[1], 'w').write(sys.argv[2])",
                                 str(out), "$HOME ${X}"], memory="200M", deadline=20.0, grace=2.0)
    assert record["status"] == "completed" and out.read_text() == "$HOME ${X}"


def test_supervisor_cancellation_stops_the_tree():
    marker = "tdo-k1d-cancel-marker"
    ready = Path("/tmp/tdo_k1d_cancel_ready")
    ready.unlink(missing_ok=True)
    process = subprocess.Popen([sys.executable, str(REPO / "tools" / "run_supervised.py"), "--memory", "200M",
                                "--deadline", "60", "--grace", "1", "--", "bash", "-c",
                                f"(exec -a {marker} sleep 300) & touch {ready}; sleep 300"],
                               stdout=subprocess.PIPE, text=True)
    # the signal only once the workload runs (it creates the file): a fixed pause
    # raced a slow startup under load; pgrep would match the supervisor's own
    # command line, which carries the marker
    limit = time.monotonic() + 60
    while not ready.exists() and time.monotonic() < limit:
        time.sleep(0.1)
    process.send_signal(signal.SIGINT)
    out, _ = process.communicate(timeout=60)
    record = json.loads(out)
    assert record["status"] == "cancelled" and record["scope_empty"] and process.returncode == 3
    assert _no_leftovers(marker)


def test_a_launcher_killed_outright_leaves_nothing():
    """The supervisor's own cleanup (cgroup.kill, populated 0) after the
    launcher vanished without a final status."""
    marker = "tdo-k1d-launcher-marker"
    script = f"(exec -a {marker} sleep 300) & kill -9 $PPID; sleep 300"
    record = _run(script, deadline=5.0, grace=1.0)
    assert record["scope_empty"]
    assert record["status"] in ("deadline", "infrastructure", "completed", "signalled", "exited")
    assert _no_leftovers(marker)


def test_the_memory_localevents_mount_is_refused(tmp_path, monkeypatch):
    import _launcher

    mounts = tmp_path / "mounts"
    mounts.write_text("cgroup2 /sys/fs/cgroup cgroup2 rw,nosuid,memory_localevents 0 0\n")
    real_open = open

    def fake_open(path, *args, **kwargs):
        return real_open(mounts if path == "/proc/mounts" else path, *args, **kwargs)

    monkeypatch.setattr("builtins.open", fake_open)
    assert _launcher._local_events_mount()


def test_export_cleanup_after_a_normal_leader_exit():
    import export_bundle

    Path("/tmp/tdo_k1d_started").unlink(missing_ok=True)
    marker = "tdo-k1d-export-marker"
    # the descendant is running before the leader exits (bash: exec -a)
    returncode, timed_out, stopped = export_bundle.run_bounded(
        ["bash", "-c", f"(touch /tmp/tdo_k1d_started; exec -a {marker} sleep 300) & "
                       "until [ -e /tmp/tdo_k1d_started ]; do sleep 0.05; done; sleep 0.2; exit 0"],
        dict(os.environ), 20)   # (the descendant itself acknowledges, then execs)
    assert (returncode, timed_out, stopped) == (0, False, True)
    assert Path("/tmp/tdo_k1d_started").exists()
    assert _no_leftovers(marker)


def test_an_exec_failure_is_infrastructure():
    record = run_supervised.run(["/nonexistent/tdo-command"], memory="200M", deadline=20.0, grace=2.0)
    assert record["status"] == "infrastructure" and "exec" in record["error"] and record["scope_empty"]


def test_export_total_timeout():
    import export_bundle

    returncode, timed_out, stopped = export_bundle.run_bounded(
        ["sh", "-c", "trap '' TERM; sleep 300"], dict(os.environ), 1)
    assert timed_out and stopped


def test_export_cleanup_sees_threads_behind_a_zombie_leader():
    """A process whose main thread exited shows as a zombie while a thread runs:
    it is still a live member (Astra K1d impl. round 2, P1)."""
    import export_bundle

    script = "; ".join([
        "import threading, time, ctypes",
        "threading.Thread(target=lambda: time.sleep(300)).start()",
        "time.sleep(0.2)",
        "ctypes.CDLL(None).pthread_exit(None)",
    ])
    record = Path("/tmp/tdo_k1d_thread.txt")
    record.unlink(missing_ok=True)
    # the leader waits until the descendant shows Z with a live task, records
    # its pid and the observed task states, then exits
    leader = (f'python3 -c "{script}" & child=$!; '
              'for i in $(seq 100); do s=$(sed "s/.*) //" /proc/$child/stat | cut -d" " -f1); '
              '[ "$s" = Z ] && break; sleep 0.05; done; '
              f'echo $child $s $(ls /proc/$child/task | wc -l) > {record}; exit 0')
    returncode, timed_out, stopped = export_bundle.run_bounded(["bash", "-c", leader], dict(os.environ), 20)
    pid, state, tasks = record.read_text().split()
    assert state == "Z" and int(tasks) >= 2   # the case: a zombie leader with a live thread
    assert stopped and not timed_out
    assert not export_bundle._threads_running(int(pid))   # nothing of it runs any more
