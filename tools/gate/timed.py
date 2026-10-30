"""Run a command with a time limit and record its wall time and peak memory: a portable stand-in for
GNU ``/usr/bin/time -f "%e s %M KB" -o FILE timeout LIMIT cmd`` (macOS has neither by default).

usage: python timed.py --out FILE [--timeout SECONDS] -- cmd [args...]

FILE gets one line "<wall seconds> s <peak KB> KB" (the largest resident size of the command or one of its
waited-for descendants, as GNU time's %M; a floor of the wrapper's own fork size). Exit status: the command's,
124 when the limit was hit (as GNU timeout), 128+N when it died of signal N.
The command runs in its own process group. On a time-out the group gets SIGTERM, then -- 10 s later, or as soon as
the command itself has exited -- SIGKILL (so no descendant outlives the job; the command is reaped only after
that, which keeps its group id from being reused). SIGTERM / SIGHUP (and SIGINT unless ignored, as in a background
job) to this wrapper are passed on to the group, also when they arrive while the command is being started, and
end the same way: SIGKILL to the group 10 s later or once the command has exited."""
import argparse
import os
import resource
import signal
import subprocess
import sys
import time

parser = argparse.ArgumentParser()
parser.add_argument("--out", required=True)
parser.add_argument("--timeout", type=float, default=None)
parser.add_argument("command", nargs=argparse.REMAINDER)
args = parser.parse_args()
command = args.command[1:] if args.command[:1] == ["--"] else args.command
if not command:
    parser.error("no command")

child = None
pending = []          # signals received before the command's group exists
stop_at = None        # a forwarded signal: the group is killed by this time at the latest


def stop_group(sig):
    try:
        os.killpg(child.pid, sig)
    except ProcessLookupError:
        pass


def forward(signum, frame):
    global stop_at
    if stop_at is None:
        stop_at = time.monotonic() + 10
    if child is None:
        pending.append(signum)
    else:
        stop_group(signum)


for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    if signal.getsignal(sig) is not signal.SIG_IGN:      # (a background job keeps SIGINT ignored)
        signal.signal(sig, forward)


def exited(timeout):
    """The command has exited (left unreaped: its pid, the group id, stays reserved), within ``timeout`` s."""
    deadline = None if timeout is None else time.monotonic() + timeout
    while True:
        if not hasattr(os, "waitid"):          # (CPython on macOS has no waitid: reaped here, a negligible window)
            if child.poll() is not None:
                return True
        else:
            try:
                if os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG) is not None:
                    return True
            except ChildProcessError:
                return True
        if deadline is not None and time.monotonic() >= deadline:
            return False
        if stop_at is not None and time.monotonic() >= stop_at:
            return False
        time.sleep(0.05)


start = time.monotonic()
child = subprocess.Popen(command, start_new_session=True)   # (own group: a time-out stops the whole job)
for signum in pending:
    stop_group(signum)
finished = exited(args.timeout)
timed_out = not finished and stop_at is None
if timed_out:
    stop_group(signal.SIGTERM)
    exited(10)
if timed_out or stop_at is not None:
    stop_group(signal.SIGKILL)     # (descendants that ignored SIGTERM, or outlived the command)
status = child.wait()
wall = time.monotonic() - start
peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
if sys.platform == "darwin":
    peak //= 1024                                      # (bytes on macOS, KB on Linux)
with open(args.out, "w", encoding="utf-8") as handle:
    handle.write(f"{wall:.2f} s {peak} KB\n")
if timed_out:
    sys.exit(124)
sys.exit(128 - status if status < 0 else status)
