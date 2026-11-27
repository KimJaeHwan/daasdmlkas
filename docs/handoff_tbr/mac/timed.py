"""Portable time / peak-RSS wrapper (macOS has no GNU /usr/bin/time -f).

usage: python3 timed.py <label> <log file> -- <command ...>
prints: TIME <label> <seconds> s <peak KB> KB      (exit status of the command is kept)
"""
import resource
import subprocess
import sys
import time

label, log = sys.argv[1], sys.argv[2]
command = sys.argv[sys.argv.index("--") + 1:]
start = time.perf_counter()
with open(log, "wb") as out:
    status = subprocess.call(command, stdout=out, stderr=subprocess.STDOUT)
seconds = time.perf_counter() - start
peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
peak_kb = peak // 1024 if sys.platform == "darwin" else peak     # (bytes on macOS, KB on Linux)
print(f"TIME {label} {seconds:.2f} s {peak_kb} KB", flush=True)
sys.exit(status)
