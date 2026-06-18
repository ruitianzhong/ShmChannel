#!/usr/bin/env python3
"""Show top N processes by anonymous memory usage inside a container (viewed from host).

Usage:
    sudo python3 container_anon_mem_top.py <container_name_or_id> [-n TOP_N]

Examples:
    sudo python3 container_anon_mem_top.py my_container
    sudo python3 container_anon_mem_top.py my_container -n 20

Requires root to read /proc/<pid>/smaps.
"""

import argparse
import re
import subprocess
import sys


def get_container_pids(container: str) -> list[str]:
    result = subprocess.run(
        ["docker", "top", container, "-eo", "pid"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"Error: docker top failed: {result.stderr.strip()}", file=sys.stderr)
        sys.exit(1)
    pids = result.stdout.strip().split("\n")[1:]
    return [p.strip() for p in pids if p.strip()]


def get_proc_name(pid: str) -> str:
    try:
        with open(f"/proc/{pid}/cmdline", "r") as f:
            cmdline = f.read().replace("\x00", " ").strip()
        if cmdline:
            return cmdline
    except (FileNotFoundError, PermissionError):
        pass
    try:
        with open(f"/proc/{pid}/comm", "r") as f:
            return f.read().strip()
    except (FileNotFoundError, PermissionError):
        return f"(pid {pid})"


def get_anon_mem_mib(pid: str) -> float:
    """Return anonymous memory in MiB. Try smaps_rollup first (fast), fall back to smaps."""
    # Try smaps_rollup (Linux 4.14+)
    try:
        with open(f"/proc/{pid}/smaps_rollup", "r") as f:
            for line in f:
                if line.startswith("Anonymous:"):
                    return int(line.split()[1]) / 1024.0
    except (FileNotFoundError, PermissionError):
        pass

    # Fallback: parse full smaps
    try:
        with open(f"/proc/{pid}/smaps", "r") as f:
            content = f.read()
    except (FileNotFoundError, PermissionError):
        return 0.0
    anon_kb = sum(int(m.group(1)) for m in re.finditer(r"^Anonymous:\s+(\d+)\s+kB", content, re.MULTILINE))
    return anon_kb / 1024.0


def main():
    parser = argparse.ArgumentParser(description="Top N processes by anonymous memory in a container")
    parser.add_argument("container", help="Docker container name or ID")
    parser.add_argument("-n", "--top", type=int, default=10, help="Number of top processes to show (default: 10)")
    args = parser.parse_args()

    pids = get_container_pids(args.container)
    if not pids:
        print("No processes found.")
        return

    procs = []
    for pid in pids:
        anon = get_anon_mem_mib(pid)
        if anon > 0:
            procs.append((pid, get_proc_name(pid), anon))

    procs.sort(key=lambda x: x[2], reverse=True)

    print(f"{'Rank':<6}{'PID':<10}{'Process':<48}{'Anon (MiB)':>12}")
    print("-" * 76)
    for i, (pid, name, mem) in enumerate(procs[:args.top], 1):
        # Truncate long cmdline for display
        display_name = (name[:45] + "...") if len(name) > 48 else name
        print(f"{i:<6}{pid:<10}{display_name:<48}{mem:>10.2f}")


if __name__ == "__main__":
    main()
