#!/usr/bin/env python3
import json
import os
import sys
import time
import subprocess
import struct
from typing import Dict, List

PAGE_SIZE = 4096
PAGEMAP_ENTRY_SIZE = 8
SOFTDIRTY_BIT = 1 << 55


def check_root():
    if os.geteuid() != 0:
        print("Error: This script requires root privileges to run!", file=sys.stderr)
        sys.exit(1)


def clear_softdirty(pid: int):
    clear_refs_path = f"/proc/{pid}/clear_refs"
    if not os.path.exists(clear_refs_path):
        print(f"Error: Process {pid} does not exist", file=sys.stderr)
        return

    try:
        with open(clear_refs_path, "w") as f:
            f.write("4")
    except Exception as e:
        print(
            f"Failed to clear softdirty flags for pid {pid}: {e}", file=sys.stderr)
        return


def parse_pmap(pid: int) -> tuple[List[Dict], int]:
    try:
        result = subprocess.check_output(
            ["pmap", "-x", str(pid)],
            text=True,
            stderr=subprocess.STDOUT
        )
    except subprocess.CalledProcessError as e:
        print(f"Failed to execute pmap -x {pid}: {e.output}", file=sys.stderr)
        return None, None

    memory_regions = []
    total_rss_kb = 0
    lines = result.strip().split("\n")

    for line in lines[2:]:
        line = line.strip()
        if not line:
            continue

        if "total" in line:
            total_parts = line.split()
            if len(total_parts) >= 4:
                try:
                    total_rss_kb = int(total_parts[3])
                except ValueError:
                    print(
                        "Warning: Failed to parse total RSS from pmap output", file=sys.stderr)
            continue

        parts = line.split()
        if len(parts) < 6:
            continue

        start_addr = int(parts[0], 16)
        addr_len_kb = int(parts[1])
        end_addr = start_addr + addr_len_kb * 1024
        page_count = (end_addr - start_addr) // PAGE_SIZE

        try:
            region_rss_kb = int(parts[2])
            region_dirty_kb = int(parts[3])
            region_rss_pages = region_rss_kb // (PAGE_SIZE // 1024)
            region_dirty_pages = region_dirty_kb // (PAGE_SIZE // 1024)
        except ValueError:
            region_rss_kb = 0
            region_rss_pages = 0
            region_dirty_pages = 0

        region = {
            "start_addr": start_addr,
            "end_addr": end_addr,
            "page_count": page_count,
            "permissions": parts[4],
            "mapping": parts[-1] if len(parts) == 6 else parts[-2],
            "rss_kb": region_rss_kb,
            "rss_pages": region_rss_pages,
            "region_dirty_kb": region_dirty_kb,
            "dirty_pages": region_dirty_pages
        }
        memory_regions.append(region)

    return memory_regions, total_rss_kb


def calculate_total_pss(pid_list: list[int]) -> float:
    if not os.path.exists("/proc"):
        raise OSError(
            "This function only works on Linux (requires /proc filesystem)")

    total_pss_kb = 0.0

    for pid in pid_list:
        try:
            pid_int = int(pid)
            smaps_path = f"/proc/{pid_int}/smaps"

            if not os.path.exists(smaps_path):
                print(f"[WARNING] PID {pid_int}: smaps file not found")
                continue

            with open(smaps_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("Pss:"):
                        total_pss_kb += float(line.split()[1])

        except ValueError:
            print(f"[WARNING] '{pid}' is not a valid PID")
            continue
        except PermissionError:
            raise PermissionError(
                "[ERROR] No permission to read smaps (run with sudo)")
        except Exception as e:
            print(f"[WARNING] PID {pid}: Failed to parse PSS - {str(e)}")
            continue

    total_pss_mb = round(total_pss_kb / 1024, 2)
    return total_pss_mb if total_pss_mb > 0 else None


def calculate_total_uss(pid_list: List[int]) -> float:
    if not os.path.exists("/proc"):
        raise OSError(
            "This function only works on Linux (requires /proc filesystem)")

    total_uss_kb = 0.0

    for pid in pid_list:
        try:
            pid_int = int(pid)
            smaps_path = f"/proc/{pid_int}/smaps"

            if not os.path.exists(smaps_path):
                print(f"[WARNING] PID {pid_int}: smaps file not found")
                continue

            with open(smaps_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("Private_Clean:"):
                        total_uss_kb += float(line.split()[1])
                    elif line.startswith("Private_Dirty:"):
                        total_uss_kb += float(line.split()[1])
                    elif line.startswith("Private_Hugetlb:"):
                        total_uss_kb += float(line.split()[1])

        except ValueError:
            print(f"[WARNING] '{pid}' is not a valid PID")
            continue
        except PermissionError:
            raise PermissionError(
                "[ERROR] No permission to read smaps (run with sudo)")
        except Exception as e:
            print(f"[WARNING] PID {pid}: Failed to parse USS - {str(e)}")
            continue

    total_uss_mb = round(total_uss_kb / 1024, 2)
    return total_uss_mb if total_uss_mb > 0 else None


def count_softdirty_pages(pid: int, regions: List[Dict], pfn_set: set, overall_stat: dict) -> List[Dict]:
    pagemap_path = f"/proc/{pid}/pagemap"
    if not os.path.exists(pagemap_path):
        print(f"Error: {pagemap_path} is inaccessible", file=sys.stderr)
        sys.exit(1)

    for region in regions:
        region["softdirty_count"] = 0

    try:
        with open(pagemap_path, "rb") as f:
            for region in regions:
                start_addr = region["start_addr"]
                end_addr = region["end_addr"]

                start_page_idx = start_addr // PAGE_SIZE
                end_page_idx = end_addr // PAGE_SIZE

                f.seek(start_page_idx * PAGEMAP_ENTRY_SIZE)

                for page_idx in range(start_page_idx, end_page_idx):
                    entry_data = f.read(PAGEMAP_ENTRY_SIZE)
                    if len(entry_data) != PAGEMAP_ENTRY_SIZE:
                        break

                    entry = struct.unpack("<Q", entry_data)[0]
                    present = (entry >> 63) & 1
                    pfn = entry & ((1 << 55) - 1)

                    if present == 1 and (pfn != 0) and (pfn not in pfn_set) and (entry & SOFTDIRTY_BIT):
                        pfn_set.add(pfn)
                        overall_stat["dedup_softdirty"] += 1

                    if (entry & SOFTDIRTY_BIT) and present == 1 and pfn != 0:
                        region["softdirty_count"] += 1

    except Exception as e:
        print(f"Failed to read pagemap: {e}", file=sys.stderr)
        sys.exit(1)
    return regions


def get_process_name(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/comm", "r") as f:
            return f.read().strip()
    except (FileNotFoundError, IOError):
        return "unknown"


def get_process_pss(pid: int) -> float:
    try:
        smaps_path = f"/proc/{pid}/smaps"
        if not os.path.exists(smaps_path):
            return 0.0

        total_pss_kb = 0.0
        with open(smaps_path, "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("Pss:"):
                    total_pss_kb += float(line.split()[1])

        return round(total_pss_kb / 1024, 2)
    except Exception:
        return 0.0


def get_process_uss(pid: int) -> float:
    try:
        smaps_path = f"/proc/{pid}/smaps"
        if not os.path.exists(smaps_path):
            return 0.0

        total_uss_kb = 0.0
        with open(smaps_path, "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("Private_Clean:"):
                    total_uss_kb += float(line.split()[1])
                elif line.startswith("Private_Dirty:"):
                    total_uss_kb += float(line.split()[1])
                elif line.startswith("Private_Hugetlb:"):
                    total_uss_kb += float(line.split()[1])

        return round(total_uss_kb / 1024, 2)
    except Exception:
        return 0.0


def get_container_pids(container_name: str) -> List[int]:
    result = subprocess.run(
        ['docker', 'top', container_name],
        capture_output=True,
        text=True,
        check=True
    )

    lines = result.stdout.strip().split('\n')
    pids = []

    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 2:
            pids.append(int(parts[1]))
    print("get container pids=", pids)
    return sorted(pids)


class DockerContainerDirtyProfiler:
    def __init__(self, container_name: str, result_dir: str):
        check_root()
        self.container_name = container_name
        self.result_dir = result_dir
        self.pids = get_container_pids(container_name)
        print(
            f"Container '{container_name}' PIDs: {self.pids}", file=sys.stderr)

    def collect_memory_info(self) -> tuple[int, float, float]:
        total_rss_kb = 0
        total_pss_mb = calculate_total_pss(self.pids)
        total_uss_mb = calculate_total_uss(self.pids)

        for pid in self.pids:
            regions, rss_kb = parse_pmap(pid)
            if regions is None:
                continue

            for region in regions:
                total_rss_kb += region["rss_kb"]

        total_rss_mb = round(total_rss_kb / 1024, 2)
        print(
            f"Total RSS: {total_rss_mb} MB, Total PSS: {total_pss_mb} MB, Total USS: {total_uss_mb} MB", file=sys.stderr)
        return total_rss_mb, total_pss_mb, total_uss_mb

    def clear_softdirty(self):
        self.pids = get_container_pids(self.container_name)
        for pid in self.pids:
            clear_softdirty(pid)
        print(
            f"Cleared softdirty flags for {len(self.pids)} processes", file=sys.stderr)

    def get_top_k_memory_processes(self, k: int) -> tuple[List[tuple], List[tuple]]:
        uss_processes = []
        pss_processes = []

        for pid in self.pids:
            process = {
                'pid': pid,
                'name': get_process_name(pid),
                'uss': get_process_uss(pid),
                'pss': get_process_pss(pid)
            }
            uss_processes.append(process)
            pss_processes.append(process)

        uss_sorted = sorted(
            uss_processes, key=lambda x: x['uss'], reverse=True)[:k]
        pss_sorted = sorted(
            pss_processes, key=lambda x: x['pss'], reverse=True)[:k]

        uss_result = [(p['pid'], p['name'], p['uss']) for p in uss_sorted]
        pss_result = [(p['pid'], p['name'], p['pss']) for p in pss_sorted]

        return uss_result, pss_result

    def collect_dirty_pages(self) -> tuple[int, int, int]:
        pfn_set = set()
        result = {"dedup_softdirty": 0}
        total_pg_cnt = 0
        total_dirty = 0
        total_anon_dirty = 0
        result_lists = []

        for pid in self.pids:
            regions, total_rss_kb = parse_pmap(pid)
            if regions is None:
                print(f"pid {pid} is None", file=sys.stderr)
                continue

            result_lists.append(regions)
            regions = count_softdirty_pages(pid, regions, pfn_set, result)

            for region in regions:
                mapping = region["mapping"]
                is_anonymous = mapping == "anon" or "[stack]" in mapping

                if "w" in region["permissions"]:
                    total_pg_cnt += region["rss_pages"]
                    total_dirty += region["softdirty_count"]
                    if is_anonymous:
                        total_anon_dirty += region["softdirty_count"]

        print(f"Total writable pages: {total_pg_cnt}, Total dirty pages: {total_dirty}, "
              f"Total anonymous dirty pages: {total_anon_dirty}, Dedup dirty: {result['dedup_softdirty']}",
              file=sys.stderr)

        return total_pg_cnt, total_dirty, total_anon_dirty


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser("docker_container_dirty_profiler")
    parser.add_argument("--container_name", required=True)
    parser.add_argument("--result_dir", required=True)
    parser.add_argument(
        "--action", choices=["collect", "clear", "stat", "top_k"], required=True)
    parser.add_argument("--k", type=int, default=5,
                        help="Number of top processes to show")

    args = parser.parse_args()

    profiler = DockerContainerDirtyProfiler(
        args.container_name, args.result_dir)

    if args.action == "collect":
        rss_mb, pss_mb, uss_mb = profiler.collect_memory_info()
        print(f"RSS: {rss_mb} MB, PSS: {pss_mb} MB, USS: {uss_mb} MB")
    elif args.action == "clear":
        profiler.clear_softdirty()
    elif args.action == "stat":
        total_pg_cnt, total_dirty, total_anon_dirty = profiler.collect_dirty_pages()
        print(
            f"Writable pages: {total_pg_cnt}, Dirty pages: {total_dirty}, Anonymous dirty pages: {total_anon_dirty}")
    elif args.action == "top_k":
        uss_top, pss_top = profiler.get_top_k_memory_processes(args.k)
        print(f"Top {args.k} processes by USS:")
        for pid, name, uss in uss_top:
            print(f"  PID {pid} ({name}): {uss} MB")
        print(f"\nTop {args.k} processes by PSS:")
        for pid, name, pss in pss_top:
            print(f"  PID {pid} ({name}): {pss} MB")
