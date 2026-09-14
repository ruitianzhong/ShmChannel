#!/bin/env python3
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import copy
import argparse
from virtcontainer import QEMUTemplate, QEMUChild, QEMU_DEFAULT_CONFIG, TapManager
import time
from vm_utils import run_command
from perf_profiler import PerfProfiler


def test_qemu_basic_ops(test_config):
    template = QEMUTemplate(0, test_config["output_dir"], QEMU_DEFAULT_CONFIG)
    template.create()
    template.start()
    time.sleep(10)
    result = template.run_command_on_guest("echo hello world")
    assert result.rc == 0
    template.dump_log()
    input("Start ended\n")
    template.shutdown()
    template.dump_log()

    print("Done")


def test_qemu_start_multiple(test_config):
    num_vm = 100
    vm_list: list[QEMUTemplate] = []
    tap_manager = TapManager(num_vm, output_dir=test_config["output_dir"])
    tap_manager.init()
    base_config = QEMU_DEFAULT_CONFIG

    for idx in range(1, num_vm+1):
        modified_config = copy.deepcopy(base_config)
        mgmt_name, mgmt_host_ip, mgmt_guest_ip = tap_manager.get_tap_info(idx)

        modified_config["network_dev"] = mgmt_name
        base_disk_image_path = os.path.abspath(base_config["disk_image"])
        modified_config["disk_image"] = os.path.abspath(
            f'{test_config["output_dir"]}/vm_{idx}.qcow2')

        cmd = f'qemu-img create -f qcow2 -b {base_disk_image_path} -F qcow2 {modified_config["disk_image"]}'
        run_command(cmd)

        vm = QEMUTemplate(
            idx, test_config["output_dir"], modified_config, file_back_mem=True)
        vm.create()
        vm.start()
        vm.dump_log()
        vm_list.append(vm)

    input("All vms started")

    for vm in vm_list:
        vm.shutdown(graceful=False)

    tap_manager.cleanup()


def test_qemu_fork_ops(test_config: dict):
    template = QEMUTemplate(0, test_config["output_dir"], QEMU_DEFAULT_CONFIG)
    template.create()
    template.start()
    time.sleep(15)
    result = template.run_command_on_guest("echo hello world")
    template.copy_to_guest("./EmuFork/agent/server_qemu", "./")
    template.run_command_on_guest(
        "nohup ./server_qemu >/tmp/server.log 2>&1 &")
    template.dump_log()
    time.sleep(30)
    assert result.rc == 0
    print("Start ended")
    template.pause()
    template.snapshot()
    template.shutdown(graceful=False)
    template.dump_log()
    print("template saved")

    num_vm = 128
    tap_manager = TapManager(
        num_vm=num_vm, output_dir=test_config["output_dir"])
    # We must do it
    tap_manager.init()

    childs = []
    output_dir = test_config["output_dir"]

    parallel = test_config.get("parallel", False)

    fork_start = time.monotonic()

    if not parallel:
        for idx in range(1, num_vm+1):
            mgmt_name, mgmt_host_ip, mgmt_guest_ip = tap_manager.get_tap_info(
                idx)
            child = QEMUChild(idx, output_dir=output_dir, mgmt_name=mgmt_name,
                              guest_side_ip=mgmt_guest_ip, host_side_ip=mgmt_host_ip, template=template)
            childs.append(child)
            child.create()
            child.dump_log()
            child.start()

            child.run_command_on_guest("echo hello on forked vm")
            child.dump_log()

    else:
        futures = []
        records = []
        with ThreadPoolExecutor() as executor:
            for idx in range(1, num_vm+1):
                mgmt_name, mgmt_host_ip, mgmt_guest_ip = tap_manager.get_tap_info(
                    idx)
                child = QEMUChild(idx, output_dir=output_dir, mgmt_name=mgmt_name,
                                  guest_side_ip=mgmt_guest_ip, host_side_ip=mgmt_host_ip, template=template)
                childs.append(child)
                child.set_logging(False)
                futures.append(executor.submit(child.create_and_start))

        for future in as_completed(futures):
            result = future.result()
            records += result

        with open(f"{test_config['output_dir']}/fork.log", "w") as f:
            f.writelines(str(rec) for rec in records)

        for child in childs:
            child.set_logging(True)
            rec = child.run_command_on_guest("echo hello on forked vm")
            if rec.rc != 0:
                print(child.id(), "not ok")
            child.dump_log()
    fork_end = time.monotonic()
    print(f"fork time {fork_end-fork_start} s")

    input("child done\n")
    shutdown_start = time.monotonic()
    if not parallel:
        for child in childs:
            child: QEMUChild = child

            child.shutdown()

    else:
        futures = []
        with ThreadPoolExecutor() as executor:

            for child in childs:
                child: QEMUChild = child
                futures.append(executor.submit(
                    child.shutdown
                ))
        for future in as_completed(futures):
            future.result()

    tap_manager.cleanup()
    shutdown_end = time.monotonic()
    print(f"Shutdown time: {shutdown_end-shutdown_start} s")


def test_qemu_fork_copy_on_write_perf(test_config: dict):
    template = QEMUTemplate(0, test_config["output_dir"], QEMU_DEFAULT_CONFIG)
    template.create()
    template.start()
    time.sleep(15)
    result = template.run_command_on_guest("echo hello world")
    template.copy_to_guest("./EmuFork/agent/server_qemu", "./")
    if test_config.get("dirtier", False):
        template.copy_to_guest("./EmuFork/dirtier/dirtier", "./")
    template.run_command_on_guest(
        "nohup ./server_qemu >/tmp/server.log 2>&1 &")
    template.dump_log()
    time.sleep(30)
    assert result.rc == 0
    print("Start ended")
    template.pause()
    template.snapshot()
    template.shutdown(graceful=False)
    template.dump_log()
    print("template saved")

    num_vm = 80
    tap_manager = TapManager(
        num_vm=num_vm, output_dir=test_config["output_dir"])
    # We must do it
    tap_manager.init()

    childs = []
    output_dir = test_config["output_dir"]

    parallel = test_config.get("parallel", False)

    fork_start = time.monotonic()

    if not parallel:
        for idx in range(1, num_vm+1):
            mgmt_name, mgmt_host_ip, mgmt_guest_ip = tap_manager.get_tap_info(
                idx)
            child = QEMUChild(idx, output_dir=output_dir, mgmt_name=mgmt_name,
                              guest_side_ip=mgmt_guest_ip, host_side_ip=mgmt_host_ip, template=template)
            childs.append(child)
            child.create()
            child.dump_log()
            child.start()

            child.run_command_on_guest("echo hello on forked vm")
            child.dump_log()

    else:
        futures = []
        records = []
        with ThreadPoolExecutor() as executor:
            for idx in range(1, num_vm+1):
                mgmt_name, mgmt_host_ip, mgmt_guest_ip = tap_manager.get_tap_info(
                    idx)
                child = QEMUChild(idx, output_dir=output_dir, mgmt_name=mgmt_name,
                                  guest_side_ip=mgmt_guest_ip, host_side_ip=mgmt_host_ip, template=template)
                childs.append(child)
                child.set_logging(False)
                futures.append(executor.submit(child.create_and_start))

        for future in as_completed(futures):
            result = future.result()
            records += result

        with open(f"{test_config['output_dir']}/fork.log", "w") as f:
            f.writelines(str(rec) for rec in records)

        for child in childs:
            child.set_logging(True)
            rec = child.run_command_on_guest("echo hello on forked vm")
            if rec.rc != 0:
                print(child.id(), "not ok")
            child.dump_log()
    fork_end = time.monotonic()
    print(f"fork time {fork_end-fork_start} s")

    # fork 完成后，在子 VM 上运行 dirtier (1G)：触发写时复制
    if test_config.get("dirtier", False):
        dirtier_bytes = 1 * 1024 * 1024 * 1024  # 1G
        profiler = PerfProfiler(
            perf_data_path=f"{output_dir}/dirtier.perf.data")
        profiler.start()
        dirtier_start = time.monotonic()
        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(
                child.run_command_on_guest, f"./dirtier {dirtier_bytes}")
                for child in childs]
            for future in as_completed(futures):
                future.result()
        dirtier_end = time.monotonic()
        print(f"dirtier duration: {dirtier_end-dirtier_start} s")
        profiler.stop(block=True)
        print("perf data:", profiler.perf_data_path)
        svg = profiler.plot_flamegraph(
            flamegraph_dir="./FlameGraph",
            output_svg=f"{output_dir}/dirtier_flamegraph.svg",
            block=True,
        )
        print("dirtier flamegraph:", svg)

    input("child done\n")
    shutdown_start = time.monotonic()
    if not parallel:
        for child in childs:
            child: QEMUChild = child

            child.shutdown()
    else:
        futures = []
        with ThreadPoolExecutor() as executor:

            for child in childs:
                child: QEMUChild = child
                futures.append(executor.submit(
                    child.shutdown
                ))
        for future in as_completed(futures):
            future.result()

    tap_manager.cleanup()
    shutdown_end = time.monotonic()
    print(f"Shutdown time: {shutdown_end-shutdown_start} s")

def test_qemu_fork_suspend_wakeup_ops(test_config: dict):
    QEMU_DEFAULT_CONFIG["disk_image"] = "base_large.qcow2"
    dirtier_bytes = test_config.get("dirtier_size", 512) * 1024 * 1024
    template = QEMUTemplate(0, test_config["output_dir"], QEMU_DEFAULT_CONFIG)
    template.create()
    template.start()
    time.sleep(15)
    result = template.run_command_on_guest("echo hello world")
    template.copy_to_guest("./EmuFork/agent/server_qemu", "./")
    if test_config.get("dirtier", False):
        template.copy_to_guest("./EmuFork/dirtier/dirtier", "./")
    template.run_command_on_guest(
        "nohup ./server_qemu >/tmp/server.log 2>&1 &")

    input("waiting to adjust")
    template.dump_log()
    time.sleep(30)
    assert result.rc == 0
    print("Start ended")
    template.pause()
    template.snapshot()
    template.shutdown(graceful=False)
    template.dump_log()
    print("template saved")

    num_vm = 2
    tap_manager = TapManager(
        num_vm=num_vm, output_dir=test_config["output_dir"])
    # We must do it
    tap_manager.init()

    childs = []
    output_dir = test_config["output_dir"]

    parallel = test_config.get("parallel", False)

    fork_start = time.monotonic()

    if not parallel:
        for idx in range(1, num_vm+1):
            mgmt_name, mgmt_host_ip, mgmt_guest_ip = tap_manager.get_tap_info(
                idx)
            child = QEMUChild(idx, output_dir=output_dir, mgmt_name=mgmt_name,
                              guest_side_ip=mgmt_guest_ip, host_side_ip=mgmt_host_ip, template=template)
            childs.append(child)
            child.create()
            child.dump_log()
            child.start()

            child.run_command_on_guest("echo hello on forked vm")
            child.dump_log()

            child.copy_to_guest("./EmuFork/dirtier/busy_cpu", "./")

            # child.run_command_on_guest('nohup ./busy_cpu 4 &')

            child.run_command_on_guest('nohup ./busy_cpu 4 >/tmp/cpu.log 2>&1 &')
            if test_config.get("dirtier", False):
                child.run_command_on_guest(f"./dirtier {dirtier_bytes}")

    else:
        futures = []
        records = []
        with ThreadPoolExecutor() as executor:
            for idx in range(1, num_vm+1):
                mgmt_name, mgmt_host_ip, mgmt_guest_ip = tap_manager.get_tap_info(
                    idx)
                child = QEMUChild(idx, output_dir=output_dir, mgmt_name=mgmt_name,
                                  guest_side_ip=mgmt_guest_ip, host_side_ip=mgmt_host_ip, template=template)
                childs.append(child)
                child.set_logging(False)
                futures.append(executor.submit(child.create_and_start))

        for future in as_completed(futures):
            result = future.result()
            records += result

        with open(f"{test_config['output_dir']}/fork.log", "w") as f:
            f.writelines(str(rec) for rec in records)

        for child in childs:
            child.set_logging(True)
            child.copy_to_guest("./EmuFork/dirtier/busy_cpu", "./")

            rec = child.run_command_on_guest("echo hello on forked vm")
            print(str(rec))

            if rec.rc != 0:
                print(child.id(), "not ok")

            child.run_command_on_guest("nohup ./busy_cpu 4 &")
            if test_config.get("dirtier", False):
                child.run_command_on_guest(f"./dirtier {dirtier_bytes}")
            child.dump_log()

    fork_end = time.monotonic()
    print(f"fork time {fork_end-fork_start} s")

    input("child done\n")

    for child in childs:
        # 命令立即返回；5s 后 guest 内自动挂起（S3 suspend）
        child.run_command_on_guest(
            'nohup sh -c "sleep 5 && echo mem > /sys/power/state" >/dev/null 2>&1 &')
        # child.run_command_on_guest(
        #     'nohup sh -c "sleep 5 && echo disk > /sys/power/state" >/dev/null 2>&1 &')

    input("suspend done")

    for child in childs:
        child.wakeup()

    input("child wake up")

    for child in childs:
        rec = child.run_command_on_guest("echo wakeup")
        if rec.rc != 0:
            print(child.id(), "not ok")

        child.dump_log()

    input("check after wakeup done")

    shutdown_start = time.monotonic()
    if not parallel:
        for child in childs:
            child: QEMUChild = child

            child.shutdown()

    else:
        futures = []
        with ThreadPoolExecutor() as executor:

            for child in childs:
                child: QEMUChild = child
                futures.append(executor.submit(
                    child.shutdown
                ))
        for future in as_completed(futures):
            future.result()

    tap_manager.cleanup()
    shutdown_end = time.monotonic()
    print(f"Shutdown time: {shutdown_end-shutdown_start} s")
    


if __name__ == "__main__":
    parser = argparse.ArgumentParser("test_virtcontainer_suspend")
    parser.add_argument("--parallel", action="store_true",
                        help="start forked VMs in parallel")
    parser.add_argument("--dirtier", action="store_true",
                        help="run memory dirtier in forked guests")
    parser.add_argument("--dirtier-size", type=int, default=512,
                        help="dirtier allocation size in MiB (default: 512)")
    args = parser.parse_args()

    test_config = {"output_dir": "./test_emufork_suspend",
                   "parallel": args.parallel,
                   "dirtier": args.dirtier,
                   "dirtier_size": args.dirtier_size}
    # test_qemu_basic_ops(test_config)
    # test_qemu_fork_suspend_wakeup_ops(test_config)
    test_qemu_fork_copy_on_write_perf(test_config)

    # test_qemu_start_multiple(test_config)
