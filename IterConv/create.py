# -*- coding: utf-8 -*-
"""自动创建 VM(--create): 按 /30 拓扑分配 IP/网卡/tap, 造磁盘并启动, 经 vsock 下发配置。"""
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import topo
import vmmgr
from vmmgr import HERE, sh, HOST_SYSCTL, _setup_single_tap, VM

VM_BASE_IMG = os.path.join(HERE, "vm_base.qcow2")
DISK_DIR = os.path.join(HERE, "disks")     # 自动生成的 VM 磁盘统一在此, 便于清理
VSOCK_PORT = 12345


def _reply_all_ok(reply):
    """vsock_client 应答里所有 rc= 项均为 0 才算成功。"""
    return all(not ln.startswith("rc=") or ln[3:] == "0" for ln in reply.splitlines())


def create_vms(count, base_img=VM_BASE_IMG):
    """按 count 自动创建 VM(无需手写 vm_spec)。

    流程: 造磁盘(qcow2 继承 base_img) -> 全局转发 + 建 tap + 配 /30 IP ->
    启动(带 vsock guest-cid) -> vsock 下发 ens3 IP/默认路由 -> 等 ssh 就绪 -> echo hello。
    返回 (vm_spec_dict, {name: VM})。
    """
    if not 2 <= count <= 250:
        raise ValueError(f"count 需在 2~250, 得 {count}")
    specs = {f"vm{i}": topo._auto_spec(i) for i in range(1, count + 1)}

    print(f"== 自动创建 {count} 个 VM ==", flush=True)
    # 1) 造磁盘: 基于 base_img 的 qcow2, 统一放 disks/(已存在则跳过)
    os.makedirs(DISK_DIR, exist_ok=True)
    for s in specs.values():
        img = os.path.join(HERE, s["img"])
        if os.path.exists(img):
            print(f"    磁盘已存在: {s['img']}", flush=True)
        else:
            sh(f"qemu-img create -f qcow2 -b {base_img} -F qcow2 {img}")

    # 2) host 网络: 全局转发 + 每台建 tap + 配 host 侧 /30 IP
    for k in list(HOST_SYSCTL) + ["net.ipv4.conf.all.forwarding=1"]:
        sh(f"sysctl -w {k}")
    sh("iptables -P FORWARD ACCEPT")
    for s in specs.values():
        _setup_single_tap(s)
        sh(f"sysctl -w net.ipv4.conf.{s['tap']}.forwarding=1")
        print(f"    tap {s['tap']} = {s['host_ip']}", flush=True)

    # 3) 构建 VM 并启动(带 vsock guest-cid)
    vms = {n: VM(n, spec=specs[n]) for n in specs}
    for n, vm in vms.items():
        if not vm.is_running():
            print(f"    启动 {n} (cid={vm.spec['guest_cid']}) ...", flush=True)
            vm.start()

    # 4) vsock 并行给每台配内部 ens3 IP + 默认路由(复用 scripts/vsock_client.py)
    def configure(vm):
        cmd = [sys.executable, os.path.join(HERE, "scripts", "vsock_client.py"),
               str(vm.spec["guest_cid"]),
               "--ip", f"{vm.spec['vm_ip']}/{topo.SUB_MASK}",
               "--gw", vm.spec["gateway"],
               "-p", str(VSOCK_PORT)]
        print(f"    vsock→{vm.name}(cid={vm.spec['guest_cid']}): "
              f"{vm.spec['vm_ip']}/{topo.SUB_MASK} via {vm.spec['gateway']}", flush=True)
        for _ in range(40):                    # server 刚 boot 可能未监听, 轮询
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode == 0 and _reply_all_ok(r.stdout):
                return
            time.sleep(0.5)
        raise RuntimeError(
            f"vsock 配置 {vm.name} 失败(cid={vm.spec['guest_cid']}); 请确认 base 镜像 "
            f"已部署 vsock server 且宿主已 modprobe vhost_vsock")

    with ThreadPoolExecutor(max_workers=len(vms)) as ex:
        list(ex.map(configure, vms.values()))

    # 5) 等 ssh 就绪并 echo hello 验证
    for n in vms:
        vms[n].wait_boot()
    for n, vm in vms.items():
        r = vm.exec("echo hello")
        print(f"    {n} @ {vm.spec['vm_ip']}: {r.stdout.strip()}", flush=True)

    return specs, vms