# -*- coding: utf-8 -*-
"""vm.py 入口: 解析命令行并编排各模块(host 网络 / VM / FRR / 数据面 / iter / create)。

模块划分见同级: topo(拓扑配置) vmmgr(基础设施) frr(FRR 建网) dataplane(定制数据面)
create(自动建 VM) iter(冻结/恢复)。
"""
import argparse
import os
import time

import topo
import vmmgr
from vmmgr import _load_json, setup_host_network, VM
from frr import setup_frr_overlay, setup_frr_veth_only, verify_frr_overlay
from dataplane import (build_dataplane, gen_agent_json, gen_controller_json,
                       deploy_agent, start_controller, stop_dataplane,
                       verify_veth_bgp)
from create import create_vms
from iter import run_iter


def main():
    """配置 host 网络, 启动 VMSPEC 指定的 VM, 相互 ping 并打印输出。
    topo.VMSPEC / topo.FRR_OVERLAY 为可变默认, 由 --vm-spec / --frr-overlay 覆盖。"""
    ap = argparse.ArgumentParser(description="QEMU VM 控制器: 网络->启动->ping->上传->overlay")
    ap.add_argument("--shutdown", action="store_true",
                    help="流程结束立即关闭所有 VM; 不加则等待按回车后再关闭")
    ap.add_argument("--num-routes", type=int, default=None,
                    help="每台 VM 发布的 /32 路由条数(默认取 FRR_NUM_ROUTES 或 NUM_ADVERTISE_ROUTES)")
    ap.add_argument("--veth-only", action="store_true",
                    help="只建 netns+veth(不建 bridge/vxlan、不做检查); 默认是完整 overlay")
    grp = ap.add_mutually_exclusive_group()
    grp.add_argument("--vm-spec", metavar="JSON", default=None,
                     help="VM 规格配置文件路径; 与 --create 互斥")
    grp.add_argument("--create", action="store_true",
                     help="按 --frr-overlay 规定的数量自动创建 VM(无需 vm_spec), 作为 FRR router")
    ap.add_argument("--frr-overlay", metavar="JSON", default=None,
                    help="FRR overlay 配置文件路径; 不指定则用内置默认")
    ap.add_argument("--iter-config", metavar="JSON", default=None,
                    help="partition 配置文件(常在线 + 轮换集合), 走 iter 冻结/恢复模式")
    ap.add_argument("--iter-rounds", type=int, default=1,
                    help="iter 模式轮换轮数(默认 1)")
    ap.add_argument("--iter-step", action="store_true",
                    help="iter 模式: 每次节点上下线前等用户按 Enter 再继续")
    args = ap.parse_args()
    if args.frr_overlay:
        topo.FRR_OVERLAY = _load_json(args.frr_overlay)
        print(f"FRR_OVERLAY 从 {args.frr_overlay} 加载", flush=True)
    if args.vm_spec:
        # 共享加载: iter/create/普通三种模式都能经 --vm-spec 覆盖 VMSPEC
        topo.VMSPEC = _load_json(args.vm_spec)
        print(f"VMSPEC 从 {args.vm_spec} 加载", flush=True)
    if args.iter_config:
        part = _load_json(args.iter_config)
        print(f"== iter 模式 (partition: {args.iter_config}) ==", flush=True)
        run_iter(part, rounds=args.iter_rounds, step=args.iter_step,
             shutdown=args.shutdown)
        return
    if args.create:
        # 自动建 len(FRR_OVERLAY) 个 VM 并作为 FRR router; 拓扑/邻居由 --frr-overlay 指定
        count = len(topo.FRR_OVERLAY)
        specs, created = create_vms(count)
        topo.VMSPEC = specs
        vms = list(created.values())
        print(f"[--create] 按 --frr-overlay 建 {count} 个 VM 作为 FRR router", flush=True)
        # 创建完成后互 ping(与普通流程 3/5 一致)
        if len(vms) >= 2:
            print("== 相互 ping ==", flush=True)
            src, dst = vms[0], vms[1]
            for s, d in ((src, dst), (dst, src)):
                title = f"--- {s.name}({s.spec['vm_ip']}) -> {d.name}({d.spec['vm_ip']}) ---"
                print(title, flush=True)
                r = s.exec(f"ping -c 3 -W 2 {d.spec['vm_ip']}", check=False)
                print(r.stdout.decode(errors="replace"), flush=True)
    else:
        print("== 1/5 配置 host 网络 (tap + IP + 转发) ==")
        setup_host_network()

        print(f"== 2/5 启动并等待 {len(topo.VMSPEC)} 个 VM 就绪 ==")
        vms = [VM(n) for n in topo.VMSPEC]
        for vm in vms:
            if not vm.is_running():
                print(f"    启动 {vm.name} ...")
                vm.start()
            vm.wait_boot()
            print(f"    {vm.name} 就绪 @ {vm.spec['vm_ip']}")

        print("== 3/5 相互 ping ==")
        src, dst = vms[0], vms[1]
        ping = "ping -c 3 -W 2"
        for s, d in ((src, dst), (dst, src)):
            title = f"--- {s.name}({s.spec['vm_ip']}) -> {d.name}({d.spec['vm_ip']}) ---"
            print(title, flush=True)
            r = s.exec(f"{ping} {d.spec['vm_ip']}", check=False)
            print(r.stdout.decode(errors="replace"), flush=True)

        print("== 4/5 上传文件测试 (空文件) ==")
        local_empty = os.path.join(vmmgr.HERE, ".empty_test")
        open(local_empty, "w").close()  # 创建空文件
        remote_path = f"/root/{src.name}.empty"
        src.put(local_empty, remote_path)
        r = src.exec(f"ls -l {remote_path} && wc -c < {remote_path}", check=False)
        print(r.stdout.decode(errors="replace"), flush=True)
        os.remove(local_empty)

    if args.veth_only:
        print("== 5/5 veth-only 定制数据面 (agent/controller 中继 BGP, 无 bridge/vxlan) ==")
        for vm in vms:
            setup_frr_veth_only(vm, num_routes=args.num_routes)
        build_dataplane()
        for vm in vms:
            deploy_agent(vm, gen_agent_json(vm.name))
        start_controller(gen_controller_json())
        print("    等待 BGP 经定制数据面收敛 (控制通道 + 179 终结 + 报文中继) ...")
        time.sleep(30)
        for vm in vms:
            verify_veth_bgp(vm, verbose=True)
    else:
        print("== 5/5 VXLAN + FRR overlay (netns 内跑 bgpd) ==")
        for vm in vms:
            setup_frr_overlay(vm, num_routes=args.num_routes)
        print("    等 BGP 收敛 5s 后再验证 ...")
        time.sleep(20)
        for vm in vms:
            verify_frr_overlay(vm, verbose=True)

    # 是否立即关机由 --shutdown 决定; 否则等用户按 Enter 后同样关闭
    if not args.shutdown:
        print(f"\n实验完成, {len(vms)} 个 VM 当前运行中 "
              f"(" + ", ".join(f"{vm.name}={vm.spec['vm_ip']}" for vm in vms) + ")。")
        try:
            input(f"按 Enter 关闭全部 {len(vms)} 个 VM ...")
        except EOFError:
            pass  # 非交互 stdin 提前结束时也继续走关机
    if args.veth_only:
        stop_dataplane(vms)
    for vm in vms:
        vm.stop()  # verbose 默认 True, 会打印实际退出方式


if __name__ == "__main__":
    main()