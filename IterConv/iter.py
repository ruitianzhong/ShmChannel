# -*- coding: utf-8 -*-
"""iter(partition) 驱动: 常在线节点 + 轮换上线集合的冻结/恢复。"""
import time

import topo
from vmmgr import setup_host_network, VM
from dataplane import (build_dataplane, gen_agent_json, gen_controller_json,
                       ControllerCtl, CTL_SOCKET, deploy_agent, start_controller,
                       stop_dataplane, verify_veth_bgp)
from frr import setup_frr_veth_only


def run_iter(part, rounds=1, step=False, shutdown=False):
    """iter(partition) 驱动: 让"常在线 + 轮换上线集合"按序冻结/恢复。

    每段: resume 该集合 -> controller.quiescent(全局无 BGP UPDATE quiescent_ms) ->
    controller.offline(优雅排空) -> VM.pause。常在线节点全程保持。
    惰性上线: 初始仅启动常在线节点; 每个轮换集合接到其 slot 时才冷启动
    (未启动过, 含数据面部署, 并至少等 first_boot_wait_ms)或 resume(已启动过)。
    step: 为 True 时, 每次节点上线(resume)前与下线(offline/pause)前都 input
    等用户按 Enter 再继续, 便于人工观察每步状态。
    shutdown: 完成后默认等按 Enter 再关闭 VM + controller(与普通模式一致);
              为 True 时不等输入, 立即关闭。
    """
    def step_wait(msg):
        if not step:
            return
        # 打印此刻活跃(分区计划里 controller 视为在线)的节点(id + ip)供人工参考。
        # 惰性模型下初始仅常在线节点, 而非所有已启动的 VM(frr 就绪但尚未上线的不算)。
        online = sorted(active)
        info = ", ".join(f"{n}(id{topo._rid(n)}, {vms[n].spec['vm_ip']})" for n in online)
        print(f"    当前在线节点: {info or '(无)'}", flush=True)
        try:
            input(f"    按 Enter {msg} ...")
        except EOFError:
            pass  # 非交互 stdin 时直接继续

    qms = int(part.get("quiescent_ms", 20000))
    fbw = int(part.get("first_boot_wait_ms", 30000))
    always = list(part.get("always_online", []))
    sets = part.get("sets", [])
    for s in sets:
        if not isinstance(s, list):
            raise ValueError(f"partition 的 sets 每项须为列表, 遇 {s!r}")
    all_need = set(always) | {n for s in sets for n in s}
    for n in all_need:
        if n not in topo.VMSPEC:
            raise ValueError(f"partition 引用 {n!r}, 不在 VMSPEC: {list(topo.VMSPEC)}")

    print("== iter: 配置 host 网络 (tap + 转发) ==", flush=True)
    setup_host_network()
    build_dataplane()               # host 编译 agent/controller 一次; 各 VM 数据面惰性部署时复用

    vms = {n: VM(n) for n in all_need}
    # 惰性上线: 初始只 start/resume 常在线(all_need 里 sets 节点先不动),
    # 每个轮换集合轮到其 slot 时才冷启动(未启动过)或 resume(已启动)并配数据面。
    booted = set()                  # 本次会话已启动(含数据面部署)的节点

    def ensure_up(n):
        if n in booted:
            vms[n].resume()         # 已建好数据面, 只需恢复
            return False
        vm = vms[n]
        cold = False
        if vm.is_running():
            vm.resume()             # 唤醒可能遗留的暂停态
        else:
            print(f"    [iter] 启动 {n} ...", flush=True)
            vm.start()
            cold = True
        vm.wait_boot()              # 仅等 ssh 就绪(后续数据面操作依赖)
        print(f"    [iter] 配置 {n} 数据面 (frr netns+veth) + 部署 agent ...", flush=True)
        setup_frr_veth_only(vm, num_routes=None)
        deploy_agent(vm, gen_agent_json(n))
        booted.add(n)
        return cold

    # 1) 惰性: 仅先上线常在线节点; 轮换集合由下方 slot 的 ensure_up 按需启动
    #    首启收敛等待放在本批次上线循环之后, 而非单个 ensure_up 内。
    fresh = []
    for n in sorted(always):
        if ensure_up(n):
            fresh.append(n)
    if fresh:
        print(f"    [iter] 首次冷启动 {fresh}, 等 {fbw/1000:.0f}s 收敛", flush=True)
        time.sleep(fbw / 1000)

    # 2) 启动 controller, 仅常在线节点默认为在线(admin_online); 其余 lazy 上线
    admin_online = [topo._rid(n) for n in always]
    start_controller(gen_controller_json(admin_online))
    ctl = ControllerCtl(CTL_SOCKET)
    # controller 刚 Popen, ctl 服务需 bind/listen 后才可连; 轮询重试避免
    # 启动竞态造成的瞬时 Connection refused(上次残留的僵尸 socket 亦会被冲掉)。
    r = None
    for _ in range(30):
        r = ctl.ping()
        if r.get("ok"):
            break
        time.sleep(0.5)
    if not r or not r.get("ok"):
        print(f"    [iter] 连 controller ctl 失败: {r}", flush=True)
        return
    print(f"    [iter] controller ctl 就绪, 常在线 {always} (ids={admin_online})", flush=True)

    # active = 当前 controller 视为在线(分区计划里活跃)的节点, 初始仅常在线。
    # 初始仅常在线、彼此间常无邻居, 无 BGP 可收敛, 故不做无谓的全局首轮 quiescent;
    # 每个集合上线后的 quiescent 会吸收该集合与常在线间的收敛。
    active = set(always)
    for rnd in range(1, rounds + 1):
        print(f"== iter round {rnd}/{rounds} ==", flush=True)
        for s in sets:
            print(f"  -- 上线集合 {s} --", flush=True)
            step_wait(f"上线节点 {s}: vms resume")
            fresh = []
            for n in s:
                if ensure_up(n):     # 惰性: 首次则冷启动+配数据面, 否则 resume
                    fresh.append(n)
                # 关键: 控制器视为离线的节点须先 online(标回在线 + 重拨 agent),
                # 否则它对端一上报 UP 就被 controller 当作"对端离线"而 CLOSE 掉。
                rid = topo._rid(n)
                rr = ctl.online(rid)
                print(f"    controller online {n}(id{rid}): {rr}", flush=True)
                active.add(n)
            # 首启收敛等待: 对本集合冷启动的节点统一等 fbw, 再进入静默判定
            if fresh:
                print(f"    [iter] 首次冷启动 {fresh}, 等 {fbw/1000:.0f}s 收敛", flush=True)
                time.sleep(fbw / 1000)
            qr = ctl.quiescent(qms)     # 阻塞: 全局 quiescent_ms 无 BGP UPDATE
            print(f"    quiescent({qms}ms): {qr}", flush=True)
            step_wait(f"下线节点 {s}: controller offline + VM.pause")
            for n in s:
                rid = topo._rid(n)
                rr = ctl.offline(rid)
                print(f"    controller offline {n}(id{rid}): {rr}", flush=True)
                vms[n].pause()      # 优雅排空确认后冻结 VM(即使超时也推进)
                active.discard(n)
            # 段结束后: 对仍在线节点验证 BGP(对端离线时保活/会话不误拆)
            for n in sorted(active):
                print(f"  [verify] 在线节点 {n} BGP 会话:", flush=True)
                verify_veth_bgp(vms[n], verbose=True)
    print("== iter 完成, 常在线节点保持在线 ==", flush=True)

    # 完成后与普通模式一致: 默认等按 Enter 再关闭, --shutdown 则立即关
    if not shutdown:
        still = sorted(active)
        info = ", ".join(f"{n}(id{topo._rid(n)}, {vms[n].spec['vm_ip']})" for n in still)
        print(f"\niter 完成, 仍在运行的节点: {info or '(无)'}", flush=True)
        try:
            input("按 Enter 关闭全部 VM 与 controller ...")
        except EOFError:
            pass  # 非交互 stdin 时直接继续
    ordered = sorted(all_need)
    for n in ordered:
        vms[n].resume()          # 冻结的 VM 先恢复, 使 ssh(agent pkill) 可通
    stop_dataplane([vms[n] for n in ordered])
    for n in ordered:
        vms[n].stop()