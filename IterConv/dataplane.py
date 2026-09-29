# -*- coding: utf-8 -*-
"""veth-only 定制数据面: C++ agent(VM 内) + controller(host) 的编排与验证。
经独立于 veth 的 TCP 控制通道中继 BGP 报文。
"""
import json
import os
import socket
import subprocess
import time

import topo
import vmmgr
from vmmgr import sh, HERE, _write_json  # noqa: F401 (HERE/_write_json 也直接经 vmmgr.)

DP_CONTROL_PORT = 9000
CTL_SOCKET = "/tmp/controller.ctl"   # controller unix 命令服务路径(供 iter/offline/online/quiescent)
AGENT_BIN = os.path.join(HERE, "bin", "agent")
CONTROLLER_BIN = os.path.join(HERE, "bin", "controller")


def build_dataplane():
    """用 CMake 在 host 编译 agent 与 controller 到 bin/。"""
    print("    编译 agent / controller (cmake) ...", flush=True)
    build_dir = os.path.join(HERE, "build")
    sh(f"cmake -S {HERE} -B {build_dir} -DCMAKE_BUILD_TYPE=Release", check=True)
    sh(f"cmake --build {build_dir}", check=True)
    print("    agent / controller 编译完成", flush=True)


def gen_agent_json(name):
    """生成单台 VM 的 agent.json(dict)。

    veths = 每邻居一条: fake_ip = 对端 frr IP(配在 frr<i>p), frr_ip = 本端源。
    peer_router_id 每 veth 携带该链路上"对端 router id"; agent 据此按链路判
    低/高侧(不再用全局单值)。顶层 peer_router_id 保留为兼容旧字段(取首邻居)。
    """
    host_ip = topo.VMSPEC[name]["host_ip"].split("/")[0]
    veths = [
        {
            "veth_name": f"frr{i}p",
            "fake_ip": p["peer_frr"],            # 模拟对端 FRR 的 IP(配在 frr<i>p)
            "frr_ip": p["frr_ip"],               # 本端 ns-frr 源 IP
            "peer_router_id": topo._rid(p["name"]) if p["name"] else 0,
        }
        for i, p in enumerate(topo._peers(name))
    ]
    return {
        "controller_ip": host_ip,
        "control_port": DP_CONTROL_PORT,
        "router_id": topo._rid(name),
        "peer_router_id": veths[0]["peer_router_id"] if veths else 0,
        "veths": veths,
    }


def gen_controller_json(admin_online=None):
    """生成 controller.json(dict)。dial_ip = host 到该 VM 的局端 tap IP。

    admin_online: 启动即期望在线的 router id 列表(partition 的 always_online)。
    不在该列表的 router 启动时默认离线(不主动拨号、收其流量只缓存), 供 iter 轮换。
    多邻居 vm 的 frr_ip 输出为数组(controller 为同一 Router 登记多个 frr ip);
    links 由拓扑全部邻居去重展开(支持多链路)。
    """
    routers, links, edge_seen = [], [], set()
    for name, spec in topo.VMSPEC.items():
        this_rid = topo._rid(name)
        ips = [p["frr_ip"] for p in topo._peers(name)]
        for p in topo._peers(name):
            other_rid = topo._rid(p["name"]) if p["name"] else 0
            key = tuple(sorted((this_rid, other_rid)))
            if other_rid and key not in edge_seen:
                edge_seen.add(key)
                links.append({"ip_a": p["frr_ip"], "ip_b": p["peer_frr"]})
        routers.append({
            "id": this_rid,
            "name": name,
            "vm_ip": spec["vm_ip"],
            "dial_ip": spec["host_ip"].split("/")[0],
            # 单 frr_ip 输出字符串, 多则数组(Router 即可登记多个本端地址)
            "frr_ip": ips[0] if len(ips) == 1 else ips,
        })
    listen_ip = topo.VMSPEC["vm1"]["host_ip"].split("/")[0]
    return {"listen_ip": listen_ip, "control_port": DP_CONTROL_PORT,
            "ctl_socket": CTL_SOCKET,
            "admin_default_online": admin_online or [],   # 空=全部启动在线(兼容旧行为)
            "routers": routers, "links": links}


class ControllerCtl:
    """controller 的 unix 命令服务客户端(一条命令一个连接, 阻塞式应答)。

    对应 controller.cpp 的 CtlService 协议: 发一行 JSON 命令, controller 处理完回一行 JSON。
    """
    def __init__(self, path, timeout=3.0):
        self.path = path
        self.timeout = timeout

    def _cmd(self, obj, timeout=None):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout or self.timeout)
        try:
            s.connect(self.path)
        except OSError as e:
            return {"ok": False, "reason": f"connect: {e}"}
        s.sendall((json.dumps(obj) + "\n").encode())
        buf = b""
        while b"\n" not in buf:
            try:
                r = s.recv(65536)
            except socket.timeout:
                s.close()
                return {"ok": False, "reason": "timeout"}
            if not r:
                break
            buf += r
        s.close()
        try:
            return json.loads(buf.split(b"\n")[0])
        except Exception:
            return {"ok": False, "reason": "bad_reply", "raw": buf.decode(errors="replace")[:200]}

    def ping(self):
        return self._cmd({"cmd": "ping"})

    def offline(self, rid, timeout_ms=8000):
        return self._cmd({"cmd": "offline", "router": int(rid),
                          "timeout_ms": timeout_ms}, timeout=timeout_ms / 1000 + 2)

    def online(self, rid, timeout_ms=8000):
        return self._cmd({"cmd": "online", "router": int(rid),
                          "timeout_ms": timeout_ms}, timeout=timeout_ms / 1000 + 2)

    def quiescent(self, ms=20000):
        return self._cmd({"cmd": "quiescent", "ms": int(ms)}, timeout=ms / 1000 + 5)


def deploy_agent(vm, cfg):
    """scp agent 二进制 + json 到 VM, 后台启动。"""
    vm.exec("pkill -x agent 2>/dev/null; true", check=False)
    vm.put(AGENT_BIN, "/root/agent")
    local = os.path.join(HERE, f".{vm.name}-agent.json.tmp")
    _write_json(cfg, local)
    vm.put(local, "/root/agent.json")
    os.remove(local)
    # 分步执行: chmod, 再用 nohup 后台启动(不留 /dev/null)
    vm.exec("chmod +x /root/agent", check=False)
    vm.exec("nohup /root/agent --config /root/agent.json "
            ">/root/agent.log 2>&1 &", check=False)
    print(f"    {vm.name} agent 已启动 (log: /root/agent.log)", flush=True)


def start_controller(cfg):
    """在 host 后台启动 controller(当前用户,不 sudo)。"""
    sh("pkill -x controller 2>/dev/null || true")
    conf_path = os.path.join(HERE, "controller.json")
    _write_json(cfg, conf_path)
    log = open(os.path.join(HERE, "controller.out"), "w")
    subprocess.Popen([CONTROLLER_BIN, "--config", conf_path],
                     stdout=log, stderr=log, start_new_session=True)
    print(f"    controller 已启动 (log: controller.out, conf: {conf_path})",
          flush=True)


def stop_dataplane(vms):
    for vm in vms:
        vm.exec("pkill -x agent 2>/dev/null; true", check=False)
    sh("pkill -x controller 2>/dev/null || true")
    print("    已停止 agent/controller", flush=True)


def verify_veth_bgp(vm, verbose=True, wait=12):
    """Phase1 验证: 经定制数据面, FRR 学到对端路由(不做 peer ping, 假 IP 在 root 会本地回)。"""
    peers, up, pfxs = 0, 0, 0
    for _ in range(wait):
        r = vm.exec(f"ip netns exec {topo.NETNS_NAME} vtysh -c 'show bgp summary'",
                    check=False)
        peers, up, pfxs = _parse_bgp_summary(r.stdout.decode(errors="replace"))
        if up >= 1:
            break
        time.sleep(1)
    if verbose:
        print(f"      [BGP 邻居] {vm.name}: {up}/{peers} 个邻居 UP "
              f"(共收到 {pfxs} 条前缀) [经定制数据面]", flush=True)

    r = vm.exec(f"ip netns exec {topo.NETNS_NAME} vtysh -c 'show ip bgp'", check=False)
    bgp_out = r.stdout.decode(errors="replace")
    # 对端 ASN: 统一从 peers 取; 多邻居时任一匹配即可
    peer_asns = {str(p["peer_asn"]) for p in topo._peers(vm.name)}
    learned = [ln.strip() for ln in bgp_out.splitlines()
               if "/32" in ln and any(asn in ln for asn in peer_asns)]
    if verbose:
        print(f"      [BGP 表] {vm.name}: 从对端学到 {len(learned)} 条路由",
              flush=True)
        for ln in learned:
            print("        " + ln, flush=True)
    return up


def _parse_bgp_summary(text):
    """解析 `show bgp summary` 输出, 返回 (邻居数, 建立数, 总前缀数)。

    邻居行格式:
        Neighbor  V  AS  MsgRcvd  MsgSent  TblVer  InQ  OutQ  Up/Down  State/PfxRcd  PfxSnt  Desc
        ip        n  n   n       n       n      n    n    hh:mm:ss  {Established|N}  M       NA
    按列: Up/Down(索引8), State/PfxRcd(索引9)。State/PfxRcd 会话建立后为
    Established 或已收到的前缀数(N); 未建立为 Idle/Active/Connect/OpenSent 等文字。
    """
    peers = 0
    up = 0
    pfxs = 0
    for ln in text.splitlines():
        cols = ln.split()
        if len(cols) >= 10 and cols[0].count(".") == 3:
            peers += 1
            state = cols[9]                    # State/PfxRcd 列
            if state == "Established" or state.isdigit():
                up += 1
                if state.isdigit():
                    pfxs += int(state)
    return peers, up, pfxs