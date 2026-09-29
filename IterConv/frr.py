# -*- coding: utf-8 -*-
"""FRR overlay / veth-only 建网: 配置生成(host 侧) -> scp 上传 -> 远端建网脚本 -> 部署/验证。"""
import os
import time

import topo
import vmmgr
from vmmgr import HERE
from dataplane import _parse_bgp_summary  # noqa: F401 (frr 验证复用 BGP summary 解析)


def _frr_conf(name, num_routes=None):
    """生成指定 VM 的 FRR 配置文件内容(在 host 侧), 返回 {文件名: 内容} dict。

    num_routes: 在 adv_base 网段下发布的 /32 路由条数, 默认 NUM_ADVERTISE_ROUTES。
    """
    o = topo.FRR_OVERLAY[name]
    num = num_routes or topo.NUM_ADVERTISE_ROUTES
    peers = topo._peers(name)
    adv_addrs = [f"{o['adv_base']}.{i}" for i in range(1, num + 1)]
    net_lines = "\n".join(f"  network {a}/32" for a in adv_addrs)
    neigh_lines = "".join(
        f" neighbor {p['peer_frr']} remote-as {p['peer_asn']}\n" for p in peers)
    af_lines = "".join(
        f"  neighbor {p['peer_frr']} activate\n"
        f"  neighbor {p['peer_frr']} next-hop-self\n" for p in peers)
    zebra = (
        "hostname " + name + "-frr\n"
        "log stdout\n")
    bgpd = (
        f"hostname {name}-frr\n"
        "log stdout\n"
        f"router bgp {o['asn']}\n"
        " no bgp ebgp-requires-policy\n"
        f"{neigh_lines}"
        " address-family ipv4 unicast\n"
        f"{af_lines}"
        f"{net_lines}\n"
        " exit-address-family\n")
    return {"zebra.conf": zebra, "bgpd.conf": bgpd}


def _frr_start_daemons(name):
    """返回在 netns 内启动 zebra+bgpd 的脚本片段(配置文件已由 host 上传到 /etc/frr)。

    FRR 路由加载: 配置文件由 _frr_conf 生成, 本片段只负责把两个 daemon 在
    netns 里拉起来。注意 -d 后台化进程会继承 ssh 的 stdin/stdout, 导致 ssh
    连接不关闭而挂起, 必须重定向 </dev/null >/dev/null 2>&1 让远端命令立即返回。
    """
    return f"""\
# 启动 zebra + bgpd (配置文件已由 host 上传到 /etc/frr)
sudo ip netns exec {topo.NETNS_NAME} /usr/lib/frr/zebra -d -f /etc/frr/zebra.conf </dev/null >/dev/null 2>&1
sudo ip netns exec {topo.NETNS_NAME} /usr/lib/frr/bgpd  -d -f /etc/frr/bgpd.conf </dev/null >/dev/null 2>&1
sleep 2
echo "setup done on {name}"
"""


def _frr_overlay_setup_script(name, num_routes=None):
    """返回在指定 VM 内建网 netns/VXLAN 的一段远端 shell 脚本。

    FRR 配置文件由 setup_frr_overlay 先从 host 上传到 /etc/frr/,
    本脚本不再写配置, 只负责网络建网 + 在 lo 上添加广告网段的 /32 + 启动 zebra/bgpd。

    num_routes: 在 adv_base 网段下发布的 /32 路由条数, 供 lo 地址使用。
    """
    o = topo.FRR_OVERLAY[name]
    num = num_routes or topo.NUM_ADVERTISE_ROUTES
    peers = topo._peers(name)
    # adv 网段若与 loopback 同址(发布地址含 loopback)会重复 add 触发 File exists:
    # zebra 已从 lo 读到 loopback, 这里只需 add 其余 adv 地址
    lb_ip = o["loopback"].split("/")[0]
    adv_addrs = [f"{o['adv_base']}.{i}" for i in range(1, num + 1)]
    lo_addrs = "\n".join(
        f"sudo ip -n {topo.NETNS_NAME} addr add {a}/32 dev lo"
        for a in adv_addrs if a != lb_ip)
    # 每邻居一条 veth pair: frr<i> 进 netns(本端), frr<i>p 留 root ns 待挂桥
    veth_lines = "".join(
        f"sudo ip link del frr{i}p 2>/dev/null || true\n"
        f"sudo ip link del frr{i} 2>/dev/null || true\n"
        f"sudo ip link add frr{i} type veth peer name frr{i}p\n"
        f"sudo ip link set frr{i} netns {topo.NETNS_NAME}\n"
        f"sudo ip -n {topo.NETNS_NAME} addr add {p['frr_ip']}/30 dev frr{i}\n"
        f"sudo ip -n {topo.NETNS_NAME} link set frr{i} up\n"
        f"sudo ip link set frr{i}p up\n"
        for i, p in enumerate(peers))
    # 清残留桥/隧道: 旧名 vxlan1024(历史命名) + 本 VM 各 vx<i>(按邻居数动态)。
    # 前一跑异常退出常把这些留 root 层, 叠加挂同一 br0 会干扰桥学习/ARP。
    vx_cleanup = ("sudo ip link del vxlan1024 2>/dev/null || true\n" +
                  "".join(f"sudo ip link del vx{i} 2>/dev/null || true\n"
                          for i in range(len(peers))) +
                  "sudo ip link del br0 2>/dev/null || true\n")
    # 每邻居: frr<i>p 挂桥 + 建 vxlan 单播隧道连其 underlay, 并入桥
    link_lines = "".join(
        f"sudo ip link set frr{i}p master br0\n"
        f"sudo ip link del vx{i} 2>/dev/null || true\n"
        f"sudo ip link add vx{i} type vxlan id {topo._link_vni(name, p['name'])} \\\n"
        f"    remote {topo.VMSPEC[p['name']]['vm_ip']} local {o['underlay']} dstport 4789 dev ens3\n"
        f"sudo ip link set vx{i} master br0\n"
        f"sudo ip link set vx{i} up\n"
        for i, p in enumerate(peers))
    return f"""\
set -eux
# 0) 停用 root-ns 默认 frr + 彻底杀掉 netns 内 FRR 进程 + 清 stale pid
sudo systemctl stop frr 2>/dev/null || true
sudo systemctl disable frr 2>/dev/null || true
sudo pkill -9 -f '/usr/lib/frr/zebra' 2>/dev/null || true
sudo pkill -9 -f '/usr/lib/frr/bgpd'  2>/dev/null || true
if sudo ip netns exec {topo.NETNS_NAME} true 2>/dev/null; then
  sudo ip netns exec {topo.NETNS_NAME} pkill -9 -f zebra 2>/dev/null || true
  sudo ip netns exec {topo.NETNS_NAME} pkill -9 -f bgpd  2>/dev/null || true
fi
sudo rm -f /var/run/frr/*.pid 2>/dev/null || true
sleep 1

# 1) netns + loopback (广告网段的 /32 由 zebra 从 lo 上读取)
sudo ip netns pids {topo.NETNS_NAME} 2>/dev/null | while read p; do sudo kill -9 "$p" 2>/dev/null || true; done
for _nd in 1 2 3; do sudo ip netns del {topo.NETNS_NAME} 2>/dev/null && break; sleep 1; done
sudo ip netns add {topo.NETNS_NAME}
sudo ip -n {topo.NETNS_NAME} link set lo up
sudo ip -n {topo.NETNS_NAME} addr add {o['loopback']} dev lo
{lo_addrs}
sudo ip -n {topo.NETNS_NAME} link set lo up

# 2) veth: 每邻居一条 frr<i> 进 netns, frr<i>p 留 root ns 挂桥
{f"{veth_lines}"}

# 3) bridge (root ns): 先清残留桥/隧道再建干净 br0(避免叠加干扰桥学习/ARP)
{vx_cleanup}sudo ip link add br0 type bridge 2>/dev/null || true
sudo ip link set br0 up

# 4) 每邻居: frr<i>p 挂桥 + 建 vxlan 单播隧道到对端 underlay, 并入桥
{link_lines}
{_frr_start_daemons(name)}
"""


def _frr_veth_setup_script(name, num_routes=None):
    """返回 veth-only 建网脚本: 只建 netns + veth(不建 bridge/vxlan)。

    供"只建链路、不做连通性检查"的模式使用。FRR 路由加载复用
    _frr_conf(配置文件)与 _frr_start_daemons(daemon 启动)。
    num_routes: 透传给 _frr_conf 控制通告条数; 本脚本只用于给 lo 配 /32。
    """
    o = topo.FRR_OVERLAY[name]
    num = num_routes or topo.NUM_ADVERTISE_ROUTES
    peers = topo._peers(name)
    # adv 网段若与 loopback 同址(发布地址含 loopback)会重复 add 触发 File exists:
    # zebra 已从 lo 读到 loopback, 这里只需 add 其余 adv 地址
    lb_ip = o["loopback"].split("/")[0]
    adv_addrs = [f"{o['adv_base']}.{i}" for i in range(1, num + 1)]
    lo_addrs = "\n".join(
        f"sudo ip -n {topo.NETNS_NAME} addr add {a}/32 dev lo"
        for a in adv_addrs if a != lb_ip)
    # 每邻居一条 veth pair: frr<i> 进 netns(本端), frr<i>p 留 root(模拟对端)
    veth_lines = "".join(
        f"sudo ip link del frr{i}p 2>/dev/null || true\n"
        f"sudo ip link del frr{i} 2>/dev/null || true\n"
        f"sudo ip link add frr{i} type veth peer name frr{i}p\n"
        f"sudo ip link set frr{i} netns {topo.NETNS_NAME}\n"
        f"sudo ip -n {topo.NETNS_NAME} addr add {p['frr_ip']}/30 dev frr{i}\n"
        f"sudo ip -n {topo.NETNS_NAME} link set frr{i} up\n"
        f"sudo ip addr add {p['peer_frr']}/30 dev frr{i}p\n"
        f"sudo ip link set frr{i}p up\n"
        for i, p in enumerate(peers))
    # 清残留桥/隧道: 旧名 vxlan1024 + 本 VM 各 vx<i>(可能从 overlay 切换而来)
    vx_cleanup = ("sudo ip link del vxlan1024 2>/dev/null || true\n" +
                  "".join(f"sudo ip link del vx{i} 2>/dev/null || true\n"
                          for i in range(len(peers))) +
                  "sudo ip link del br0 2>/dev/null || true\n")
    return f"""\
set -eux
# 0) 停用 root-ns 默认 frr + 彻底杀掉 netns 内 FRR 进程 + 清 stale pid
sudo systemctl stop frr 2>/dev/null || true
sudo systemctl disable frr 2>/dev/null || true
sudo pkill -9 -f '/usr/lib/frr/zebra' 2>/dev/null || true
sudo pkill -9 -f '/usr/lib/frr/bgpd'  2>/dev/null || true
if sudo ip netns exec {topo.NETNS_NAME} true 2>/dev/null; then
  sudo ip netns exec {topo.NETNS_NAME} pkill -9 -f zebra 2>/dev/null || true
  sudo ip netns exec {topo.NETNS_NAME} pkill -9 -f bgpd  2>/dev/null || true
fi
sudo rm -f /var/run/frr/*.pid 2>/dev/null || true
sleep 1

# 1) netns + loopback (广告网段的 /32 由 zebra 从 lo 上读取)
sudo ip netns pids {topo.NETNS_NAME} 2>/dev/null | while read p; do sudo kill -9 "$p" 2>/dev/null || true; done
for _nd in 1 2 3; do sudo ip netns del {topo.NETNS_NAME} 2>/dev/null && break; sleep 1; done
sudo ip netns add {topo.NETNS_NAME}
sudo ip -n {topo.NETNS_NAME} link set lo up
sudo ip -n {topo.NETNS_NAME} addr add {o['loopback']} dev lo
{lo_addrs}
sudo ip -n {topo.NETNS_NAME} link set lo up

# 2) 每邻居一条 veth pair: frr<i> 进 netns(本端 frr), frr<i>p 留 root(配模拟对端假 IP)
{veth_lines}
# 清可能残留的 overlay 桥/隧道(veth-only 不需要)
{vx_cleanup}
{_frr_start_daemons(name)}
"""


def _upload_frr_conf_and_run(vm, script, n):
    """host 侧生成 FRR 配置 -> scp 到 VM /etc/frr/ -> 跑建网脚本 -> 清临时文件。

    被 setup_frr_overlay / setup_frr_veth_only 复用(Frr 路由加载的上传执行)。
    """
    confs = _frr_conf(vm.name, num_routes=n)
    tmp_files = {}
    for fname, content in confs.items():
        tmp = os.path.join(HERE, f".{vm.name}-{fname}.tmp")
        with open(tmp, "w") as f:
            f.write(content)
        tmp_files[fname] = tmp
    try:
        for fname, tmp in tmp_files.items():
            vm.put(tmp, f"/etc/frr/{fname}")
        r = vm.run_script(script)
        print(r.stdout, flush=True)
    finally:
        for tmp in tmp_files.values():
            os.remove(tmp)


def setup_frr_overlay(vm, num_routes=None):
    """在给定 VM 上建网 netns+FRR+VXLAN overlay(完整模式, 含桥和隧道)。

    num_routes: 每台 VM 发布的 /32 路由条数, 默认 NUM_ADVERTISE_ROUTES。
    """
    n = num_routes or topo.NUM_ADVERTISE_ROUTES
    print(f"    配置 {vm.name} overlay (netns/VXLAN/FRR), 发布 {n} 条 /32 ...",
          flush=True)
    _upload_frr_conf_and_run(
        vm, _frr_overlay_setup_script(vm.name, num_routes=n), n)
    print(f"    {vm.name} overlay 建网完成", flush=True)


def setup_frr_veth_only(vm, num_routes=None):
    """新模式: 只建 netns + veth + FRR(无 bridge/vxlan), frr0p 上配模拟对端假 IP。

    复用 _frr_conf 的路由加载配置与 _frr_start_daemons 的启动脚本。
    假 IP = 对端 frr_ip(同 /30 直连), 供 agent 在此:179 终结 FRR 的 BGP 连接。
    num_routes: 每台 VM 发布的 /32 路由条数, 默认 NUM_ADVERTISE_ROUTES。
    """
    n = num_routes or topo.NUM_ADVERTISE_ROUTES
    print(f"    配置 {vm.name} veth-only (netns+veth+假IP, 无 bridge/vxlan), "
          f"发布 {n} 条 /32 ...", flush=True)
    _upload_frr_conf_and_run(
        vm, _frr_veth_setup_script(vm.name, num_routes=n), n)
    print(f"    {vm.name} veth-only 建网完成", flush=True)


def verify_frr_overlay(vm, verbose=True, wait=8):
    """验证指定 VM 的 overlay/BGP 状态。返回活跃 BGP 邻居数。"""
    peers, up, pfxs = 0, 0, 0
    # 等 eBGP 收敛(存在至少一个 UP 邻居即认为收敛)
    for _ in range(wait):
        r = vm.exec(
            f"ip netns exec {topo.NETNS_NAME} vtysh -c 'show bgp summary'",
            check=False)
        sum_out = r.stdout.decode(errors="replace")
        peers, up, pfxs = _parse_bgp_summary(sum_out)
        if up >= 1:
            break
        time.sleep(1)

    if verbose:
        print(f"      [BGP 邻居] {vm.name}: "
              f"{up}/{peers} 个邻居 UP (共收到 {pfxs} 条前缀)", flush=True)

    # BGP 路由表: 找出 PR 端发布、本端学到的路由条目(行内含 "/32" 且对端AS路径)
    r = vm.exec(f"ip netns exec {topo.NETNS_NAME} vtysh -c 'show ip bgp'",
                check=False)
    bgp_out = r.stdout.decode(errors="replace")
    # 学到的路由: 任一邻居(peer)AS 路径上的 /32 即视为从对端学到
    known_asn = {p["peer_asn"] for p in topo._peers(vm.name) if p["peer_asn"]}
    learned = [ln.strip() for ln in bgp_out.splitlines()
               if "/32" in ln and any(str(a) in ln for a in known_asn)]
    if verbose:
        print(f"      [BGP 表] {vm.name}: 从对端学到 "
              f"{len(learned)} 条路由", flush=True)
        for ln in learned:
            print("        " + ln, flush=True)

    # 隧道可达性(任一邻居隧道通即算通)
    ping_ok = False
    for p in topo._peers(vm.name):
        if not p["peer_frr"]:
            continue
        r = vm.exec(f"ip netns exec {topo.NETNS_NAME} ping -c 2 -W 2 "
                    f"{p['peer_frr']}", check=False)
        if "0% packet loss" in r.stdout.decode(errors="replace"):
            ping_ok = True
            break
    if verbose:
        print(f"      [{vm.name}] 隧道 ping 对端 frr: "
              f"{'OK' if ping_ok else 'FAIL'}", flush=True)
    return up