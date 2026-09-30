#!/usr/bin/env python3
"""拓扑配置自动生成器。

两阶段设计, 关注点分离:
  Phase 1 - 拓扑生成: 每种拓扑(topo 构建器)产出统一 Topology dict,
            每个节点带 `name` + `role` 两个属性(role 用于后续分区区分)。
  Phase 2 - 统一分区接口: `partition(topo, ...)` 只按 topo.nodes[].role 划分,
            与拓扑形状(line/fattree)无关, 输出 partition.json;
            `_frr_overlay(topo)` 另由 节点序 + 边 生成隧道地址(与分区无关)。

VM 规格不再需要: VM 由 vm.py `--create` 按 `len(frr_overlay)` 自动创建(经 vsock 配 ens3),
故本工具只产出 frr_overlay.json + partition.json 两份。

Topology dict:
  {
    "type": "line|fattree",
    "nodes": [ {"name": "vm1", "role": "middle"}, ... ],
    "edges": [ (node_idx_a, node_idx_b), ... ],
    "roles": ["middle","head",...],       # 该拓扑出现的真实节点角色(不含保留字 any)
    "default_partition": {"always_roles": [...], "rotate_roles": [...]},
  }
保留角色 "any" = 全部节点(仅供 partition/--show-roles 用, 节点不真的带此角色)。

支持拓扑:
  - line      线性: vm1-vm2-...-vmN
  - fattree   经典 k-ary fat-tree(Al-Fares): 三层 core/aggregation/edge 均为路由器,
              k 个 pod(k 为偶数)。不含服务端主机(主机不是 FRR router)。
              core=(k/2)², agg=edge=k²/2, 总=5k²/4, 链路=k³/2。

用法:
  python3 config/gen_config.py line    -n N [--out DIR] [--always-role ..] [--rotate-role ..]
  python3 config/gen_config.py fattree -k K [--out DIR] [--always-role ..] [--rotate-role ..]
  python3 config/gen_config.py line -n 6 --show-roles
  跑:
  python3 vm.py --create --frr-overlay <out>/frr_overlay.json [--iter-config <out>/partition.json]

生成时自动调用 scripts/vis_topology.py 把拓扑图存为 <out>/topo.html(每分区一色,
可使用 --no-vis 关闭; topo.html 已 gitignore)。

地址/编号(生成器内部, 与 topo._auto_spec 的 /30 分配一致):
  - frr 链路: 每链路一个 /30, 10.3.<link>.0/30, 两端 .1/.2。
  - loopback/adv_base: 每节点 10.4.<node>.1/32, adv_base="10.4.<node>"。
  - ASN: 每节点 65000 + 节点序。
  - underlay: 192.168.0.<2+4N>(= --create 的 ens3 IP)。
"""
import argparse
import json
import os
import subprocess
import sys

FRR_SEG = 3      # frr 链路网段高两字节 10.<FRR_SEG>.<link>
LB_SEG = 4       # loopback/adv 网段高两字节 10.<LB_SEG>.<node>
ASN_BASE = 65000
HOST_BASE = 1    # underlay 起始: 192.168.0.<1+4idx+1>/30(步进 4)


# ---------------------------------------------------------------- Phase 1: 拓扑生成
def _line(n):
    """线性拓扑: 中心节点 role=middle, 首尾 head/tail, 其余 internal。"""
    mid = (n - 1) // 2
    nodes = []
    for i in range(n):
        if i == mid:
            role = "middle"
        elif i == 0:
            role = "head"
        elif i == n - 1:
            role = "tail"
        else:
            role = "internal"
        nodes.append({"name": f"vm{i + 1}", "role": role})
    edges = [(i, i + 1) for i in range(n - 1)]
    return {
        "type": "line", "nodes": nodes, "edges": edges,
        "roles": ["middle", "head", "tail", "internal"],
        # 默认: 中心常在线, 其余逐台轮换
        "default_partition": {"always_roles": ["middle"], "rotate_roles": ["any"]},
    }


def _fattree_k(k):
    """经典 k-ary fat-tree(Al-Fares), k 为偶数。

    三层(core/aggregation/edge)均为路由器, 不含服务端主机。
    规模: core=(k/2)², aggregation=edge=k·(k/2), 总=5k²/4, 链路=k³/2。
    节点属性:
      - core 节点 role = "core"。
      - aggregation / edge 节点 按所属 pod 标记 role = "pod1".."podk"(第 p+1 个 pod)。
    连通: 每 pod 内 edge 与 aggregation 全互连; aggregation(p,a) 连 各 core 组
    core(g,a)(即某个 core 与每个 pod 的"第 a 个 aggregation"相连)。
    默认分区: core 常在线; 每个 pod(其 agg+edge)为一组轮换在线。
    """
    if k % 2 != 0 or k < 2:
        raise ValueError(f"fattree k 需为偶数且 >= 2, 得 {k}")
    h = k // 2
    core_cnt = h * h
    off_core, off_agg = 0, core_cnt
    off_edge = core_cnt + k * h

    def node_name(i):
        return f"vm{i + 1}"

    def idx_edge(p, e): return off_edge + p * h + e
    def idx_agg(p, a):  return off_agg + p * h + a
    def idx_core(g, c): return off_core + g * h + c

    nodes = [{"name": node_name(i), "role": "core"} for i in range(core_cnt)]
    for p in range(k):                       # aggregation: 按 pod 标记
        for a in range(h):
            nodes.append({"name": node_name(idx_agg(p, a)), "role": f"pod{p + 1}"})
    for p in range(k):                       # edge: 按 pod 标记
        for e in range(h):
            nodes.append({"name": node_name(idx_edge(p, e)), "role": f"pod{p + 1}"})

    edges = []
    for p in range(k):                       # 每 pod: edge <-> aggregation 全互连
        for e in range(h):
            for a in range(h):
                edges.append((idx_edge(p, e), idx_agg(p, a)))
    for p in range(k):                       # aggregation(p,a) 连 core(g,a) 各 g
        for a in range(h):
            for g in range(h):
                edges.append((idx_agg(p, a), idx_core(g, a)))

    pod_roles = [f"pod{p + 1}" for p in range(k)]
    return {
        "type": "fattree", "nodes": nodes, "edges": edges,
        "roles": ["core"] + pod_roles,
        # 默认: core 常在线, 每个 pod 一整组轮换在线
        "default_partition": {"always_roles": ["core"], "rotate_roles": pod_roles},
    }


BUILDERS = {"line": _line, "fattree": _fattree_k}


# ---------------------------------------------------------------- Phase 2: 统一分区接口
def _expand_role(topo, node_names_by_role, role):
    """role -> 节点名列表; 保留字 "any" = 全部节点。"""
    if role == "any":
        return [nd["name"] for nd in topo["nodes"]]
    return node_names_by_role.get(role, [])


def partition(topo, always_roles=None, rotate_roles=None):
    """统一分区接口: 只按 topo.nodes[].role 划分, 与拓扑形状无关。

    always_roles: 常在线角色(各角色节点并集); 缺省用 topo 默认。
    rotate_roles: 轮换角色; 组角色 = 整组一个集合, 保留字 "any" = 组内逐台各一集合;
                  已在 always 的节点不进入轮换。
    返回 partition.json(dict): {"quiescent_ms","first_boot_wait_ms","always_online","sets"}。
    """
    by_role = {}
    for nd in topo["nodes"]:
        by_role.setdefault(nd["role"], []).append(nd["name"])

    defaults = topo.get("default_partition", {})
    ar = list(always_roles) if always_roles else list(defaults.get("always_roles", []))
    rr = list(rotate_roles) if rotate_roles else list(defaults.get("rotate_roles", []))

    always = sorted({i for r in ar for i in _expand_role(topo, by_role, r)})
    always_set = set(always)
    sets = []
    for r in rr:
        cand = [x for x in _expand_role(topo, by_role, r) if x not in always_set]
        if not cand:
            continue
        if r == "any":
            sets.extend([[x] for x in cand])          # 逐台各一集合
        else:
            sets.append(sorted(cand))                 # 整组一起轮换
    return {"quiescent_ms": 20000, "first_boot_wait_ms": 30000,
            "always_online": always, "sets": sets}


# ---------------------------------------------------------------- 隧道地址生成(frr_overlay)
def _host_underlay(idx):
    """第 idx 台(0 基)的 vm ens3 IP(作 underlay): 每台占一个 /30。"""
    return f"192.168.0.{HOST_BASE + 4 * idx + 1}"


def _alloc_frr_ip(link_idx, side):
    """链路 link_idx 的 /30 网段地址: side 0 -> .1, side 1 -> .2。"""
    return f"10.{FRR_SEG}.{link_idx}.{1 + side}"


def _frr_overlay(topo):
    """由 节点序 + 边 生成 frr_overlay.json(dict), 与分区无关。"""
    nodes = topo["nodes"]
    n = len(nodes)
    asn = {i: ASN_BASE + i for i in range(n)}
    # 每条链路分配独立 /30; 按节点序去重定向, side0=较小序节点
    link_map = {}               # (lo,hi) -> (link_idx, ip_lo, ip_hi)
    link_idx = 0
    for a, b in topo["edges"]:
        lo, hi = min(a, b), max(a, b)
        if (lo, hi) not in link_map:
            link_map[(lo, hi)] = (link_idx, _alloc_frr_ip(link_idx, 0),
                                  _alloc_frr_ip(link_idx, 1))
            link_idx += 1
    peers = {i: [] for i in range(n)}
    for (a, b), (_, ip_a, ip_b) in link_map.items():
        peers[a].append(dict(name=nodes[b]["name"], frr_ip=ip_a,
                             peer_frr=ip_b, peer_asn=asn[b]))
        peers[b].append(dict(name=nodes[a]["name"], frr_ip=ip_b,
                             peer_frr=ip_a, peer_asn=asn[a]))
    overlay = {}
    for i, nd in enumerate(nodes):
        overlay[nd["name"]] = dict(
            underlay=_host_underlay(i),
            loopback=f"10.{LB_SEG}.{i}.1/32",
            adv_base=f"10.{LB_SEG}.{i}",
            asn=asn[i],
            peers=sorted(peers[i], key=lambda p: p["name"]),
        )
    return overlay


# ---------------------------------------------------------------- 输出与 CLI
def _write(out_dir, frr_overlay, partition_json):
    os.makedirs(out_dir, exist_ok=True)
    for fname, obj in (("frr_overlay.json", frr_overlay),
                       ("partition.json", partition_json)):
        with open(os.path.join(out_dir, fname), "w") as f:
            json.dump(obj, f, indent=2)
            f.write("\n")


def _render_vis(out_dir, sig, title=None):
    """生成完配置后自动调 scripts/vis_topology.py, 把图存到同一目录 topo.html。"""
    script = os.path.normpath(os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "vis_topology.py"))
    if not os.path.exists(script):
        print(f"[gen] 未找到 {script}, 跳过可视化")
        return
    html = os.path.join(out_dir, "topo.html")
    r = subprocess.run(
        [sys.executable, script,
         "--frr-overlay", os.path.join(out_dir, "frr_overlay.json"),
         "--partition", os.path.join(out_dir, "partition.json"),
         "--out", html, "--title", title or f"{sig}"],
        capture_output=True, text=True)
    if r.returncode == 0:
        print(f"[gen] 可视化 -> {html}")
    else:
        print(f"[gen] 可视化失败:\n{r.stdout}\n{r.stderr}")


def _parse_roles(s):
    return [x.strip() for x in s.split(",") if x.strip()]


def main():
    ap = argparse.ArgumentParser(description="生成 frr_overlay/partition(供 vm.py --create)")
    ap.add_argument("topo", choices=sorted(BUILDERS))
    ap.add_argument("--out", default=None, help="输出目录(默认 config/<拓扑名>)")
    ap.add_argument("-n", type=int, default=3, help="line 节点数")
    ap.add_argument("-k", type=int, default=4, help="fattree k(须为偶数); k 个 pod")
    ap.add_argument("--always-role", default=None, help="常在线角色(逗号分隔), 默认用拓扑默认")
    ap.add_argument("--rotate-role", default=None, help="轮换角色(逗号分隔), 默认用拓扑默认")
    ap.add_argument("--show-roles", action="store_true", help="打印该拓扑的节点-角色后退出")
    ap.add_argument("--no-vis", action="store_true",
                    help="不自动调用 vis_topology 生成 topo.html")
    args = ap.parse_args()

    if args.topo == "line":
        if args.n < 2:
            ap.error("line -n 至少 2")
        topo = _line(args.n)
        sig = f"line_{args.n}"
    else:
        if args.k < 2 or args.k % 2 != 0:
            ap.error("fattree -k 需为 >= 2 的偶数")
        topo = _fattree_k(args.k)
        sig = f"fattree_k{args.k}"

    if args.show_roles:
        by_role = {}
        for nd in topo["nodes"]:
            by_role.setdefault(nd["role"], []).append(nd["name"])
        print(f"[roles] {sig}: 节点-角色(any=全部节点, 分区保留字):")
        for r in topo["roles"]:
            print(f"  {r:<10}: {by_role.get(r, [])}")
        print(f"  {'any':<10}: {[nd['name'] for nd in topo['nodes']]}")
        return

    always_roles = _parse_roles(args.always_role) if args.always_role else None
    rotate_roles = _parse_roles(args.rotate_role) if args.rotate_role else None
    partition_json = partition(topo, always_roles, rotate_roles)
    frr_overlay = _frr_overlay(topo)

    out_dir = args.out or os.path.join(os.path.dirname(os.path.abspath(__file__)), sig)
    _write(out_dir, frr_overlay, partition_json)
    if not args.no_vis:
        _render_vis(out_dir, sig)

    p = partition_json
    ar = always_roles or topo["default_partition"]["always_roles"]
    rr = rotate_roles or topo["default_partition"]["rotate_roles"]
    n_peers = [len(v["peers"]) for v in frr_overlay.values()]
    print(f"[gen] 拓扑 {sig}: {len(topo['nodes'])} 节点 / {len(topo['edges'])} 链路")
    print(f"[gen] 邻居数范围: {min(n_peers)}..{max(n_peers)}")
    print(f"[gen] 分区 roles: always={ar}  rotate={rr}")
    print(f"[gen] 分区: 常在线 {len(p['always_online'])} 台 · {len(p['sets'])} 组轮换"
          f"({[len(s) for s in p['sets']]} 台/组)")
    print(f"[gen] 写入 -> {out_dir}: frr_overlay/partition.json")
    print(f"[gen] 运行: python3 vm.py --create "
          f"--frr-overlay {os.path.join(out_dir, 'frr_overlay.json')} "
          f"[--iter-config {os.path.join(out_dir, 'partition.json')}]")


if __name__ == "__main__":
    main()