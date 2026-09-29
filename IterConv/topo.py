# -*- coding: utf-8 -*-
"""拓扑与配置: 默认 VM SPEC / FRR overlay / router-id / vni / 地址分配。

VMSPEC 与 FRR_OVERLAY 是运行时可变(可由 --vm-spec / --frr-overlay 覆盖)。
本模块内用裸名读取(即本模块当前值); 其他模块必须 `import topo` 并读
`topo.VMSPEC` / `topo.FRR_OVERLAY` 活引用(勿 `from topo import VMSPEC`, 会拿旧快照)。
"""
import os

# 默认拓扑(未通过 --vm-spec / --frr-overlay 指定时使用)
VMSPEC = {
    "vm1": dict(
        img="vm1.qcow2",
        tap="tap0",
        mac="52:54:00:00:00:01",
        host_ip="192.168.0.1/30",
        vm_ip="192.168.0.2",
        qmp="/tmp/vm1.sock",
    ),
    "vm2": dict(
        img="vm2.qcow2",
        tap="tap1",
        mac="52:54:00:00:00:02",
        host_ip="192.168.0.5/30",
        vm_ip="192.168.0.6",
        qmp="/tmp/vm2.sock",
    ),
}

# 每台 VM 的 overlay 参数: netns ns-frr 内跑 zebra+bgpd, 经 veth->root-ns br0 bridge
# -> vxlan1024 隧道连对端 VM (underlay 复用现有 ens3 直连, 经 host 转发)。
FRR_OVERLAY = {
    "vm1": dict(
        underlay="192.168.0.2",
        loopback="10.0.1.1/32",
        adv_base="10.0.2",           # BGP 通告的网段基址(前三字节), 发布 <base>.1~.N
        asn=65001,
        peers=[
            dict(name="vm2", frr_ip="10.0.0.1", peer_frr="10.0.0.2", peer_asn=65002),
        ],
    ),
    "vm2": dict(
        underlay="192.168.0.6",
        loopback="10.0.1.2/32",
        adv_base="10.0.3",
        asn=65002,
        peers=[
            dict(name="vm1", frr_ip="10.0.0.2", peer_frr="10.0.0.1", peer_asn=65001),
        ],
    ),
}

NETNS_NAME = "ns-frr"
VNI_BASE = 1024   # vxlan id 基础: 每条链路由两端 router id 排序派生同值 id
SUB_MASK = 30

# 每台 VM 在 adv_base 下发布的 /32 路由条数。可用环境变量 FRR_NUM_ROUTES 覆盖。
NUM_ADVERTISE_ROUTES = int(os.environ.get("FRR_NUM_ROUTES", "3"))


def _rid(name):
    """VM 名 -> controller/agent 用的 router id(按 VMSPEC 出现顺序 1..N)。"""
    return list(VMSPEC).index(name) + 1


def _link_vni(name, peer_name):
    """同一条链路的两个端点算出同一个 vxlan id(由两端 router id 排序派生)。"""
    ra, rb = sorted((_rid(name), _rid(peer_name)))
    return VNI_BASE + ra * 100 + rb


def _peers(name):
    """返回指定 VM 的邻居列表(每项含 name/frr_ip/peer_frr/peer_asn)。

    统一读 FRR_OVERLAY[name]['peers'] 邻接表(内置默认与外部 JSON 同构)。
    归一化为固定字段, 供配置生成与脚本使用。
    """
    o = FRR_OVERLAY[name]
    return [
        dict(name=p.get("name", None),
             frr_ip=p["frr_ip"],                  # 本端 frr 地址(不带掩码)
             peer_frr=p["peer_frr"],              # 对端 frr(配在 frr<p>p 模拟)
             peer_asn=p.get("peer_asn", 0))
        for p in o["peers"]
    ]


def _auto_spec(i):
    """第 i 个(i 从 1 起)自动 VM 的 spec。
    /30 平移: 第 i 台 tap 用 192.168.0.(1+4*(i-1)), ens3 用 (2+4*(i-1));
    与 AGENTS.md 拓扑一致(vm1 .1/.2, vm2 .5/.6, vm3 .9/.10)。guest_cid: host=2, vm_i=i+2。"""
    n = i - 1
    tap_addr = 1 + 4 * n
    vm_addr = 2 + 4 * n
    return dict(
        name=f"vm{i}",
        img=os.path.join("disks", f"vm{i}.qcow2"),   # 统一放 disks/, 相对路径(VM.img_path 会再拼 HERE)
        tap=f"tap{n}",
        mac=f"52:54:00:00:00:{i:02x}",
        host_ip=f"192.168.0.{tap_addr}/{SUB_MASK}",
        vm_ip=f"192.168.0.{vm_addr}",
        qmp=f"/tmp/vm{i}.sock",
        guest_cid=i + 2,                       # 宿主恒为 cid 2
        gateway=f"192.168.0.{tap_addr}",       # 对端宿主 tap IP 作 VM 默认网关
    )