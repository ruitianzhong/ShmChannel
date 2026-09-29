# VXLAN + FRR overlay 手工验证手册

背景：两个 VM（vm1、vm2）内各建 `ns-frr` netns，跑 zebra+bgpd，经 veth → root-ns `br0` bridge → `vxlan1024` 隧道互连，跑 eBGP 并通告 N 条 `/32` 路由。

```
  [netns ns-frr]      zebra + bgpd          frr0 = 10.0.0.x/30
        | veth
  [root ns]           br0 (bridge) ── vxlan1024 ──VXLAN隧道──> 对端 VM
        |
      ens3 = 192.168.0.x/30   ← host 转发互通
```

地址规划（默认）：

| 项 | vm1 | vm2 |
|----|-----|-----|
| ens3 (underlay) | 192.168.0.2 | 192.168.0.6 |
| ns-frr / frr0 | 10.0.0.1/30 | 10.0.0.2/30 |
| 广告网段 adv_base | 10.0.2.N/32 | 10.0.3.N/32 |
| AS | 65001 | 65002 |

> 以下命令一般在宿主机执行 `python3 vm.py exec <vm> '<cmd>'`，或直连 `ssh -i id_rsa root@192.168.0.x '<cmd>'`。netns 内命令需加前缀 `sudo ip netns exec ns-frr`。

---

## 1. 数据面：隧道与链路

### 1.1 vxlan 隧道存在且连对端 underlay
```bash
ip -d link show vxlan1024        # 看 remote/local/dstport/id
# 期望: vxlan id 1024 remote 192.168.0.6 local 192.168.0.2 dev ens3 dstport 4789 ...
```

### 1.2 bridge 上两个成员是否挂载、是否转发
```bash
sudo bridge link show br0         # 应见 frr0p 与 vxlan1024, state forwarding
ip -br link show br0 frr0p vxlan1024
```

### 1.3 vxlan 二层转发表（FDB）
```bash
sudo bridge fdb show dev vxlan1024
# 期望出现形如: xx:xx:.. dst 192.168.0.6 via ens3 self
```

### 1.4 underlay 直连（跨 host 转发）
```bash
ping -c 3 192.168.0.6            # vm1 上 ping 对端; 0% loss
```

### 1.5 隧道 ping 对端 frr0（经 VXLAN 跨整条 overlay）
```bash
ip netns exec ns-frr ping -c 3 -W 2 10.0.0.2     # vm1; 对端 frr0 => 0% loss
```

---

## 2. netns 内部视图

```bash
ip netns list                                     # 应见 ns-frr
ip -n ns-frr addr show lo                         # 本机 loopback(10.0.1.x) + 广告网段 /32
ip -n ns-frr addr show frr0                       # 10.0.0.x/30
ip -n ns-frr route                         # frr0 有 10.0.0.0/30 直连
ip -n ns-frr ip -br a                             # 汇总
```

---

## 3. FRR 进程与监听

```bash
ip netns exec ns-frr ps aux | grep -E 'zebra|bgpd' | grep -v grep
ip netns exec ns-frr ss -ltn | grep -E ':179|:260[15]'     # bgpd 179, zebra 2601, bgpd vty 2605
cat /etc/frr/bgpd.conf                            # 确认发布 N 条 network
```

---

## 4. 控制面：BGP

所有 vtysh 命令需在 netns 内执行：

```bash
# 邻居摘要（关键: State/PfxRcd, 应 Established, PfxRcd=N）
ip netns exec ns-frr vtysh -c 'show bgp summary'

# BGP 路由表（关键: 应见到对端广告网段的 N 条 /32, 路径里带对端 AS）
ip netns exec ns-frr vtysh -c 'show ip bgp'

# 对端学到的前缀示例:
#   10.0.3.1/32   10.0.0.2 ...  65002 i    <-- vm1 从 AS65002 学到
```

打开 vtysh 交互（可选）：
```bash
sudo ip netns exec ns-frr vtysh
> show bgp summary
> show ip bgp
# 其他有用: show running-config / show ip route / show bgp ipv4 unicast
Ctrl-D 退出
```

---

## 5. 路由注入到内核（zebra RIB → 主机路由表）

FRR 学到对端路由后,会注入 netns 内核路由表:

```bash
ip -n ns-frr route                                 # 应看到经 10.0.0.x 到的对端 /32
```

---

## 6. 端到端可达性

```bash
# 在 vm1 中 ping 对端 frr0 与对端广告网段的某个地址
ip netns exec ns-frr ping -c 2 10.0.0.2           # 对端 frr0
ip netns exec ns-frr ping -c 2 10.0.3.1           # 对端广告网段首地址 -> 走 BGP 路由
```

---

## 7. 常用排查

| 现象 | 命令 | 关注点 |
|------|------|--------|
| 隧道 ping 不通 | `sudo bridge fdb show dev vxlan1024`、`ip -d link show vxlan1024` | FDB/remote 是否对 |
| underlay 不通 | `ping $(对端).underlay` | host 转发、FORWARD 链、sysctl |
| BGP 不 Established | `ip netns exec ns-frr vtysh -c 'show bgp summary'` | State 是 Active/Connect 还是 Established; vty socket |
| 抓包 | `sudo timeout 10 tcpdump -ni br0 tcp port 179` | 看 SYN 是否穿越 |

---