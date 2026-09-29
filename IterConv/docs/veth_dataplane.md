# veth-only 定制数据面（agent + controller）

veth-only 模式没有 VXLAN 做 VM 间通信。本定制数据面用两个 C++ 组件在
**控制通道**（独立于 veth 的 TCP）上为各 VM 的 FRR 之间中继 BGP 报文，实现跨 VM 通信，
并具备"一端被冻结（VM pause）另一端无感知"的容错基础。

```
[ns-frr]  zebra+bgpd   frr0=10.0.0.1/30   (vm1)
    | veth frr0
[root ns] frr0p=10.0.0.2/30        ← 模拟对端 FRR 的假 IP
    |        agent: bind 10.0.0.2:179 终结 FRR 的 BGP TCP 连接
    |        控网 TCP(长连接)
[host]   controller: 拨号所有 VM 的 agent; 按 frr_ip 转发; 拼接会话
    |        控网 TCP
[root ns](vm2) frr0p=10.0.0.1/30 ← agent 终结 vm2 的 FRR 连接
[ns-frr]  frr0=10.0.0.2/30  (vm2)
```

## 目录 / 构建

| 组件 | 位置 | 运行处 |
|------|------|--------|
| agent | `agent/agent.cpp` | VM 内 root netns |
| controller | `controller/controller.cpp` | host |
| 共享协议 | `common/protocol.h` | — |

构建（host，x86 Linux，`g++` 已具备）：
```bash
g++ -O2 -std=c++17 -I. agent/agent.cpp -o bin/agent
g++ -O2 -std=c++17 -I. controller/controller.cpp -o bin/controller
```
JSON 解析用 `common/json.hpp`（nlohmann/json 单头）。

## 消息头（common/protocol.h）

定长 32 字节，little-endian（本机即 x86，直接读写结构体）：

| 字段 | 偏移 | 字节 | 含义 |
|------|------|------|------|
| magic | 0 | 4 | `0x50445856` ("VXDP") |
| version | 4 | 2 | 1 |
| type | 6 | 2 | 见 MsgType |
| src_router | 8 | 4 | 发送方 router_id |
| dst_router | 12 | 4 | 目标 router_id，0=all |
| src_ip | 16 | 4 | FRR 视角源 IP（本端 FRR ns 源地址） |
| dst_ip | 20 | 4 | FRR 视角目的 IP（对端 FRR 地址） |
| veth_idx | 24 | 4 | 归属 veth 索引（0=控制面，≥1=映射 veth） |
| len | 28 | 4 | 负载字节数（不含 header） |

`MsgType`：`MSG_CTRL_HELLO=1` 注册、`MSG_CTRL_ACK=2`、`MSG_CTRL_UP=3` 本地 FRR 会话 up、
`MSG_CTRL_ESTABLISH=4` 提示外部发起(重)连接、`MSG_CTRL_CLOSE=5` 通知会话断开、
`MSG_BGP=6` 单条 BGP PDU、`MSG_RAW=7` 单条原始以太帧（Phase 2）、
`MSG_CTRL_OFFLINE=8` controller→agent 开始优雅下线（排空后 shutdown 写端）。

控制通道上用 `header + payload` 定界；BGP 载荷按 BGP 自身 16B marker + 2B length 分帧
（agent 端终结的 FRR 连接读到完整 BGP 报文后，逐条 `MSG_BGP` 转发）。

## agent.json（每 VM 一份）

```json
{
  "controller_ip": "192.168.0.1",
  "control_port": 9000,
  "router_id": 1,
  "peer_router_id": 2,
  "veths": [
    { "veth_name": "frr0p", "fake_ip": "10.0.0.2", "frr_ip": "10.0.0.1", "peer_router_id": 2 }
  ]
}
```
- `fake_ip`：配在 root-ns `frr0p` 上、模拟对端 FRR 的 IP；agent 在此 `:179` 绑定终结。
- `frr_ip`：本端 ns-frr 源 IP；agent 用它识别"哪条已接受连接是本端 FRR 的"，并作为
  出向 `MSG_BGP` 写回的目标。
- veth 与假 IP 一一对应，`veths` 可多条。
- `peer_router_id`（顶层 + 每条 veth）：该链路上对端 router id，agent 据此**按链路**判低/高侧
  （本 id < peer_router_id 为低侧，拒绝该 FRR 的主动连接）；顶层取首邻居，保留为兼容旧字段。

## controller.json

```json
{
  "listen_ip": "192.168.0.1",
  "control_port": 9000,
  "ctl_socket": "/tmp/controller.ctl",
  "admin_default_online": [],
  "routers": [
    { "id": 1, "name": "vm1", "vm_ip": "192.168.0.2", "dial_ip": "192.168.0.1", "frr_ip": "10.0.0.1" },
    { "id": 2, "name": "vm2", "vm_ip": "192.168.0.6", "dial_ip": "192.168.0.5", "frr_ip": "10.0.0.2" }
  ],
  "links": [
    { "ip_a": "10.0.0.1", "ip_b": "10.0.0.2" }
  ]
}
```
- `ctl_socket`：controller 的 unix 命令服务路径（供 iter 上下线 / quiescent，见下节）。
- `admin_default_online`：启动即期望在线的 router id 白名单；非空时其余 router 默认离线
  （不拨号、收其流量只缓存），供 iter 逐节点轮换；空 = 全部上线（兼容旧行为）。
- `dial_ip`：controller 拨号该 router 时本地绑定的源 IP（本测试床 vm1 走 tap0=192.168.0.1，
  vm2 走 tap1=192.168.0.5）。
- `frr_ip` 全局唯一（即"哪个 router 的 FRR 以它为源"），controller 据此路由转发；多邻居的
  router 输出为数组（controller 为同一 Router 登记多个本端地址，一条链路一个）。

## controller 命令服务（iter 上下线接口）

controller 监听 `ctl_socket`（unix socket），一条命令一个连接、阻塞式单行 JSON 应答
（`dataplane.ControllerCtl` 是配套 Python 客户端）。命令：

| 命令 | 参数 | 含义 |
|------|------|------|
| `ping` | — | 探活，回 router 数 |
| `offline` | `router` 的 id，`timeout_ms` | 优雅下线：先给 agent 发 `MSG_CTRL_OFFLINE`，agent 把积压全写给 controller 后 `shutdown` 写端；controller 发尽剩余缓存后关连接，排空完成才应答 ok |
| `online` | `router` 的 id，`timeout_ms` | 标回在线并触发立即重拨 agent；重连成功（`ctl_up`）才应答 ok |
| `quiescent` | `ms` | 阻塞直到全局最近一次 `MSG_BGP` 中继距今 ≥ ms（iter 判定"20s 无 BGP UPDATE"收敛） |
| `shutdown` | — | 让 controller 退出 |

下线/上线必须与 QMP 的 `VM.pause`/`VM.resume` 配套（见 AGENTS.md）：先 `offline` 优雅排空再
`pause`；先 `resume` 再 `online`，否则对端一上报 UP 就被 controller 当"对端离线" CLOSE 掉。

## 单边离线保活（一端冻结，另一端无感知）

controller 每 30s 跑 `KeepaliveThread`，对整条链路扫两侧，取一侧在线、另一侧 `admin_offline` 的对：

- 链路已 OPEN（Established）：向在线侧**注入一条 BGP KEEPALIVE**（以离线侧 IP 为源写出），
  防其随对端离线而 keepalive 超时 teardown——在线端对冻结无感知。
- 链路未 OPEN：向在线侧发 `MSG_CTRL_CLOSE`，令其关闭该 FRR 会话，避免空等超时；
  对端恢复后经正常流程（ESTABLISH）重建。

## BGP 会话建立期过滤

controller 转发 `MSG_BGP` 时按链路 OPEN 态过滤（避免旧会话遗留的 OPEN/keepalive 污染新握手）：

- 链路**未 OPEN**：除 BGP `OPEN`(type 1)/`NOTIFICATION`(type 3) 外的帧一律**丢弃**（不缓存）。
- 未 OPEN 且对端**默认离线**（`admin_offline`）：连 `OPEN` 也丢（重建后对端会重发）。
- 链路 OPEN 后正常透传；转发时见到 `OPEN` 置 `L.open`，`NOTIFICATION` 复位。

## 消息流

1. agent 启动：监听 `control_port` 和每个 `fake_ip:179`。
2. controller 启动：按 `routers[].vm_ip` 拨号各 agent 控制端口（长连接，掉线自动重连）。
3. 每 VM 的 FRR（ns-frr）拨其 `fake_ip:179`（已在 frr0p 配置该假 IP，同 /30 直连）。
   agent 接受，`getpeername`=本端 frr_ip，向 controller 报 `MSG_CTRL_UP`。
4. agent 读到 FRR 的 BGP 字节流 → 按 BGP 长度分帧 → 逐条 `MSG_BGP`（src=frr_ip, dst=fake_ip）发 controller。
5. controller 按 `MSG_BGP.dst_ip` 找到所属 router（跨 VM）→ 转发到其 agent 连接。
6. agent 收到 `MSG_BGP`，按 `dst_ip` 写回对应 FRR socket（整条 PDU，FRR 自行解析）。

两端的 FRR 之间看起来就是一条普通 eBGP 会话（10.0.0.1 ↔ 10.0.0.2）。

## router-id 规则（不对称会话建立）

BGP 会话建立采用**不对称模型**，按 router id 高低分工：

- **高 id 侧**：其 FRR 主动拨 `fake_ip:179`，agent **accept 并保留**，上报 `MSG_CTRL_UP`。
- **低 id 侧**：其 FRR 主动拨 `fake_ip:179` 时，agent **accept 后立即 close**（拒绝低侧主动建连）；
  正确路径是等 controller 的 `MSG_CTRL_ESTABLISH` 后，由 agent 主动反向 dial 本机
  `frr_ip:179`，再上报 `MSG_CTRL_UP`。

controller 只在**高 id 侧上报 UP** 时向低 id 侧发 `MSG_CTRL_ESTABLISH`（`agent.json` 配 `peer_router_id`
判定低侧；`MSG_CTRL_ESTABLISH` 的 `dst_router` = 高 id，低侧据 `本 id < dst_router` 触发 dial）。
**不会**在低侧一连接就盲发，保证低侧 dial 发生在高侧 FRR 就绪之后，避免两侧会话起建时差。

每侧 agent 收到 ESTABLISH 校验 `本 id < 目标 id` 才 dial（兜底，幂等）。

## 缓存与保序（不丢包）

发送侧统一"**收即入队 FIFO、可写/就绪事件统一出队**"，保序由"唯一队列 + 唯一发送入口"
结构性保证，未就绪时缓存字节排在后续之前、连接就绪后先于后续发出。

- **agent → controller**：全部入 `g_ctrl_tx`，controller 未接入时留守，接入后 `FlushCtrlTx()` 补发。
- **controller → agent**：`SendToRouter` 一律入 `txbuf` 并唤醒属主线程，由 `FlushRouter` 出队；
  目标 agent 未连/连接中时字节留守，`OpenConn`/断开拆除处**不清空 txbuf**，(重)连后按序补发。
- **agent → FRR**：按 `frr_ip` 一会话一 `txq`；controller 来的 `MSG_BGP` 一律入该会话 `txq` +
  `FlushFrrReader()`。会话未就绪（accept/dial 前）字节留守，注册后由统一的 flush 补发；
  会话断开保留 `txq`（`fd=-1`），跨重连保序。
- 任一方向的发送都走"先入队再 flush"，无第二条写 socket 路径，故**只有在排队时已按序**
  这一前提，出队也就是有序的。

> 注：该模型按"缓存先于后续"语义原样保留跨会话遗留字节。为避免旧会话遗留的 OPEN/keepalive
> 注入新建立会话，controller 另有 BGP 会话建立期过滤（见上节）：链路未 OPEN 时仅放行
> OPEN/NOTIFICATION，其余 BGP 帧一律丢弃，避免 BGP 握手乱序。

## 验证（Phase 1）

host 看 controller 日志（充分打了 log）：
- 两个 agent 均"agent 已连接"。
- 各 VM FRR 连入后 controller 打"会话 UP <name>: frr_ip=... fake_ip=... veth_idx=..."。
- 学路由期间打 `RX MSG_BGP src/ dst / len` 与 `TX MSG_BGP -> <name>`。

每 VM：
```bash
ip netns exec ns-frr vtysh -c 'show bgp summary'   # 对端 Established
ip netns exec ns-frr vtysh -c 'show ip bgp'        # 学到对端发布的 /32
```
反向佐证无 VXLAN：`ip -d link show br0 vxlan1024` 应不存在。

## 运行（由 vm.py 编排）

`python3 vm.py --veth-only [--num-routes N] [--shutdown]`

`agent.json` / `controller.json` 由 vm.py 的 `gen_agent_json` / `gen_controller_json` 自动生成，
无需手写。三节点 iter（冻结/恢复）走同一数据面（见 README「三节点 iter」与 docs/partition.md）。

## 启动命令行与配置（非 iter vs iter，两节点模拟）

构建产物：`bin/agent`（VM 内）、`bin/controller`（host）。下面按**两节点默认拓扑**
（vm1=id1, vm2=id2；链路 10.0.0.1↔10.0.0.2）给出两种收敛方式的启动命令与配置。

### agent（每 VM 一份，两种模式相同）

配置写入 VM `/root/agent.json`，二进制 `/root/agent`，后台启动：

```bash
nohup /root/agent --config /root/agent.json >/root/agent.log 2>&1 &
```

vm1 的 agent.json：

```json
{
  "controller_ip": "192.168.0.1",
  "control_port": 9000,
  "router_id": 1,
  "peer_router_id": 2,
  "veths": [
    { "veth_name": "frr0p", "fake_ip": "10.0.0.2", "frr_ip": "10.0.0.1", "peer_router_id": 2 }
  ]
}
```

vm2 的 agent.json 仅差异：`controller_ip=192.168.0.5`、`router_id=2`、`peer_router_id=1`，
veth 的 `fake_ip/frr_ip` 与 vm1 **对调**（vm1 的 `fake_ip` = vm2 的 `frr_ip`），其余同。
两种收敛模式下 agent.json **完全一致**，因为 agent 不感知 iter/非 iter，只负责终结 179 与中继。

### controller（host，两种模式仅差 `admin_default_online`）

配置文件 `controller.json`，启动：

```bash
bin/controller --config controller.json
```

- **非 iter**：由 `gen_controller_json()`（无参）生成 → `admin_default_online: []`（空）。
  controller 启动即把 vm1、vm2 **全部默认在线**，一上来就拨号两者 agent，BGP 自动收敛。
- **iter**：由 `gen_controller_json(admin_online)` 生成，`admin_online = [topo._rid(n) for n in always]`
  → 只把**常在线**节点写进 `admin_default_online`；其余（轮换集合）节点默认离线
  （不拨号、收其流量只缓存），由后续 `controller online <id>` 逐个拉起。

以两节点 `config/partition.example.json`（`always_online=["vm1"]`, `sets=[["vm2"]]`）为例，
iter 的 `controller.json` 相比非 iter **只在 `admin_default_online` 一处不同**：

| 模式 | `admin_default_online` | 启动即拨号 | iter 环节 |
|------|------------------------|-----------|-----------|
| 非 iter | `[]` | vm1、vm2 | 无，收敛自动发生 |
| iter | `[1]` | 仅 vm1 | `online 2` 拉起 vm2 → 收敛 → `offline 2` + `VM.pause` 冻结 |

`routers` / `links` / `listen_ip` / `ctl_socket` 两种模式完全一致（见 §controller.json 示例）。
iter 收敛靠 `ControllerCtl` 经 `ctl_socket` 驱动：`online(2)` 标回在线并重拨，
`quiescent(20000)` 阻塞到 20s 无 BGP UPDATE 判收敛，`offline(2)` 优雅排空后再 `VM.pause` 冻结。