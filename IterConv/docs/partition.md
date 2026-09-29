# partition 配置与节点冻结/恢复 (iter 模式)

本文档定义 `--iter-config <partition.json>` 的配置格式，以及它驱动的"常在线 + 轮换上线"
节点冻结/恢复流程。底层由 controller 的 unix 命令服务(`offline`/`online`/`quiescent`)与
agent 的优雅下线协议配合实现；前端由 vm.py 用 QMP `VM.pause()/resume()` 冻结/恢复整台 VM。

## 1. partition 文件格式

json 顶层字段：

| 字段 | 类型 | 默认 | 含义 |
|------|------|------|------|
| `quiescent_ms` | int | 20000 | 每段等待"全局无 BGP UPDATE"的时长(毫秒)。见 §3 quiescent |
| `first_boot_wait_ms` | int | 30000 | 某节点**首次启动**(含数据面)后的兜底等待(毫秒)，让其收敛 |
| `always_online` | `[vm名]` | `[]` | 常在线节点：全程保持在线、不被 pause。也是 controller 启动时的 `admin_default_online` 种子 |
| `sets` | `[[vm名]...]` | `[]` | 轮换上线集合的**有序**列表：按顺序依次上线→静默→下线 |

约定：
- 每个 vm 名必须是 `vm_spec.json`(VMSPEC) 里的键。
- 同一个 vm 名应只出现在一个 set 里(语义上它属于该轮换集合)。
- 链路的链接关系沿用 controller.json 里既有的 `links`(目前按 VMSPEC 前两台建的单条 link)。

示例(常在线 vm1，轮换 vm2)：

```json
{
  "quiescent_ms": 20000,
  "first_boot_wait_ms": 30000,
  "always_online": ["vm1"],
  "sets": [ ["vm2"] ]
}
```

运行：

```bash
python3 vm.py --iter-config config/partition.example.json --iter-rounds 2
```

## 2. iter 流程 (vm.py::run_iter)

1. 检查 partition 引用全部在 VMSPEC 内；`setup_host_network()` 配 host tap/转发。
2. 对 `always_online ∪ 各 set` 每台 VM：
   - 已运行 → `resume()`(清掉可能遗留的暂停态)；未运行 → `start()` 并记为首启。
   - `wait_boot()`（等 ssh 就绪）；首启的再等 `first_boot_wait_ms`。
3. 数据面：每 VM 内建 frr netns+veth(`setup_frr_veth_only`) → host 编译 agent/controller
   (`build_dataplane`) → 部署 agent(`deploy_agent`) → 启动 controller(`start_controller`)，
   `admin_default_online` 取自 partition 的 `always_online`。
4. 用 `ControllerCtl` 连 controller 的 ctl socket；`ping()` 建连。
5. `quiescent(quiescent_ms)` 做首次静默同步。
6. 每轮、每个 set：
   - `resume()` 该 set 的全部节点；
   - `quiescent(quiescent_ms)` **阻塞**至全局 quiescent_ms 内无 BGP UPDATE；
   - 逐个 `ControllerCtl.offline(rid)`(**优雅排空**)，再 `VM.pause()` 冻结该 VM。
7. `always_online` 节点全程保持在线。

## 3. controller 命令服务协议

controller 在 `ctl_socket`(默认 `/tmp/controller.ctl`，可由 controller.json 改) 起 unix
socket 服务；一条命令一个连接，发一行 JSON、回一行 JSON。

| 命令 | 请求 | 应答 | 说明 |
|------|------|------|------|
| ping | `{"cmd":"ping"}` | `{"ok":true,"routers":N}` | 心跳/建连确认 |
| offline | `{"cmd":"offline","router":id}[,"timeout_ms":8000]` | `{"ok":true,"router":id}` 或 `{"ok":false,"reason":"timeout"}` | 优雅下线该 router(见 §4)，等其通道关闭后应答 |
| online | `{"cmd":"online","router":id}[,"timeout_ms":8000]` | `{"ok":true,"router":id}` | 重建到该 router agent 的连接，就绪后应答 |
| quiescent | `{"cmd":"quiescent","ms":N}` | `{"ok":true,"idle_ms":N}` | **阻塞**到最近一次 BGP 中继距今 ≥ N ms |
| shutdown | `{"cmd":"shutdown"}` | `{"ok":true}` | 应答后终止整个 controller 进程(含后台 worker) |

semantics：
- `offline` 置该 router `admin_offline=true`，经 eventfd 唤醒属主 worker 向 agent 发
  `MSG_CTRL_OFFLINE`；agent 排空后 `shutdown(SHUT_WR)`；controller 收 EOF 后补发剩余缓存，
  再 `SHUT_WR` 关连接并回收 fd，然后应答。
- `online` 置 `admin_offline=false`，触发重连(复用既有 `OpenConn` 路径)，连上后应答。
- 目标 router 离线/未连接时，发往它的 MSG_BGP/MSG_RAW 一律缓存到它的 `txbuf`(跨断线保留)，
  待其(重)连/flush 时按序补发——**不丢包**。

> 每次 iter `offline` 成功后才 `VM.pause()`：排空依赖 agent 还活着；`offline` 带超时兜底，
> 超时也推进 pause 以免 iter 卡死。

**手动调用示例**(逐条命令、一条连接一应，socat 或 python 均可)：

```bash
# 方式一：socat(命令结束 controller 关闭连接即返回)
printf '{"cmd":"ping"}\n'                 | socat - UNIX-CONNECT:/tmp/controller.ctl
printf '{"cmd":"quiescent","ms":5000}\n'  | socat - UNIX-CONNECT:/tmp/controller.ctl
printf '{"cmd":"offline","router":2}\n'   | socat - UNIX-CONNECT:/tmp/controller.ctl

# 方式二：python(可带超时, 便于脚本化; 语义同 vm.py::ControllerCtl)
python3 - <<'PY'
import socket, json
def ctl(req, path="/tmp/controller.ctl"):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(path); s.sendall((json.dumps(req) + "\n").encode())
    buf = b""
    while True:
        d = s.recv(4096)
        if not d: break
        buf += d
    return json.loads(buf)
print(ctl({"cmd": "ping"}))
print(ctl({"cmd": "online", "router": 2}))
print(ctl({"cmd": "quiescent", "ms": 20000}))
PY
```

## 4. 优雅下线/上线数据面协议

新增消息类型：

| 类型 | 值 | 方向 | 语义 |
|------|----|------|------|
| `MSG_CTRL_OFFLINE` | 8 | controller→agent | 开始优雅下线：agent 先把待发全部写给 controller，再 `shutdown(SHUT_WR)` 关写端，仍读直到 EOF |

下线排空顺序（以 router R 为例）：
1. controller 置 `R.admin_offline=true`，发 `MSG_CTRL_OFFLINE`。
2. agent 收到：`FlushCtrlTx()` 排空 → `shutdown(g_ctrl_fd, SHUT_WR)`，之后新报文仍入队缓存。
3. controller worker 读到 agent EOF(半关)：发尽 `R.txbuf` 剩余缓存 →
   `shutdown(SHUT_WR)` → `close(fd)`、`fd=-1`、回收 → 通知 ctl 应答。
4. agent 读 EOF → `close`。通道彻底关闭。

上线：controller `online` 后对 agent 重新拨号；agent 在控制监听 accept 时把
`g_ctrl_offline` 复位，进入新一轮连接。

## 5. 单边离线时的 BGP 会话策略 (P3)

controller 按 link 追踪 BGP 状态(中继 MSG_BGP 解析 offset-18 的 BGP type：OPEN→Established，
NOTIFICATION→复位)。`KeepaliveThread` 每 30s 扫一遍 link：当一端 `admin_offline`、另一端在线时，

- link **已 OPEN**：向在线侧注入真实 `MSG_BGP(KEEPALIVE)`(源=离线侧 frr ip)，让在线侧 FRR 的
  Established 会话不因对端离线而超时 teardown；对端回来无需完整重协商。
- link **未 OPEN**：向在线侧发 `MSG_CTRL_CLOSE`(目标=其 frr session)，agent 收到后关闭该 FRR
  会话，避免空等 TCP 超时。

agent 侧 `ProcessCtrlIn` 处理 `MSG_CTRL_CLOSE`：按 `h.dst_ip` 找到 FRR 会话并关闭(清理 fd，
保留其 txq 以便重建后补发)。

## 6. 三节点 line 示例 (config/ 三份文件)

拓扑 `r1 - r2 - r3`(`-` 为链路)，中间节点 **r2 同时连 r1 与 r3**(两条独立 BGP 会话)。
对应三份示例配置:

| 文件 | 作用 |
|------|------|
| `config/vm_spec.json` | 三台 VM: vm1/vm2/vm3 (tap0/1/2, mac ...01/02/03, host `192.168.0.1/5/9`, vm ens3 `.2/.6/.10`) |
| `config/frr_overlay.json` | line 邻接表: 每 vm 带 `peers` 列表(r2 两条), 含 frr 地址/asn/loopback/adv_base |
| `config/partition.json` | `always_online=["vm2"]`, `sets=[["vm1"],["vm3"]]` (r2 常在线, r1/r3 轮换) |

**地址分配**:

| 节点 | frr 地址(链路) | loopback / adv_base | asn | underlay(ens3) |
|------|----------------|---------------------|-----|----------------|
| vm1(r1) | `10.0.0.1/30` (r1-r2) | `10.0.3.1/32` / `10.0.3` | 65001 | 192.168.0.2 |
| vm2(r2) | `10.0.0.2/30` (r1-r2), `10.0.1.1/30` (r2-r3) | `10.0.4.1/32` / `10.0.4` | 65002 | 192.168.0.6 |
| vm3(r3) | `10.0.1.2/30` (r2-r3) | `10.0.5.1/32` / `10.0.5` | 65003 | 192.168.0.10 |

- 每 vm 的本端 frr 地址全局唯一(agent 侧 `frr_sess` 按它索引); 链路两端的 frr 地址互指。
- veth-only 模式: root 侧 veth `frr<i>p` 配"模拟对端"假 IP(对端 frr 地址)。
- 原生 overlay 模式: 每邻居一条 veth + 一个 vxlan(r2 两条), VNI 由两端 router id 派生
  (r1-r2 = 1126, r2-r3 = 1227), 两端算得同值。

**运行**:

```bash
# 原生 VXLAN + FRR overlay (FRR 直连, 不冻结)
python3 vm.py --vm-spec config/vm_spec.json --frr-overlay config/frr_overlay.json

# iter 冻结/恢复 (恒走 veth-only 定制数据面; r2 全程在线, r1/r3 轮换)
python3 vm.py --vm-spec config/vm_spec.json --frr-overlay config/frr_overlay.json \
  --iter-config config/partition.json --iter-rounds 2
```