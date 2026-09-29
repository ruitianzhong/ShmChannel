# IterConv

基于 QEMU/FRR 的路由**迭代收敛**（Iterative Convergence）实验环境：多台 VM 各跑一个 FRR 路由器，
以 BGP 互相建立会话并发布路由，通过暂停/恢复（冻结/恢复）节点来反复验证"某节点离线期间，其余节点的
BGP 会话保持稳定、拓扑收敛正确"。

核心是一套 **veth-only 定制数据面**（`agent` + `controller`，C++ 实现），用一条独立于 veth 的 TCP
控制通道在 VM 之间中继 BGP 报文与裸报文（取代 VXLAN 隧道），并做到**一端被冻结、另一端无感知**。

支持：
- 拓扑：两节点点对点、三节点 line（`r1-r2-r3`）。
- 数据面：原生 VXLAN+FRR overlay，或 veth-only 定制数据面（agent/controller 中继 BGP）。
- 自动建 VM（`--create`，按 `--frr-overlay` 数量建一批、经 vsock 下发网络配置）。
- **迭代收敛（iter）**：按 partition 配置，常在线节点全程保持，轮换集合节点反复 冻结（`VM.pause`）/恢复
  （`resume`），controller 配合单边离线保活与 BGP 会话建立期过滤（链路未 OPEN 时丢弃失序帧），
  验证离线期间的收敛稳定性。

```
  vm.py (入口: argparse + 编排; 逻辑按单向依赖拆分到下列模块)
     │
     ├── topo.py       拓扑/配置: VMSPEC/FRR_OVERLAY 默认、router-id/vni、/30 地址分配
     ├── vmmgr.py      基础设施: VM 类/QMP/SSH 客户端/host 网络(tap/转发)
     ├── frr.py        FRR 建网: netns+veth 与 VXLAN+FRR 的配置生成/上传/部署/验证
     ├── dataplane.py  定制数据面: agent/controller 编排、controller 命令服务、单边离线保活
     ├── create.py     自动建 VM(--create): 造磁盘/tap/vsock 下发配置
     ├── iter.py       冻结/恢复: run_iter, 经 ControllerCtl 驱动 online/offline/quiescent
     │
     ├── agent/        agent.cpp   跑在 VM 内: 终结 FRR 的 179 连接、AF_PACKET 收裸帧、经 controller 转发
     ├── controller/   controller.cpp  跑在 host: 拨号各 agent、按 frr_ip 转发、多线程 epoll 拼接会话
     ├── common/       protocol.h  共享消息头(MsgHeader + MsgType)
     │                json.hpp    nlohmann/json 单头
     └── *.md          见下「文档」
```

> 模块依赖单向无环：`topo ← vmmgr ← {frr, dataplane, create, iter} ← vm.py`。`VMSPEC`/`FRR_OVERLAY`
> 为运行时可变默认（由 `--vm-spec`/`--frr-overlay` 覆盖），各模块经 `topo.XXX` 活引用读取。

## 构建

需要 `cmake >= 3.16` 与支持 C++17 的编译器（g++ 即可）。

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

- 产物统一输出到 **`bin/agent`** 与 **`bin/controller`**（`CMAKE_RUNTIME_OUTPUT_DIRECTORY` 已指到仓库根 `bin/`）。
- 二次构建是增量的：改完 `agent/agent.cpp` 或 `controller/controller.cpp` 后，直接
  `cmake --build build` 只重编改动的目标。
- 两个目标都链接 `Threads`, 编译选项 `-Wall -Wextra`, 标准 C++17。

> `dataplane.build_dataplane()`（由 vm.py 流程调用）内部已调用上述 cmake 命令。

## 运行与验证

四种跑法：**两节点**、**三节点 line overlay**、**三节点 iter（冻结/恢复）**、
**自动创建 VM（`--create`）**。iter 恒走 veth-only 定制数据面；非 iter 的 overlay 走原生 VXLAN + FRR
（`--create` 可搭配 `--veth-only` 或默认 overlay）。

### 两节点（内置默认拓扑）

```bash
python3 vm.py --veth-only          # veth-only: 定制数据面 + BGP 中继（agent/controller）
python3 vm.py                      # 默认: 原生 VXLAN + FRR overlay（FRR 直连）
```

不指定 `--vm-spec` / `--frr-overlay` 时用 `vm.py` 内置的两节点默认（vm1↔vm2）。

### 三节点 line（r1-r2-r3）

拓扑：`r1 - r2 - r3`（`-` 为链路），中间节点 **r2 同时连 r1 和 r3**（两条 BGP 会话）。
由 `config/` 下的 JSON 描述，**必须同时传** `--vm-spec` 与 `--frr-overlay`：

- `config/vm_spec.json` — 三台 VM（vm1/vm2/vm3；tap0/1/2，host `192.168.0.1/5/9`）。
- `config/frr_overlay.json` — line 邻接表：每个 vm 带 `peers` 列表（`name`/`frr_ip`/`peer_frr`/`peer_asn`），
  r2 有两条邻居。frr 地址 `10.0.0.x`(r1-r2)、`10.0.1.x`(r2-r3)。

原生 VXLAN + FRR overlay（FRR 直连，不经 agent/controller）：

```bash
python3 vm.py \
  --vm-spec config/vm_spec.json \
  --frr-overlay config/frr_overlay.json
```

`vm.py` 会为每个邻居建一条 veth + 一个 vxlan（r2 建两条，VNI 由链路两端 router id 派生、两端一致），
按 `frr_overlay.json` 的 `peers` 生成 bgpd 多邻居配置，最后打印各 VM 的 BGP 邻居/路由与隧道可达性。

三节点 veth-only 定制数据面（**不迭代**，agent/controller 中继 BGP，三节点同时在线）：
与两节点 veth-only 相同的参数，只是换成三节点配置：

```bash
python3 vm.py \
  --vm-spec config/vm_spec.json \
  --frr-overlay config/frr_overlay.json \
  --veth-only
```

只需三节点两份配置 + `--veth-only`、**不加** `--iter-config`，即走常规非 iter 分支；
`gen_controller_json` 展开全部 router 与 links（r2 两条链路），三节点同时在线直接收敛。

### 三节点 iter（节点冻结/恢复）

常在线 **r2**，轮换集合 **r1 → r3**（`always_online=[vm2]`，`sets=[[vm1],[vm3]]`）。
按 partition 配置依次 resume → quiescent（20s 无 BGP UPDATE）→ 优雅 offline → `VM.pause`，
controller 负责排空与单边离线保活。格式与协议见 `docs/partition.md`。

```bash
python3 vm.py \
  --vm-spec config/vm_spec.json \
  --frr-overlay config/frr_overlay.json \
  --iter-config config/partition.json \
  --iter-rounds 2
```

> iter 模式**恒走 veth-only 定制数据面**（不需要 `--veth-only`），r2 全程在线，r1/r3 轮流冻结。
> 两节点 iter 示例见 `config/partition.example.json`。

**手动分步走查（`--iter-step`）**：加该开关后，每段的节点**上线前**（`vms resume`）与**下线前**
（`controller offline` + `VM.pause`）都会 `input` 等按 Enter 再继续，便于人工逐段观察状态；不传则与原来一样自动推进。
每段冻结后还会对**仍在线**节点跑 `verify_veth_bgp`，核对其 BGP 会话/学到的前缀保持正常。

```bash
python3 vm.py \
  --vm-spec config/vm_spec.json \
  --frr-overlay config/frr_overlay.json \
  --iter-config config/partition.json \
  --iter-rounds 2 \
  --iter-step
```

### 自动创建 VM（`--create`，与 `--vm-spec` 互斥）

按 `--frr-overlay` 规定的数量自动建一批 VM 作为 FRR router，无需手写 VM 规格：
**建的数量 = `len(FRR_OVERLAY)`**（overlay 里列了几台 vm 就建几台），不需要再给个数。
IP/网卡/tap 按 AGENTS.md 拓扑 `/30` 平移分配（vm_i: tap0.. 用 `192.168.0.(1+4·(i-1))`，
ens3 用 `192.168.0.(2+4·(i-1))`）。流程：造磁盘（qcow2 继承 `vm_base.qcow2`，统一放 **`disks/`**，
已被 gitignore）→ 建 tap 配 IP →
启动（带 vsock `guest-cid`）→ 用并行的 `vsock_client.py` 下发 ens3 IP/默认路由 → echo hello 验证。
**拓扑/邻居由 `--frr-overlay` 指定**（引用 vm1..vmN，`underlay` 须填对应 `vm_ip`）。

```bash
python3 vm.py \
  --create \
  --frr-overlay config/frr_overlay.json \
  --veth-only
```

> `--create` 与 `--vm-spec` 二选一；它自动生成 VMSPEC 并直接进入数据面流程（`--veth-only`
> 定制数据面或默认 VXLAN overlay）。前置：宿主 `modprobe vhost_vsock`；`vm_base.qcow2`
> 镜像内已部署并自启 vsock server（`scripts/vsock_server.py` + systemd，见 `scripts/vsock-setup.sh`）。
> `--create` 的 VM 地址分配固定，`--frr-overlay` 的 `underlay`/名称需与之匹配。

### 选项说明

- `--vm-spec`：VM 规格（镜像、tap、mac、host/vm ip、QMP socket），默认 `vm.py` 内置（两节点）；与 `--create` 互斥。
- `--create`：按 `--frr-overlay` 的数量自动创建 VM 并作为 FRR router（按 `/30` 拓扑分配 IP/网卡/tap，见上文）。
- `--frr-overlay`：FRR overlay（underlay、frr 地址/loopback/adv_base、ASN、`peers` 邻居），默认内置。
- `--iter-config` / `--iter-rounds`：partition（常在线 + 轮换集合）与轮换轮数；走 iter 冻结/恢复模式。
- `--iter-step`：iter 模式每段节点上下线前等按 Enter 再继续（手动分步走查）。
- `--veth-only`：仅非 iter 时生效——只建 netns+veth（定制数据面），不建 bridge/vxlan。
- 两个 spec 文件彼此独立、可只覆盖其一；三节点需两份同时给。

## 文档

- `AGENTS.md` — VM 描述、VM 类设计要求、veth-only 模式规格（agent/controller 职责）。
- `docs/veth_dataplane.md` — agent/controller 的 JSON 配置格式、消息头、消息流、router-id 规则、缓存与保序、验证。
- `docs/overlay_verify.md` — VXLAN + FRR overlay 手工验证手册。
- `docs/partition.md` — partition 配置格式、iter 冻结/恢复流程、controller 命令服务与优雅下线协议、
  单边离线 BGP 策略；§6 为三节点 line 示例配置与地址分配。
- `config/` — 三节点示例配置：`vm_spec.json`(vm1/vm2/vm3)、`frr_overlay.json`(line 邻接)、
  `partition.json`(r2 常在线、r1/r3 轮换)、`partition.example.json`(两节点 iter 示例)。
  两节点拓扑本身是 `vm.py` 内置默认，无需配置文件。