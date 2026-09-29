

## VM描述

VM1：使用vm1.qcow2 磁盘镜像，使用tap0，ip地址 192.168.0.1/30，内部网卡名称ens3，IP地址192.168.0.2/30
VM2：使用vm2.qcow2 磁盘镜像，使用tap1，ip地址 192.168.0.5/30，内部网卡名称ens3，IP地址192.168.0.6/30
VM2：使用vm2.qcow2 磁盘镜像，使用tap1，ip地址 192.168.0.9/30，内部网卡名称ens3，IP地址192.168.0.10/30
VM之间通过host进行路由转发

启动方式参考：

```bash
sudo qemu-system-x86_64 \
  -enable-kvm -m 1024 -smp 2 -cpu host \
  -drive file=vm1.qcow2,format=qcow2,if=virtio \
  -netdev tap,id=n0,ifname=tap0,script=no,downscript=no \
  -device virtio-net-pci,netdev=n0,mac=52:54:00:00:00:01 \
  -nographic \
  -qmp unix:/tmp/vm1.sock,server,nowait
```

注意，启动前要创建好tap（如果存在，先删除），并配置好ip，VM中的IP地址启动时自动配置，无需额外配置。
使用ssh连接时，直接使用本目录下的id_rsa登录root账户即可，使用ssh命令行在vm上执行程序

## VM设计要求

设计成为一个类，执行命令、上传文件、启动、关闭等操作

## veth-only模式

由于veth-only模式下没有vxlan进行vm间通信，构建一个定制的数据面，主要有两个目的
1、使得不同VM之间可以通信
2、甚至做到一端被冻结（VM pause），另外一端不会有察觉。

我们需要在veth pair中放在root netns的veth配置IP地址，比如，vm1 frr命名空间的IP是10.0.0.1/30，处于VM2中frr的IP为10.0.0.2/30，
这里我们需要在vm1 veth pair中放在root netns的veth配置IP地址10.0.0.2/30 来模拟另外一端。

因此首先Python脚本预先将相应的veth配置好IP地址

这需要有两个组件agent和controller，需要用C++实现，分别放在两个目录当中

### agent组件

这个组件运行在VM当中，主要有两个职责

1、监听模拟的IP地址的179端口（上述例子中的VM1就是10.0.0.2，注意这个可能是多个），进行BGP session建立操作，BGP session建立后，
解析并接收BGP消息，并将其转发到controller（请设计消息头包含相应IP信息）
2、读取对应veth的裸报文（TCP除外，也就是AF_PACKET），直接转发到controller（同样利用消息头传送必要元信息）
3、监听来自controller其他router的建立连接，需要有相应消息类型来提示外部发起连接，并且处理来自controller其他router的消息，分发到对应的连接当中。

agent启动的时候采用命令行指定JSON配置文件，里面包含需要监听的IP地址和veth网卡名称，两者是一一对应的，一个veth对应一个IP地址，JSON解析可用本目录的json.hpp 头文件库

另外agent启动时还要指定controller的IP地址，agent和controller之间通过TCP连接，注意是长连接，命令行还要指定router的id（int），本router id 小于目标router id，不接受建立连接，断开。



### controller组件

controller负责监听某个IP地址（可以直接用第一个tap的IP地址即可），获取和转发来自不同VM agent的BGP消息和裸报文原始消息，需要维护不同IP之间的对应关系（比如10.0.0.1/30对应10.0.0.2/30），并且转发到对应router所在的VM当中。初始化阶段由controller向所有VM中的agent发起连接，连接建立后，所有agent才能和frr建立tcp连接，进行消息转发。

controller命令行启动要指定监听的IP地址，并且通过json来指定不同router的多个IP地址，以及router之间的连接（IP-IP对），json还有router所在vm的IP地址、id等信息，请指定一个格式，并且形成文档。

JSON解析可用本目录的json.hpp 头文件库

controller一定要在各个流程充分打log，方便验证。

controller采用epoll的方式进行处理，支持多线程（每个线程按照一定规则epoll对应的连接）

### 数据面可靠性要求（不丢包）

定制数据面（agent 与 controller 之间、以及往各端 FRR 的转发）**不允许丢包**。实现需满足：
- **发送缓冲 + EPOLLOUT 续发**：跨连接/跨线程发送遇到发送缓冲满（`EAGAIN`/部分发送）时，未发出的字节必须进入该连接的发送队列，由负责该连接的线程在其 socket 可写（`EPOLLOUT`）时续发直至发完；发完前不得丢弃。
- **在途缓冲（controller 未连接时不丢）**：agent 侧当 controller 未连接（`g_ctrl_fd < 0`）时，待发消息仍需入队缓存，等控制连接建立/重连后补发，而不是静默丢弃。
- **保序**：同一目的连接的消息顺序不变（入队一律追加到队尾，未发完的部分置于队首以保持先后），避免 BGP/裸包乱序。
- **跨线程发送安全（仅需多线程处）**：发送队列用锁保护，对 socket 的监听事件（`EPOLLOUT`）注册/取消只在属主线程自己的 epoll 上操作，属主线程经 `EPOLLOUT` 事件续发。多线程组件（controller）跨线程入队时用 eventfd 唤醒属主线程去 flush；**agent 为单线程**（裸帧/控制/BGP 汇于一条 epoll 循环），无需 eventfd/锁/atomic。
- **队列空则撤 EPOLLOUT**：level-triggered 下，队列空时必须去掉 `EPOLLOUT`，否则可写事件会忙触发。
- **控制连接生命周期**：仅在真实断开（读到 0 / 错误 / 协议错）时才拆除，不得在读完一批数据后误拆。
- **异常帧除外**：畸形/自环（`PACKET_OUTGOING`）或已由专用通道处理的 TCP 帧按既有过滤丢弃，这不属于"丢包"定义范围。


### 节点冻结/恢复特性

现在需要使用vm 的pause和resume来实现节点的冻结下线和恢复，这里面需要controller和agent作对应的配合。

1、controller要提供外部控制的接口，指定下线和上线的VM的编号，并获取结果
2、下线流程：节点下线前，需要提前通知agent，要求把agent所有消息都写给controller后shutdown掉写端，controller把所有消息（最后加一条KEEPALIVE消息）写给agent后shutdown掉写端，controller之间的连接断开（fd需要及时回收），所有下线节点的通道关闭以后，通知接口调用者，
3、上线流程：节点上线后，controller主动向agent重建通道，所有上线节点的通道重建后，通知接口调用者
4、controller启动时可以指定默认在线的节点，收到消息时，如果对端不在线，要确保消息缓存起来，而不是丢失或报错
5、当一端在线，另外一端不在线的时候，如果两端的BGP不是处于OPEN状态，任意一方主动连接都需要关闭，这是为了避免不必要的超时。如果一端在线，另外一端不在线，两端BGP已经是OPEN状态了，对于在线的一方，controller需要按照一定周期向在线的一方发送BGP KEEPALIVE消息，避免超时连接断开。

**注意（iter 上/下线与 controller 在线态要一致）**：节点的"冻结/恢复"存在两个独立维度——`VM.pause`/`VM.resume`（QMP 冻结 vCPU）和 controller 侧的 `admin_offline`（是否拨号/重连该节点 agent）。二者必须配套：
- **上线**：`VM.resume`（QMP cont）之后，还必须调用 `controller online(rid)`，把节点标回在线并触发 controller 重拨其 agent 连接，否则 controller 仍以为该节点离线——它对端一上报 `UP` 就会被 controller 当成"对端离线"而立即 `CLOSE` 掉刚建起的会话，BGP 永远到不了 Established。
- **下线**：`controller offline(rid)`（优雅排空）之后，再 `VM.pause`。
只做 QMP 层面的 resume/pause、不同步 controller 的 online/offline，会表现为"对端在上报 UP 后被反复 CLOSE"，且每段结束的对端 BGP 判定失真。

### vm.py需要做的适配

设置一个iter模式，迭代启动，启动

vm需要通过一个partition配置文件（JSON格式）指定始终在线的节点id，和多个轮流在线的节点集合id，按照一定顺序先resume始终在线节点，然后再按照顺序启动轮流在线节点，等到20s内没有BGP UPDATE消息后（controller要提供类似接口，阻塞直到条件满足），pause该节点，resume下一个节点集合。

注意，如果节点没有启动过，则需要启动（包括数据面），并且启动后至少等待30s。


你需要指定partition文件的格式，并且写到文档里







