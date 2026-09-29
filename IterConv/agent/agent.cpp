// agent: 运行在 VM 内的定制数据面代理。
// Phase 1(控制面/BGP):
//   1. 监听控制端口, 接受 controller 拨号, 建立长连接;
//   2. 对每个 fake_ip:179 绑定 listener, 终结本地 FRR 的 BGP TCP 连接;
//   3. FRR 连接的字节流按 BGP 报文长度分帧, 逐条 MSG_BGP 转发 controller;
//   4. controller 来的 MSG_BGP 按其 dst_ip(frr_ip) 写入对应 FRR socket;
//   5. MSG_CTRL_ESTABLISH: 按 router-id 规则(本 id < 目标 id 则拒绝)。
// Phase 2(数据面/AF_PACKET):
//   6. AF_PACKET 在 root-ns 的那个 veth(frr0p) 上读非TCP裸帧 -> MSG_RAW 转发;
//   7. 收 MSG_RAW -> 原样注入对端对应 veth(数据面连通性, 无需 VXLAN)。
#include "../common/protocol.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <linux/if_packet.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "../common/json.hpp"
using json = nlohmann::json;

// 单线程: 裸帧/控制/BGP 全在一条 epoll 循环里, 故 g_ctrl_* 无需加锁/atomic。
static uint32_t g_router_id = 0;
static int g_ctrl_fd = -1;  // 与 controller 的长连接

// router-id 规则: 本 id < peer_router_id => 本侧为"低 id 侧", 拒绝 FRR 的主动连接,
// 改由本 agent 反向 dial FRR(收到 controller 的 ESTABLISH 后)。多邻居时按每个
// veth 独立判定(peer_router_id 每 veth 配置); ESTABLISH 由 controller 权威给出。
static uint32_t g_peer_router_id = 0;
// 本侧每条 veth(一条链路): 低 id 侧 dial 用 frr_ip, 上报用 fake_ip/veth_idx,
// peer_router_id 用于按链路判低/高侧。
struct VethCtx {
  uint32_t frr_ip = 0, fake_ip = 0, peer_router_id = 0, veth_idx = 0;
};
static std::vector<VethCtx> g_veths;
// 低 id 侧反向 dial FRR 的连接状态 + 本次所属链路(仅主线程, dial 回合串行)
static int g_frr_dial_fd = -1;
static bool g_frr_dial_connecting = false;
static const VethCtx* g_dial = nullptr;   // 当前 in-flight dial 对应的链路(回调注册用)
// 发往 FRR 的字节缓存统一放在各 BgpReader.txq(按 frr_ip 一会话一队列),
// 会话未就绪(accept/dial 前)时入队留守, 注册后由 FlushFrrReader 按序出队, 不丢。

// 到 controller 的可靠发送: 发送缓冲 + EPOLLOUT 续发。
static std::string g_ctrl_tx;              // 待发字节(含 controller 未连接时的在途缓冲)
static bool g_ctrl_need_epollout = false;  // 队列非空、已挂 EPOLLOUT(仅主线程)
static uint32_t g_ctrl_evs = 0;            // 控制连接当前注册到 g_efd 的事件掩码
static bool g_ctrl_offline = false;        // 已按 OFFLINE 排空并关写端, 等对端关连接
static int g_efd = -1;                     // 主线程 epoll fd

std::string NowStr() {
  char buf[40];
  time_t t = time(nullptr);
  struct tm tm;
  localtime_r(&t, &tm);
  strftime(buf, sizeof(buf), "%H:%M:%S", &tm);
  return std::string(buf);
}
void Log(const std::string& s) {
  fprintf(stderr, "%s [agent] %s\n", NowStr().c_str(), s.c_str());
}

int SetNonblock(int fd) {
  int fl = fcntl(fd, F_GETFL, 0);
  fcntl(fd, F_SETFL, fl | O_NONBLOCK);
  return fd;
}
int MakeTcpListen(uint32_t ip_be, uint16_t port) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  int on = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = ip_be;  // 网络字节序
  a.sin_port = htons(port);
  if (bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
    perror("bind");
    close(fd);
    return -1;
  }
  listen(fd, 16);
  return SetNonblock(fd);
}

uint64_t IfaceMac(const char* name) {
  char p[128];
  snprintf(p, sizeof(p), "/sys/class/net/%s/address", name);
  std::ifstream f(p);
  std::string s;
  f >> s;
  uint64_t mac = 0;
  for (int i = 0; i < 6; i++) {
    unsigned h = 16;
    sscanf(s.c_str() + i * 3, "%02x", &h);
    mac = (mac << 8) | h;
  }
  return mac;
}

struct BgpReader {  // 一次 FRR 连接的缓冲
  std::string buf;    // 读缓冲
  std::string txq;    // 发给该 FRR 的待发缓冲(背压时排队, 不丢)
  uint32_t evs = 0;   // 该连接当前注册事件(仅主线程)
  int fd = -1;
  uint32_t frr_ip = 0;
  uint32_t fake_ip = 0;
  uint32_t veth_idx = 0;
  uint8_t last_type = 0;   // 最近解析到的一条 BGP 类型(OPEN/UPDATE/...)
  uint64_t rx_total = 0;   // 自注册以来从该 FRR 累计读到的字节
};

struct RawIface {  // 一个 veth 的原始收发
  int rx = -1;  // AF_PACKET 读 socket(reader 线程)
  int tx = -1;  // AF_PACKET 写 socket(epoll 线程注入)
  int ifindex = 0;
  uint64_t mac = 0;         // 本 veth MAC(用于只转发发给本机的单播)
  uint32_t frr_ip = 0;      // 本端 frr 源 IP(读到的帧属于这个"源")
  uint32_t fake_ip = 0;     // 模拟对端 FRR 的 IP(路由键)
  std::string name;
};

static std::vector<RawIface> g_raw_ifaces;

// 非阻塞发送, 返回已发字节数(遇 EAGAIN/错误即停, 不阻塞)
size_t send_partial(int fd, const char* data, size_t len) {
  size_t sent = 0;
  while (sent < len) {
    ssize_t w = ::send(fd, data + sent, len - sent, MSG_NOSIGNAL);
    if (w > 0) sent += (size_t)w;
    else break;
  }
  return sent;
}
// 在 g_efd 上改控制连接监听事件(level-triggered, 队列空须去掉 EPOLLOUT)
void ModCtrlEvents(uint32_t events) {
  if (g_ctrl_evs == events) return;
  epoll_event ev{}; ev.data.fd = g_ctrl_fd; ev.events = events;
  epoll_ctl(g_efd, EPOLL_CTL_MOD, g_ctrl_fd, &ev);
  g_ctrl_evs = events;
}
// 在 g_efd 上改某 FRR 连接事件(用于 FRR 侧落队续发)
void ModEventsFrr(BgpReader& r, uint32_t events) {
  if (r.evs == events) return;
  epoll_event ev{}; ev.data.fd = r.fd; ev.events = events;
  epoll_ctl(g_efd, EPOLL_CTL_MOD, r.fd, &ev);
  r.evs = events;
}
// 把 g_ctrl_tx 尽量发完; 发尽则去掉 EPOLLOUT, 否则保持(由 EPOLLOUT 事件驱动)
void FlushCtrlTx() {
  if (g_ctrl_offline) return;              // 已下线排空并关写端, 不再发送
  int fd = g_ctrl_fd;
  if (fd < 0) return;                 // controller 未连接: 缓冲等着, 重连后再发
  if (g_ctrl_tx.empty()) {
    if (g_ctrl_need_epollout) { g_ctrl_need_epollout = false; ModCtrlEvents(EPOLLIN); }
    return;
  }
  size_t n = send_partial(fd, g_ctrl_tx.data(), g_ctrl_tx.size());
  g_ctrl_tx.erase(0, n);
  if (g_ctrl_tx.empty()) { g_ctrl_need_epollout = false; ModCtrlEvents(EPOLLIN); }
  else ModCtrlEvents(EPOLLIN | EPOLLOUT);
}
// 主线程: 把某 FRR 会话的 txq 尽量发尽(唯一写 FRR socket 的入口)。
// 会话未就绪(fd<0)时留守队列, 注册后由本函数按序出队; 保证缓存先于后续。
void FlushFrrReader(BgpReader& r) {
  if (r.fd < 0) return;                    // 未就绪: 字节留在 txq, 等注册
  if (r.txq.empty()) { if (r.evs != EPOLLIN) { r.evs = EPOLLIN; ModEventsFrr(r, EPOLLIN); } return; }
  size_t n = send_partial(r.fd, r.txq.data(), r.txq.size());
  r.txq.erase(0, n);
  if (r.txq.empty()) { r.evs = EPOLLIN; ModEventsFrr(r, EPOLLIN); }
  else ModEventsFrr(r, EPOLLIN | EPOLLOUT);
}
// 发送一条消息到 controller。一律入队 g_ctrl_tx 保序, 再调 FlushCtrlTx 出队;
// controller 未连接时也入队(接入后补发), 背压时由主线程 EPOLLOUT 续发, 不丢弃。
void SendMsg(uint16_t type, uint32_t src_ip, uint32_t dst_ip,
             uint32_t veth_idx, const void* payload, uint32_t plen) {
  vxdp::MsgHeader h{};
  h.magic = vxdp::MSG_MAGIC;
  h.version = vxdp::MSG_VERSION;
  h.type = type;
  h.src_router = g_router_id;
  h.dst_router = 0;
  h.src_ip = src_ip;
  h.dst_ip = dst_ip;
  h.veth_idx = veth_idx;
  h.len = plen;
  std::string wire(reinterpret_cast<const char*>(&h), sizeof(h));
  if (plen && payload) wire.append(reinterpret_cast<const char*>(payload), plen);

  g_ctrl_tx += wire;                       // 一律入队, 保序 + 缓存优先
  if (g_ctrl_fd < 0) return;               // controller 未连接: 留在队列, 接入后补发
  FlushCtrlTx();                           // 出队发送(唯一写 controller socket 的入口)
}

// BGP 报文类型名(offset 18), 用于收发调试日志
const char* BgpTypeName(uint8_t t) {
  switch (t) {
    case 1: return "OPEN";
    case 2: return "UPDATE";
    case 3: return "NOTIFICATION";
    case 4: return "KEEPALIVE";
    default: return "BGP?";
  }
}

// 读 FRR socket, 分帧出完整 BGP 报文转发 controller。返回 false = 连接已断。
bool ProcessBgpIn(BgpReader& r) {
  while (true) {
    char tmp[4096];
    ssize_t n = recv(r.fd, tmp, sizeof(tmp), 0);
    if (n > 0) { r.buf.append(tmp, n); r.rx_total += (uint64_t)n; }
    else if (n == 0) {
      Log("EOF frr_ip=" + vxdp::ipstr(r.frr_ip) + " fd=" + std::to_string(r.fd) +
          " 累计收=" + std::to_string(r.rx_total) + "B 最近类型=" +
          (r.last_type ? BgpTypeName(r.last_type) : "-") +
          " 待发积压=" + std::to_string(r.txq.size()) + "B");
      return false;
    }
    else {
      if (errno != EAGAIN && errno != EWOULDBLOCK) return false;
      break;
    }
  }
  size_t off = 0;
  while (r.buf.size() - off >= 19) {  // BGP 头: 16 marker + 2 len + 1 type
    uint16_t mlen = ((uint16_t)(uint8_t)r.buf[off + 16] << 8) |
                    ((uint16_t)(uint8_t)r.buf[off + 17]);
    uint8_t btype = (uint8_t)r.buf[off + 18];   // BGP type 字段(offset 18)
    r.last_type = btype;                       // 记录最近一条, 供 EOF 时判断
    Log("FRR->ctrl " + std::string(BgpTypeName(btype)) +
        " len=" + std::to_string(mlen));          // 收到(转发 controller)
    if (mlen < 19) return false;
    if (off + mlen > r.buf.size()) break;
    SendMsg(vxdp::MSG_BGP, r.frr_ip, r.fake_ip, r.veth_idx,
            r.buf.data() + off, mlen);
    off += mlen;
  }
  if (off > 0) r.buf.erase(0, off);
  return true;
}

// 注入一个原始以太帧到指定 veth(tx socket)。线程安全(互斥)。
void InjectFrame(int veth_idx, const char* frame, uint32_t len) {
  if (veth_idx < 1 || (size_t)veth_idx > g_raw_ifaces.size()) return;
  RawIface& it = g_raw_ifaces[veth_idx - 1];
  if (it.tx < 0) return;
  sockaddr_ll sll{};
  sll.sll_family = AF_PACKET;
  sll.sll_ifindex = it.ifindex;
  sll.sll_halen = ETH_ALEN;
  if (len >= 14) memcpy(sll.sll_addr, frame, ETH_ALEN);  // 帧的目的MAC(bytes 0-5)
  ::sendto(it.tx, frame, len, 0, reinterpret_cast<sockaddr*>(&sll), sizeof(sll));
}

// 按对端 frr IP(=fake_ip)定位 veth; 未找到返回 nullptr。
const VethCtx* FindVethByFake(uint32_t fake) {
  for (const auto& v : g_veths) if (v.fake_ip == fake) return &v;
  return nullptr;
}

// 低 id 侧: 非阻塞 connect 到某链路的本端 FRR(frr_ip:179); 完成后再登记为 FRR 会话。
void StartFrrDial(const VethCtx* v) {
  if (!v) return;
  if (g_frr_dial_connecting || g_frr_dial_fd >= 0) return;  // 已在拨/已连(回合串行)
  int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
  sockaddr_in dst{};
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = v->frr_ip;
  dst.sin_port = htons(179);
  int rc = ::connect(fd, reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
  if (rc != 0 && errno != EINPROGRESS) {
    Log("低id侧 dial FRR 立即失败(" + vxdp::ipstr(v->frr_ip) +
        "): " + std::string(strerror(errno)));
    close(fd);
    return;
  }
  epoll_event ev{}; ev.data.fd = fd; ev.events = EPOLLIN | EPOLLOUT;
  epoll_ctl(g_efd, EPOLL_CTL_ADD, fd, &ev);
  g_frr_dial_fd = fd;
  g_frr_dial_connecting = true;
  g_dial = v;
  Log("低id侧反向 dial FRR " + vxdp::ipstr(v->frr_ip) + ":179 fd=" + std::to_string(fd));
}

// 读 controller 消息。返回 true 表示控制连接真实关闭(需要拆除); EAGAIN 读完本批返回 false。
bool ProcessCtrlIn(std::string& b, std::unordered_map<uint32_t, BgpReader>& frr_sess,
                   std::unordered_map<int, uint32_t>& frr_by_fd) {
  while (true) {
    char tmp[4096];
    ssize_t n = recv(g_ctrl_fd, tmp, sizeof(tmp), 0);
    if (n > 0) b.append(tmp, n);
    else if (n == 0) { Log("controller 长连接关闭"); g_ctrl_fd = -1; return true; }
    else {
      if (errno != EAGAIN && errno != EWOULDBLOCK) { g_ctrl_fd = -1; return true; }
      break;
    }
  }
  size_t off = 0;
  while (b.size() - off >= sizeof(vxdp::MsgHeader)) {
    vxdp::MsgHeader h;
    memcpy(&h, b.data() + off, sizeof(h));
    if (h.magic != vxdp::MSG_MAGIC) { Log("控制通道 magic 错"); g_ctrl_fd = -1; return true; }
    size_t total = sizeof(h) + h.len;
    if (b.size() - off < total) break;
    if (h.type == vxdp::MSG_BGP) {
      // 按 dst_ip(frr_ip) 找到对应会话; 不存在则建 stub(fd=-1), 字节一并入其 txq。
      // 会话未就绪时字节留守队列, 注册后由 FlushFrrReader 按序出队, 缓存先于后续。
      uint32_t dst = h.dst_ip;
      auto it = frr_sess.find(dst);
      if (it == frr_sess.end())
        it = frr_sess.emplace(dst, BgpReader{}).first;
      BgpReader& sess = it->second;
      const char* p = b.data() + off + sizeof(h);
      if (h.len >= 19)
        Log("ctrl->FRR " + std::string(BgpTypeName((uint8_t)p[18])) +
            " len=" + std::to_string(h.len) +
            (sess.fd < 0 ? " [未就绪, 缓存]" : ""));  // 发往 FRR(中继方向)
      sess.txq.append(p, h.len);                     // 一律入队(保序 + 缓存优先)
      FlushFrrReader(sess);                          // 就绪即发; 未就绪留守队列
    } else if (h.type == vxdp::MSG_RAW) {
      InjectFrame(h.veth_idx, b.data() + off + sizeof(h), h.len);
    } else if (h.type == vxdp::MSG_CTRL_ESTABLISH) {
      // controller 仅在"本侧为该链路 low-id 侧"时发 ESTABLISH(指示 dial)。按
      // dst_ip(=对端 frr = 本侧 fake_ip) 定位具体链路, 对该链路拨本端 FRR。
      const VethCtx* v = FindVethByFake(h.dst_ip);
      if (v) {
        Log("受 ESTABLISH(链路 fake=" + vxdp::ipstr(v->fake_ip) +
            "): 主动 dial FRR " + vxdp::ipstr(v->frr_ip));
        StartFrrDial(v);
      } else {
        Log("受 ESTABLISH 但无匹配 veth(dst_ip=" + vxdp::ipstr(h.dst_ip) +
            "), 忽略");
      }
    } else if (h.type == vxdp::MSG_CTRL_OFFLINE) {
      // 优雅下线: 排空 g_ctrl_tx 后关写端(仍读); 之后新报文仍入队缓存, 重建后补发
      Log("受 OFFLINE: 排空待发 " + std::to_string(g_ctrl_tx.size()) +
          "B 后 shutdown 写端");
      FlushCtrlTx();
      g_ctrl_offline = true;
      shutdown(g_ctrl_fd, SHUT_WR);
      Log("已 offline: 关闭控制写端, 等待 controller 关闭连接");
    } else if (h.type == vxdp::MSG_CTRL_CLOSE) {
      // controller 要求关掉指定 FRR 会话(对端离线且 BGP 未 OPEN 时, 避免空等超时)
      uint32_t ip = h.dst_ip;
      auto it = frr_sess.find(ip);
      if (it != frr_sess.end() && it->second.fd >= 0) {
        int cfd = it->second.fd;
        Log("受 CLOSE: 关闭 FRR 会话 frr_ip=" + vxdp::ipstr(ip) +
            " fd=" + std::to_string(cfd));
        epoll_ctl(g_efd, EPOLL_CTL_DEL, cfd, nullptr);
        frr_by_fd.erase(cfd);
        it->second.fd = -1; it->second.evs = 0; it->second.buf.clear();
        if (cfd == g_frr_dial_fd) g_frr_dial_fd = -1;   // 允许重新 dial
        close(cfd);
      } else {
        Log("受 CLOSE: 会话不存在/未就绪, 忽略 frr_ip=" + vxdp::ipstr(ip));
      }
    }
    off += total;
  }
  if (off > 0) b.erase(0, off);
  return false;
}

// ---- AF_PACKET 读者线程: 读各 veth 上的非TCP单播帧 -> MSG_RAW
void HandleRawFrame(const char* buf, ssize_t n, RawIface& it, uint32_t vidx) {
  if (n < 14) return;                                // 连以太头都不够
  uint16_t etype = ((uint16_t)(uint8_t)buf[12] << 8) | (uint8_t)buf[13];
  // 仅对 IPv4 帧跳过 TCP(走 Phase1 的 BGP 专用中继); 其余帧(任意 ethertype、
  // 任意 dst MAC, 含 ARP/非TCP IP)一律作为裸包转发, 由对端做 MAC/路由决策。
  if (etype == 0x0800 && (uint8_t)buf[14 + 9] == IPPROTO_TCP) return;
  SendMsg(vxdp::MSG_RAW, it.frr_ip, it.fake_ip, vidx, buf, (uint32_t)n);
}

// 主线程: 把一个 raw 读 socket 上取到的帧收尽并转发(level-triggered, 收到 EAGAIN 为止)
void DrainRawIface(RawIface* it) {
  char buf[8192];
  sockaddr_ll fr{};
  socklen_t flen = sizeof(fr);
  while (true) {
    ssize_t len = recvfrom(it->rx, buf, sizeof(buf), 0,
                           reinterpret_cast<sockaddr*>(&fr), &flen);
    if (len < 0) { if (errno == EAGAIN || errno == EINTR) return; return; }
    if (fr.sll_pkttype == PACKET_OUTGOING) continue;  // 自己注入的回环, 丢弃
    uint32_t vidx = (uint32_t)(it - g_raw_ifaces.data()) + 1;
    HandleRawFrame(buf, len, *it, vidx);
  }
}

int main(int argc, char** argv) {
  std::string cfgpath = "agent.json";
  for (int i = 1; i < argc; i++)
    if (!strcmp(argv[i], "--config") && i + 1 < argc) cfgpath = argv[++i];
  json cfg;
  try {
    std::ifstream ifs(cfgpath);
    ifs >> cfg;
  } catch (...) { Log("无法读取配置: " + cfgpath); return 1; }
  g_router_id = cfg["router_id"].get<uint32_t>();
  g_peer_router_id = cfg.value("peer_router_id", 0);
  uint16_t ctrl_port = cfg.value("control_port", 9000);
  const json& veths = cfg["veths"];

  Log("启动 router_id=" + std::to_string(g_router_id) + " peer_router_id=" +
      std::to_string(g_peer_router_id) + " 控制端口=" +
      std::to_string(ctrl_port) + " veths=" + std::to_string(veths.size()));

  int ctrl_listener = MakeTcpListen(INADDR_ANY, ctrl_port);
  if (ctrl_listener < 0) { Log("控制端口监听失败"); return 2; }

  std::vector<int> bgp_listeners;
  for (const auto& v : veths) {
    uint32_t fake = vxdp::ipv4(v["fake_ip"].get<std::string>().c_str());
    int fd = MakeTcpListen(fake, 179);
    if (fd < 0) { Log("179 监听失败 " + std::string(v["fake_ip"])); return 3; }
    bgp_listeners.push_back(fd);
    Log("监听 " + std::string(v["fake_ip"]) + ":179");
  }

  // 初始化原始接口(Phase 2)
  for (const auto& v : veths) {
    RawIface r;
    r.name = v["veth_name"].get<std::string>();
    r.ifindex = if_nametoindex(r.name.c_str());
    r.mac = IfaceMac(r.name.c_str());
    r.fake_ip = vxdp::ipv4(v["fake_ip"].get<std::string>().c_str());
    r.frr_ip = vxdp::ipv4(v["frr_ip"].get<std::string>().c_str());
    // 注入用 tx socket (Phase 2 单 veth)
    r.tx = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    // 接收用 rx socket: 并入主线程 epoll, 由主循环统一 drain
    r.rx = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    sockaddr_ll sll{};
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = r.ifindex;
    if (bind(r.rx, reinterpret_cast<sockaddr*>(&sll), sizeof(sll)) != 0)
      Log("AF_PACKET bind 失败 " + r.name);
    SetNonblock(r.rx);
    g_raw_ifaces.push_back(r);
    // 记录本侧 veth 上下文(每条一个): 低 id 侧 dial、上报都按它 per-veth
    VethCtx vc;
    vc.frr_ip = r.frr_ip;
    vc.fake_ip = r.fake_ip;
    vc.veth_idx = (uint32_t)g_raw_ifaces.size();
    vc.peer_router_id = v.value("peer_router_id", 0u);
    g_veths.push_back(vc);
    Log("原始接口 " + r.name + " ifindex=" + std::to_string(r.ifindex));
  }

  int efd = epoll_create1(0);
  g_efd = efd;

  auto add = [&](int fd) {
    epoll_event ev{}; ev.data.fd = fd; ev.events = EPOLLIN;
    epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev);
  };
  auto del = [&](int fd) { epoll_ctl(efd, EPOLL_CTL_DEL, fd, nullptr); };
  add(ctrl_listener);
  for (int fd : bgp_listeners) add(fd);
  for (auto& it : g_raw_ifaces) if (it.rx >= 0) add(it.rx);   // 裸帧并入主循环

  std::unordered_map<uint32_t, BgpReader> frr_sess; // frr_ip -> 会话(持 txq, 跨重连保序)
  std::unordered_map<int, uint32_t> frr_by_fd;     // FRR socket fd -> frr_ip
  std::unordered_map<int, RawIface*> raw_by_fd;    // AF_PACKET rx fd -> iface
  for (auto& it : g_raw_ifaces) if (it.rx >= 0) raw_by_fd[it.rx] = &it;
  std::string ctrl_buf;

  while (true) {
    epoll_event evs[64];
    int n = epoll_wait(efd, evs, 64, -1);
    if (n < 0) { if (errno == EINTR) continue; break; }
    for (int i = 0; i < n; i++) {
      int fd = evs[i].data.fd;
      auto rit = raw_by_fd.find(fd);            // 裸帧可读: 收尽并转发
      if (rit != raw_by_fd.end() && (evs[i].events & EPOLLIN)) {
        DrainRawIface(rit->second);
        continue;
      }
      if (fd == ctrl_listener) {
        sockaddr_in pa{}; socklen_t pl = sizeof(pa);
        int c = accept(ctrl_listener, reinterpret_cast<sockaddr*>(&pa), &pl);
        if (c < 0) continue;
        SetNonblock(c); add(c);
        g_ctrl_fd = c;
        g_ctrl_evs = EPOLLIN;
        g_ctrl_offline = false;   // 新一轮连接(上线/重建)不再处于下线排空态
        Log("controller 拨号接入 ctrl_fd=" + std::to_string(c));
        FlushCtrlTx();   // 补发 controller 未连接期间积压的在途消息
        continue;
      }
      size_t li = bgp_listeners.size();
      for (size_t j = 0; j < bgp_listeners.size(); j++)
        if (bgp_listeners[j] == fd) { li = j; break; }
      if (li < bgp_listeners.size()) {
        sockaddr_in pa{}; socklen_t pl = sizeof(pa);
        int c = accept(fd, reinterpret_cast<sockaddr*>(&pa), &pl);
        if (c < 0) continue;
        SetNonblock(c);
        // router-id 规则: 该链路上本侧为低 id 侧时, 拒绝 FRR 的主动连接(立刻 close),
        // 改由本侧反向 dial FRR。按监听器索引 li 取对应 veth 的对端 rid 判定。
        uint32_t prid = (li < g_veths.size()) ? g_veths[li].peer_router_id : 0;
        if (prid > 0 && g_router_id < prid) {
          Log("低id侧(本 id " + std::to_string(g_router_id) + " < peer " +
              std::to_string(prid) + ") 拒绝 FRR 主动连接, 关闭");
          close(c);
          continue;
        }
        add(c);
        uint32_t ip = pa.sin_addr.s_addr;
        auto it = frr_sess.find(ip);
        if (it == frr_sess.end()) it = frr_sess.emplace(ip, BgpReader{}).first;
        BgpReader& sess = it->second;   // 复用会话: 续用上次遗留的 txq(缓存先于后续, 保序)
        sess.fd = c; sess.frr_ip = ip;
        sess.fake_ip = vxdp::ipv4(veths[li]["fake_ip"].get<std::string>().c_str());
        sess.veth_idx = (uint32_t)(li + 1);
        sess.evs = EPOLLIN;
        frr_by_fd[c] = ip;
        Log("FRR 接入(高id侧) frr_ip=" + vxdp::ipstr(ip));
        SendMsg(vxdp::MSG_CTRL_UP, ip, sess.fake_ip, sess.veth_idx, nullptr, 0);
        FlushFrrReader(sess);   // 补发未就绪期间缓存的字节(高 id 侧也 flush, 保序)
        continue;
      }
      if (fd == g_frr_dial_fd && g_frr_dial_connecting) {  // 低 id 侧 dial FRR 完成?
        int soerr = 0; socklen_t sl = sizeof(soerr);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl);
        g_frr_dial_connecting = false;
        const VethCtx* v = g_dial; g_dial = nullptr;
        if (soerr == 0 && v) {
          auto it = frr_sess.find(v->frr_ip);
          if (it == frr_sess.end()) it = frr_sess.emplace(v->frr_ip, BgpReader{}).first;
          BgpReader& sess = it->second;   // 复用会话, 续用 ctx txq
          sess.fd = fd; sess.frr_ip = v->frr_ip; sess.fake_ip = v->fake_ip;
          sess.veth_idx = v->veth_idx; sess.evs = EPOLLIN;
          epoll_event ev{}; ev.data.fd = fd; ev.events = EPOLLIN;
          epoll_ctl(efd, EPOLL_CTL_MOD, fd, &ev);
          frr_by_fd[fd] = v->frr_ip;
          Log("低id侧 dial FRR 成功 frr_ip=" + vxdp::ipstr(v->frr_ip) + " fd=" +
              std::to_string(fd));
          SendMsg(vxdp::MSG_CTRL_UP, v->frr_ip, v->fake_ip, v->veth_idx, nullptr, 0);
          FlushFrrReader(sess);   // flush 未就绪期间缓存的 MSG_BGP(不丢, 保序)
        } else {
          Log("低id侧 dial FRR 失败: " + std::string(strerror(soerr)) + ", 稍后重试");
          del(fd); close(fd); g_frr_dial_fd = -1;
        }
        continue;
      }
      if (g_ctrl_fd >= 0 && fd == g_ctrl_fd) {        // 控制连接: 读 + 续发
        if (evs[i].events & EPOLLOUT) FlushCtrlTx();   // 控制连接可写: 续发积压
        if (evs[i].events & EPOLLIN) {
          bool closed = ProcessCtrlIn(ctrl_buf, frr_sess, frr_by_fd);
          if (closed) {                                 // 仅真实关闭才拆除
            del(fd);
            g_ctrl_fd = -1;
            g_ctrl_evs = 0;
            ctrl_buf.clear();
          }
        }
        continue;
      }
      auto fit = frr_by_fd.find(fd);
      if (fit != frr_by_fd.end()) {
        BgpReader& sess = frr_sess[fit->second];
        if (evs[i].events & EPOLLOUT) FlushFrrReader(sess);  // 发给 FRR 的积压续发
        if (evs[i].events & EPOLLIN) {
          if (!ProcessBgpIn(sess)) {
            del(fd);
            frr_by_fd.erase(fd);
            sess.fd = -1; sess.evs = 0; sess.buf.clear();   // 保留 txq: 下次注册续发(保序)
            if (fd == g_frr_dial_fd) g_frr_dial_fd = -1;    // 允许重新 dial
          }
        }
        continue;
      }
    }
  }
  return 0;
}