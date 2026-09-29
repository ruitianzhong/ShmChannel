// controller: 运行在 host 的定制数据面控制器(Phase 1 + 3 多线程)。
// Phase 1:
//   1. 按 controller.json 对每个 router 的 agent 拨号(vm_ip:control_port), 建长连接;
//   2. 维护 frr_ip -> router/conn 映射与 links(IP 对);
//   3. 转发 MSG_BGP 与 MSG_RAW: 按 dst_ip 找到所属 router 的 agent 连接转发;
//   4. 会话拼接: 一条 link 两端都上报 UP 后, 向 higher router_id 侧发 ESTABLISH;
//   5. 连接断开自动重连; 全程充分打 log 便于验证。
// Phase 3(多线程 epoll):
//   线程 = router_id % workers。每个 worker 线程独立 epoll 处理属于它的 agent 长连接
//   (拨号、重连、读、转发)。全局 g_reg(frr_ip->Peer) 在每个 worker 维护,
//   mutex 保护; 跨线程转发只做 send(epoll 注册只在其属主线程)。
#include "core.h"                    // Router/Link 结构 + 共享状态
#include "ctl.h"                     // 命令服务接口(本文件 main 触发其线程)
#include "../common/protocol.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <condition_variable>
#include <cstring>
#include <cstdio>
#include <fstream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "../common/json.hpp"
using json = nlohmann::json;

std::string NowStr() {
  char buf[40];
  time_t t = time(nullptr);
  struct tm tm;
  localtime_r(&t, &tm);
  strftime(buf, sizeof(buf), "%H:%M:%S", &tm);
  return std::string(buf);
}
void Log(const std::string& s) {
  fprintf(stdout, "%s [controller] %s\n", NowStr().c_str(), s.c_str());
  fflush(stdout);
}

// Router/Link 结构体定义在 ctl.h(需跨 ctl 服务共享)

static std::mutex g_reg_mtx;                            // 保护 g_reg(仅本文件用)
std::unordered_map<uint32_t, Router*> g_reg;            // frr_ip -> router(启动即全登记)
int g_router_count = 0;                                  // distinct router 数(ping 上报; 不为 frr 地址数)
// ---- 全局 quiescent 状态: 最近一次中继 MSG_BGP 的时间戳(原子, quiescent 轮询读) ----
std::atomic<long> g_last_bgp_ms{0};
// ---- ctl 线程 <-> worker 的排空/上线结果通知 ----
std::mutex g_ctl_mtx;
std::condition_variable g_ctl_cv;

long NowMs() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// 非阻塞发送, 返回实际发送的字节数(遇 EAGAIN/错误即停, 不阻塞)
size_t send_partial(int fd, const char* data, size_t len) {
  size_t sent = 0;
  while (sent < len) {
    ssize_t w = ::send(fd, data + sent, len - sent, MSG_NOSIGNAL);
    if (w > 0) sent += (size_t)w;
    else break;  // EAGAIN / EWOULDBLOCK / 其它错误 -> 停
  }
  return sent;
}

// 把消息头+负载序列化为线序字节
std::string MsgWire(const vxdp::MsgHeader& h, const char* payload) {
  std::string wire;
  wire.assign(reinterpret_cast<const char*>(&h), sizeof(h));
  if (h.len && payload) wire.append(payload, h.len);
  return wire;
}

// 属主线程在它自己的 epoll 上把某连接的监听事件改成 events(level-triggered,
// 队列空时必须去掉 EPOLLOUT 否则 busy-loop)。
void ModEvents(Router* r, uint32_t events) {
  if (r->ev_events == events) return;
  epoll_event ev{}; ev.data.fd = r->fd; ev.events = events;
  epoll_ctl(r->owner_efd, EPOLL_CTL_MOD, r->fd, &ev);
  r->ev_events = events;
}

// 分发 vxdp 消息到目标连接(可能跨线程)。绝不丢弃: 一律入队 txbuf 保序,
// 再唤醒属主线程由 FlushRouter 出队发送。目标未就绪/背压时字节留守队列,
// (重)连后先于后续字节发出(缓存优先, 保序)。此函数不做任何内联 send。
void SendToRouter(Router* r, const vxdp::MsgHeader& h, const char* payload) {
  if (!r) return;
  std::string wire;
  wire.assign(reinterpret_cast<const char*>(&h), sizeof(h));
  if (h.len && payload) wire.append(payload, h.len);

  std::lock_guard<std::mutex> lk(r->tx_mtx);
  r->txbuf += wire;                        // 一律入队: 保序 + 未就绪/背压都缓存优先
  r->need_epollout = true;
  uint64_t one = 1;
  ssize_t wr = ::write(r->owner_wake, &one, sizeof(one));   // 唤醒属主去 flush
  // EAGAIN = eventfd 计数器已非 0, 即有 pending 唤醒: 良性, 属主稍后必到, 不丢数据;
  // 其它错误(如 eventfd fd 无效)属编程/环境异常, 记日志便于排障。
  if (wr < 0 && errno != EAGAIN)
    Log("唤醒 " + r->name + " flush 写 eventfd 失败: " + std::string(strerror(errno)));
}

// 属主线程: 把某连接积压的 txbuf 尽量发出去; 发完则去掉 EPOLLOUT, 否则保持。
void FlushRouter(Router* r) {
  std::lock_guard<std::mutex> lk(r->tx_mtx);
  int fd = r->fd;
  if (fd < 0) return;                      // 未就绪: 字节留在 txbuf, 等(重)连后按序出队
  if (r->txbuf.empty()) { r->need_epollout = false; ModEvents(r, EPOLLIN); return; }
  size_t n = send_partial(fd, r->txbuf.data(), r->txbuf.size());
  r->txbuf.erase(0, n);
  if (r->txbuf.empty()) { r->need_epollout = false; ModEvents(r, EPOLLIN); }
  else ModEvents(r, EPOLLIN | EPOLLOUT);
}

bool HasPending(Router* r) {
  std::lock_guard<std::mutex> lk(r->tx_mtx);
  return r->need_epollout;
}

// 打开到某 router agent 的非阻塞连接 socket
int OpenConn(Router& r, int efd, uint16_t ctrl_port) {
  uint16_t port = r.port ? r.port : ctrl_port;  // 每 router 可覆盖, 否则全局
  int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
  sockaddr_in self{};
  self.sin_family = AF_INET;
  self.sin_addr.s_addr = vxdp::ipv4(r.dial_ip.c_str());
  bind(fd, reinterpret_cast<sockaddr*>(&self), sizeof(self));
  sockaddr_in dst{};
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = vxdp::ipv4(r.vm_ip.c_str());
  dst.sin_port = htons(port);
  ::connect(fd, reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
  epoll_event ev{}; ev.data.fd = fd; ev.events = EPOLLIN | EPOLLOUT;
  epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev);
  r.fd = fd;
  r.connecting = true;
  r.ev_events = EPOLLIN | EPOLLOUT;
  r.need_epollout = false;   // 不清理 txbuf: 留存的缓存字节在连接就绪后按序补发(保序)
  return fd;
}

// g_reg 在启动时即登记全部 router(fd 初值 -1), 故 LookupConn 恒能找到 Router*;
// 是否已连接看 router->fd (>=0 且 !connecting 才算可用)。Register/Unregister 仅打日志。
void RegisterConn(Router& r) { (void)r; }
void UnregisterConn(const Router& r) { (void)r; }
Router* LookupConn(uint32_t frr_ip) {
  std::lock_guard<std::mutex> lk(g_reg_mtx);
  auto it = g_reg.find(frr_ip);
  return it == g_reg.end() ? nullptr : it->second;
}
bool ConnReady(const Router* r) { return r && r->fd >= 0 && !r->connecting; }
Router* LookupById(uint32_t id) {   // 按 router id 找连接(用于 ESTABLISH 主动侧)
  std::lock_guard<std::mutex> lk(g_reg_mtx);
  for (auto& kv : g_reg) if (kv.second->id == id) return kv.second;
  return nullptr;
}

// 处理该 worker 属主 router 的一条消息
void HandleMsg(Router& r, const vxdp::MsgHeader& h, const char* payload,
               std::vector<Link>& links) {
  if (h.type == vxdp::MSG_CTRL_UP) {
    Log("会话 UP " + r.name + ": frr_ip=" + vxdp::ipstr(h.src_ip) +
        " fake_ip=" + vxdp::ipstr(h.dst_ip) + " veth_idx=" +
        std::to_string(h.veth_idx));
    for (const Link& L : links) {
      if (h.src_ip != L.ip_a && h.src_ip != L.ip_b) continue;
      uint32_t other = (h.src_ip == L.ip_a) ? L.ip_b : L.ip_a;
      // 对端没启动/被标记离线: 这条会话对端永远不回 OPEN, 立即关闭上报侧,
      // 不保活(未到 OPEN, 无需 keepalive); 对端恢复上线后经正常流程再拉起。
      Router* peer = LookupConn(other);
      if (!peer || peer->admin_offline) {
        vxdp::MsgHeader c{};
        c.magic = vxdp::MSG_MAGIC; c.version = vxdp::MSG_VERSION;
        c.type = vxdp::MSG_CTRL_CLOSE; c.dst_ip = h.src_ip; c.len = 0;
        SendToRouter(&r, c, nullptr);
        Log("UP " + r.name + " 但对端 " + vxdp::ipstr(other) +
            " 不在线: 立即 CLOSE 关闭该 FRR 会话, 不保活");
        continue;
      }
      uint32_t other_rid = (other == L.ip_a) ? L.rid_a : L.rid_b;
      uint32_t hi = std::max(r.id, other_rid);
      uint32_t lo = std::min(r.id, other_rid);
      // 仅当"高 id 侧上报 UP"时, 向低 id 侧发 ESTABLISH(指示它 dial FRR)。
      // 低 id 侧 agent 若尚未连上: SendToRouter 会缓冲, 待其连接后补发(时序自洽)。
      if (r.id != hi) continue;
      Router* loR = LookupById(lo);
      if (loR) {
        vxdp::MsgHeader est{};
        est.magic = vxdp::MSG_MAGIC; est.version = vxdp::MSG_VERSION;
        est.type = vxdp::MSG_CTRL_ESTABLISH;
        est.src_router = hi; est.dst_router = hi;
        est.src_ip = h.src_ip; est.dst_ip = h.src_ip; est.len = 0;
        SendToRouter(loR, est, nullptr);
        Log("拼接 link " + vxdp::ipstr(L.ip_a) + "<->" + vxdp::ipstr(L.ip_b) +
            ": 向 LOW-id " + std::to_string(lo) + " 发 ESTABLISH(指示 dial FRR)" +
            (ConnReady(loR) ? "" : " [低侧未就绪, 缓冲]"));
      }
    }
  } else if (h.type == vxdp::MSG_BGP || h.type == vxdp::MSG_RAW) {
    const char* ty = (h.type == vxdp::MSG_BGP) ? "MSGBGP" : "MSGRAW";
    // 按 dst_ip 路由; MSG_RAW 的 dst_ip 是 veth 的 fake_ip(对端 frr 源)。
    // dst 未连接时 SendToRouter 会缓冲, 待其连接后 flush(不丢包)。
    Router* dst = LookupConn(h.dst_ip);
    if (dst) {
      // 建会话期不变量: 链路未 OPEN 时, 除 OPEN/NOTIFICATION 外其他 BGP 帧一律丢弃
      // (不缓存, 免污染新握手); 对端离线且未 OPEN 时连 OPEN 也丢(重建会重发)。
      // MSG_RAW 是数据面帧(ARP/ICMP), 与 BGP 会话态无关, 不受此闸门约束。
      bool drop_stale = false;
      uint8_t btyp = 0;
      if (h.type == vxdp::MSG_BGP && h.len >= 19) {
        btyp = (uint8_t)payload[18];
        bool allowance = (btyp == 1 || btyp == 3);   // OPEN / NOTIFICATION 放行
        std::lock_guard<std::mutex> lk(g_ctl_mtx);
        for (Link& L : links) {
          bool hit = (h.src_ip == L.ip_a && h.dst_ip == L.ip_b) ||
                     (h.src_ip == L.ip_b && h.dst_ip == L.ip_a);
          if (hit) {
            if (!L.open) {                          // 链路尚未 OPEN -> 建会话期
              if (!allowance) drop_stale = true;                     // 非建立帧: 丢
              else if (btyp == 1 && dst->admin_offline)              // OPEN 到离线对端: 丢
                drop_stale = true;
            }
            break;
          }
        }
      }
      if (drop_stale) {
        Log("丢弃 未OPEN链路建立期垃圾 src=" + vxdp::ipstr(h.src_ip) +
            " dst=" + vxdp::ipstr(h.dst_ip) + " type=" + std::to_string(btyp));
      } else {
        SendToRouter(dst, h, payload);
        Log("RX " + std::string(ty) + " src=" + vxdp::ipstr(h.src_ip) +
            " dst=" + vxdp::ipstr(h.dst_ip) + " len=" + std::to_string(h.len) +
            " (from " + r.name + ")" +
            (dst->admin_offline ? " [目标离线, 已缓存]"
                                : (ConnReady(dst) ? "" : " [目标未就绪, 缓冲]")));
        if (h.type == vxdp::MSG_BGP) {
          g_last_bgp_ms = NowMs();   // 供 quiescent 命令轮询判断全局静默
          // P3: 追踪该 link 的 BGP OPEN 态(见到 OPEN->Established, NOTIFICATION->复位)
          if (h.len >= 19) {
            uint8_t btyp = (uint8_t)payload[18];
            for (Link& L : links) {
              bool hit = (h.src_ip == L.ip_a && h.dst_ip == L.ip_b) ||
                         (h.src_ip == L.ip_b && h.dst_ip == L.ip_a);
              if (hit) {
                std::lock_guard<std::mutex> lk(g_ctl_mtx);
                if (btyp == 1) L.open = true;
                else if (btyp == 3) L.open = false;
                break;
              }
            }
          }
        }
      }
    } else {
      Log(std::string(ty) + " 未知 dst_ip=" + vxdp::ipstr(h.dst_ip));
    }
  } else if (h.type == vxdp::MSG_CTRL_CLOSE) {
    Log("收到拒绝/CLOSE 来自 " + r.name);
  }
}

void WorkerLoop(std::vector<Router*>& rlist, std::vector<Link>& links,
                uint16_t ctrl_port) {
  int efd = epoll_create1(0);
  int wake_fd = eventfd(0, EFD_NONBLOCK);
  epoll_event wev{}; wev.data.fd = wake_fd; wev.events = EPOLLIN;
  epoll_ctl(efd, EPOLL_CTL_ADD, wake_fd, &wev);

  auto findR = [&](int fd) -> Router* {
    for (Router* rp : rlist) if (rp->fd == fd) return rp;
    return nullptr;
  };
  // 记录属主信息, 供跨线程发送方唤醒 flush
  for (Router* rp : rlist) {
    rp->owner_efd = efd;
    rp->owner_wake = wake_fd;
    rp->ev_events = EPOLLIN | EPOLLOUT;
  }
  // 排空收尾: 发完剩余 txbuf 后 SHUT_WR 并关连接(agent 半关后补发内容, 不丢缓存)
  auto FinishDrain = [&](Router* r, int fd) {
    FlushRouter(r);                       // 把剩余缓存字节尽量发出去
    shutdown(fd, SHUT_WR);
    epoll_ctl(efd, EPOLL_CTL_DEL, fd, nullptr);
    close(fd); UnregisterConn(*r); r->fd = -1; r->buf.clear();
    r->ev_events = 0; r->need_epollout = false; r->connecting = false;
    r->draining = false;
    { std::lock_guard<std::mutex> lk(g_ctl_mtx); r->drained = true; }
    g_ctl_cv.notify_all();
    Log("下线 " + r->name + " 排空完成: 已发尽剩余缓存, 关闭 fd=" + std::to_string(fd));
  };
  // 消费 ctl 线程置的 offline(位1)/online(位2) 请求(见 wake_fd 处理)
  auto ProcessCtlAction = [&](Router* r) {
    int act; { std::lock_guard<std::mutex> lk(g_ctl_mtx); act = r->ctl_action; r->ctl_action = 0; }
    if (act & 1) {                        // offline
      if (ConnReady(r)) {
        vxdp::MsgHeader o{};
        o.magic = vxdp::MSG_MAGIC; o.version = vxdp::MSG_VERSION;
        o.type = vxdp::MSG_CTRL_OFFLINE; o.dst_router = r->id;
        { std::lock_guard<std::mutex> lk(r->tx_mtx); r->txbuf += MsgWire(o, nullptr); }
        r->draining = true;
        FlushRouter(r);
        Log("下线 " + r->name + " 请求: 已通知 agent 排空, 等待其半关");
      } else {                            // 无存活连接: 无连接可排, 直接视为完成
        { std::lock_guard<std::mutex> lk(g_ctl_mtx); r->drained = true; }
        g_ctl_cv.notify_all();
        Log("下线 " + r->name + ": agent 未连接, 直接完成");
      }
    }
    if (act & 2) {                        // online
      if (ConnReady(r)) {
        { std::lock_guard<std::mutex> lk(g_ctl_mtx); r->ctl_up = true; }
        g_ctl_cv.notify_all();
        Log("上线 " + r->name + ": 已连接, 直接就绪");
      } else if (r->fd < 0 && !r->connecting) {
        r->next_try_ms = 0;               // 让重连循环立刻拉起
        Log("上线 " + r->name + ": 触发立即重拨");
      }
    }
  };
  // 初始拨号, 把本 worker 的 router 全部拉开(admin_offline 的期望离线节点不拨)
  for (Router* rp : rlist) {
    if (rp->admin_offline) { Log("初始跳过(默认离线) " + rp->name); continue; }
    Log("拨号 " + rp->name + "(" + rp->vm_ip + "->" + rp->dial_ip +
        ") dst router_id=" + std::to_string(rp->id));
    OpenConn(*rp, efd, ctrl_port);
  }
  while (true) {
    // 重连欠着的
    long now = NowMs();
    for (Router* rp : rlist)
      if (!rp->admin_offline && rp->fd < 0 && now >= rp->next_try_ms) {
        rp->next_try_ms = now + 2000;
        Log("重连 " + rp->name);
        OpenConn(*rp, efd, ctrl_port);
      }
    epoll_event evs[64];
    int n = epoll_wait(efd, evs, 64, 500);
    for (int i = 0; i < n; i++) {
      int fd = evs[i].data.fd;
      if (fd == wake_fd) {                 // 被跨线程唤醒: 处理 ctl 请求 + flush 有积压的连接
        uint64_t b[16];
        while (read(wake_fd, b, sizeof(b)) > 0) {}
        for (Router* rp : rlist) {
          if (rp->ctl_action) ProcessCtlAction(rp);
          if (HasPending(rp)) FlushRouter(rp);
        }
        continue;
      }
      Router* r = findR(fd);
      if (!r) continue;

      if (r->connecting) {                 // connect 完成(EPOLLOUT)或失败(EPOLLERR)
        int soerr = 0; socklen_t sl = sizeof(soerr);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl);
        if (soerr == 0) {
          if (r->admin_offline) {          // 期望离线: 刚连上也不要拉起, 直接关
            epoll_ctl(efd, EPOLL_CTL_DEL, fd, nullptr);
            close(fd); r->fd = -1; r->connecting = false; r->ev_events = 0;
            { std::lock_guard<std::mutex> lk(g_ctl_mtx); r->drained = true; }
            g_ctl_cv.notify_all();
            continue;
          }
          r->connecting = false;
          ModEvents(r, EPOLLIN);
          RegisterConn(*r);
          Log("agent 已连接 " + r->name + "(router_id=" + std::to_string(r->id) +
              ") fd=" + std::to_string(fd));
          if (!r->txbuf.empty()) FlushRouter(r);   // 补发未就绪期间缓冲的消息
          { std::lock_guard<std::mutex> lk(g_ctl_mtx); r->ctl_up = true; }
          g_ctl_cv.notify_all();
          // 注意: 此处不再盲补 ESTABLISH。低 id 侧必须在"高 id 侧 FRR 会话就绪
          // (上报 UP)"之后才 dial FRR, 否则会过早建起、造成两侧会话时差与乱序。
          // Controller 只在高侧 UP 时经 HandleMsg 发 ESTABLISH; 低侧当时未连接则
          // 由 SendToRouter 缓冲、本处 FlushRouter 连上后补送(仍保证其必达)。
        } else {
          Log("连接失败 " + r->name + ": " + strerror(soerr) + ", 稍后重连");
          epoll_ctl(efd, EPOLL_CTL_DEL, fd, nullptr);
          close(fd); r->fd = -1; r->connecting = false; r->ev_events = 0;
          r->next_try_ms = NowMs() + 2000;
        }
        continue;
      }

      if (evs[i].events & (EPOLLHUP | EPOLLERR)) {
        if (r->draining) { FinishDrain(r, fd); continue; }
        Log("agent 断开 " + r->name + ", 触发重连");
        epoll_ctl(efd, EPOLL_CTL_DEL, fd, nullptr);
        close(fd); UnregisterConn(*r); r->fd = -1; r->buf.clear();
        r->ev_events = 0; r->need_epollout = false;   // 不清理 txbuf: 缓存字节在重连后按序补发
        if (!r->admin_offline) r->next_try_ms = NowMs() + 1500;
        continue;
      }

      if (evs[i].events & EPOLLOUT) FlushRouter(r);  // 发送缓冲可写: 续发积压

      if (evs[i].events & EPOLLIN) {
        char tmp[8192];
        ssize_t got;
        while ((got = recv(fd, tmp, sizeof(tmp), 0)) > 0) r->buf.append(tmp, got);
        if (got == 0 || (got < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
          if (r->draining) { FinishDrain(r, fd); continue; }  // agent 半关(EOF): 收尾排空
          epoll_ctl(efd, EPOLL_CTL_DEL, fd, nullptr);
          close(fd); UnregisterConn(*r); r->fd = -1; r->buf.clear();
          r->ev_events = 0; r->need_epollout = false;   // 不清理 txbuf: 缓存字节在重连后按序补发
          if (!r->admin_offline) r->next_try_ms = NowMs() + 1500;
          continue;
        }
        // 分帧处理
        size_t off = 0;
        while (r->buf.size() - off >= sizeof(vxdp::MsgHeader)) {
          vxdp::MsgHeader h;
          memcpy(&h, r->buf.data() + off, sizeof(h));
          if (h.magic != vxdp::MSG_MAGIC) { r->buf.clear(); break; }
          size_t total = sizeof(h) + h.len;
          if (r->buf.size() - off < total) break;
          HandleMsg(*r, h, r->buf.data() + off + sizeof(h), links);
          off += total;
        }
        if (off > 0) r->buf.erase(0, off);
      }
    }
  }
}

// P3: 周期扫描 link, 处理"一端在线一端离线"的 BGP 会话策略:
//   link 已 OPEN(Established) -> 向在线侧注入 KEEPALIVE 保活, 免其随对端离线而超时 teardown;
//   link 未 OPEN           -> 令在线侧关闭其 FRR 会话, 避免空等超时。
// 每 30s 跑一趟; 对端同样离线(双边状态一致)的 link 跳过。
// 只在锁内读 `L.open`/`admin_offline` 并决定动作; 查表/发送/日志都放到锁外。
void KeepaliveThread(std::vector<Link>& links) {
  while (true) {
    std::this_thread::sleep_for(std::chrono::milliseconds(30000));
    struct Act { Router* R; bool open; uint32_t offline_ip, online_ip; std::string name; };
    std::vector<Act> acts;
    for (const Link& L : links) {
      Router* ra = LookupConn(L.ip_a);            // 锁外: LookupConn 内锁 g_reg_mtx
      Router* rb = LookupConn(L.ip_b);
      if (!ra || !rb) continue;
      bool oa, ob; bool open;
      {
        std::lock_guard<std::mutex> lk(g_ctl_mtx);   // 仅保护 admin_offline / open 两下读
        oa = ra->admin_offline; ob = rb->admin_offline;
        open = L.open;
      }
      if (oa == ob) continue;                     // 双边同状态(都在/都不在)不处理
      acts.push_back({oa ? rb : ra, open,          // 在线侧
                      oa ? L.ip_a : L.ip_b,        // 离线侧 frr ip(保活时作源)
                      oa ? L.ip_b : L.ip_a,        // 在线侧 frr ip(保活时作目的)
                      (oa ? rb : ra)->name});
    }
    for (const Act& a : acts) {                   // 锁外执行动作(发送/日志)
      if (a.open) {
        char ka[19]; memset(ka, 0xFF, 16);
        ka[16] = 0x00; ka[17] = 0x13; ka[18] = 0x04;  // len=19, type=KEEPALIVE
        vxdp::MsgHeader h{};
        h.magic = vxdp::MSG_MAGIC; h.version = vxdp::MSG_VERSION;
        h.type = vxdp::MSG_BGP; h.src_ip = a.offline_ip; h.dst_ip = a.online_ip; h.len = 19;
        SendToRouter(a.R, h, ka);
        Log("对端离线且 OPEN: 向 " + a.name + " 注入 KEEPALIVE(" + vxdp::ipstr(a.offline_ip) +
            "->" + vxdp::ipstr(a.online_ip) + ") 保活");
      } else {
        vxdp::MsgHeader h{};
        h.magic = vxdp::MSG_MAGIC; h.version = vxdp::MSG_VERSION;
        h.type = vxdp::MSG_CTRL_CLOSE; h.dst_ip = a.online_ip; h.len = 0;
        SendToRouter(a.R, h, nullptr);
        Log("对端离线且未 OPEN: 令 " + a.name + " 关闭 FRR 会话(" + vxdp::ipstr(a.online_ip) + ")");
      }
    }
  }
}

int main(int argc, char** argv) {
  std::string cfgpath = "controller.json";
  for (int i = 1; i < argc; i++)
    if (!strcmp(argv[i], "--config") && i + 1 < argc) cfgpath = argv[++i];
  json cfg;
  try {
    std::ifstream ifs(cfgpath);
    ifs >> cfg;
  } catch (...) { Log("无法读取配置: " + cfgpath); return 1; }
  uint16_t ctrl_port = cfg.value("control_port", 9000);
  int workers = cfg.value("workers", 2);
  std::string ctl_socket = cfg.value("ctl_socket", std::string("/tmp/controller.ctl"));
  g_last_bgp_ms = NowMs();   // 冷启动: 开机即视为"最后静默时刻"(无 BGP 时 quiescent 快速返回)

  std::vector<std::unique_ptr<Router>> routers;
  for (const auto& r : cfg["routers"]) {
    auto up = std::make_unique<Router>();
    up->id = r["id"].get<uint32_t>();
    up->name = r["name"].get<std::string>();
    up->vm_ip = r["vm_ip"].get<std::string>();
    up->dial_ip = r.value("dial_ip", cfg["listen_ip"].get<std::string>());
    // frr_ip 支持单字符串(一节点一地址)或数组(多邻居: 同一 Router 多个本端 frr 地址)
    up->frr_ips.clear();
    if (r["frr_ip"].is_array()) {
      for (const auto& ip : r["frr_ip"])
        up->frr_ips.push_back(vxdp::ipv4(ip.get<std::string>().c_str()));
      up->frr_ip = up->frr_ips.empty() ? 0 : up->frr_ips[0];
    } else {
      up->frr_ip = vxdp::ipv4(r["frr_ip"].get<std::string>().c_str());
      up->frr_ips.push_back(up->frr_ip);
    }
    up->port = r.value("port", 0);   // 0=用全局 control_port
    routers.push_back(std::move(up));
  }
  std::unordered_map<uint32_t, uint32_t> rid_by_ip;
  for (const auto& r : routers)
    for (uint32_t ip : r->frr_ips) rid_by_ip[ip] = r->id;
  std::vector<Link> links;
  for (const auto& l : cfg["links"]) {
    Link x;
    x.ip_a = vxdp::ipv4(l["ip_a"].get<std::string>().c_str());
    x.ip_b = vxdp::ipv4(l["ip_b"].get<std::string>().c_str());
    x.rid_a = rid_by_ip[x.ip_a];
    x.rid_b = rid_by_ip[x.ip_b];
    links.push_back(x);
  }

  // admin_default_online: 启动即期望在线的 router id 集合。仅当非空时当作白名单,
  // 不在集合的默认离线; 缺省/空则所有节点默认在线(同时上线)。
  std::vector<uint32_t> online_default;
  if (cfg.contains("admin_default_online")) {
    for (const auto& v : cfg["admin_default_online"]) online_default.push_back(v.get<uint32_t>());
  }
  if (!online_default.empty()) {
    for (auto& rr : routers) {
      bool in_default = false;
      for (uint32_t id : online_default) if (id == rr->id) { in_default = true; break; }
      rr->admin_offline = !in_default;
    }
  }
  g_router_count = (int)routers.size();
  Log("controller 启动 routers=" + std::to_string(routers.size()) +
      " links=" + std::to_string(links.size()) + " workers=" + std::to_string(workers) +
      " default_online=" + std::to_string(online_default.size()));

  // 启动即登记全部 router 的全部 frr 地址(fd 初值 -1): LookupConn 恒可解析到
  // Router*, 未连接时可缓冲; 多邻居时同一 Router 在 g_reg 有多个别名
  for (auto& rr : routers)
    for (uint32_t ip : rr->frr_ips) g_reg[ip] = rr.get();

  // 按 router_id % workers 把 router 分到各 worker(Router 含 mutex, 存指针)
  std::vector<std::vector<Router*>> buckets(workers);
  for (auto& rr : routers) buckets[rr->id % workers].push_back(rr.get());

  std::vector<std::thread> ths;
  for (int w = 0; w < workers; w++) {
    ths.emplace_back(WorkerLoop, std::ref(buckets[w]), std::ref(links), ctrl_port);
    Log("worker#" + std::to_string(w) + " 分到 routers=" +
        std::to_string(buckets[w].size()));
  }
  std::thread ka(KeepaliveThread, std::ref(links));   // P3: 单边离线熵 BGP 保活/关会话

  // 主线程持有 ctl 命令服务(阻塞); workers/keepalive 在后台线程跑
  CtlService(ctl_socket);
  for (auto& t : ths) t.join();
  return 0;
}