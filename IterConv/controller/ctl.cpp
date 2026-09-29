// controller 的 unix 命令服务: vm.py(iter)经此调用 offline/online/quiescent。
// 命令服务本体在此独立翻译单元; 共享 Router/Link 结构与全局状态见 core.h。
#include "ctl.h"
#include "core.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <mutex>
#include <sstream>
#include <thread>

#include "../common/json.hpp"
using json = nlohmann::json;

// 应答一条命令(循环发尽 + 失败记日志, 避免应答破帧)
static void CtlReply(int conn, json j) {
  std::string s = j.dump() + "\n";
  size_t sent = 0;
  while (sent < s.size()) {
    ssize_t w = ::send(conn, s.data() + sent, s.size() - sent, MSG_NOSIGNAL);
    if (w <= 0) {
      Log("ctl 应答发送失败(" + std::string(strerror(errno)) + "), 丢弃应答");
      break;
    }
    sent += (size_t)w;
  }
}

// 等地(worker 侧)把某 router 的标志位置位, 带超时(毫秒), 返回是否等到。
static bool WaitRouterFlag(Router* r, bool Router::*fld, int timeout_ms) {
  auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
  std::unique_lock<std::mutex> lk(g_ctl_mtx);
  while (!(r->*fld) && std::chrono::steady_clock::now() < until)
    g_ctl_cv.wait_until(lk, until);
  return r->*fld;
}

// 唤醒属主 worker 处理 r 的 ctl_action(靠 owner_wake eventfd)
static void WakeWorker(Router* r) {
  uint64_t one = 1;
  if (r->owner_wake >= 0) { ssize_t wr = ::write(r->owner_wake, &one, sizeof(one)); (void)wr; }
}

// 主线程: unix 命令服务。逐行 JSON 命令/应答, 阻塞式: 命令执行完(或超时)才回一行应答。
void CtlService(const std::string& path) {
  unlink(path.c_str());
  int ls = socket(AF_UNIX, SOCK_STREAM, 0);
  sockaddr_un a{}; a.sun_family = AF_UNIX;
  strncpy(a.sun_path, path.c_str(), sizeof(a.sun_path) - 1);
  if (bind(ls, reinterpret_cast<sockaddr*>(&a), sizeof(a)) < 0) {
    Log("ctl socket bind 失败: " + path + " err=" + std::string(strerror(errno)));
    close(ls); return;
  }
  listen(ls, 4);
  Log("ctl 服务监听 " + path);
  while (true) {
    int c = accept(ls, nullptr, nullptr);
    if (c < 0) { if (errno == EINTR) continue; break; }
    std::string line;
    char tmp[256];
    ssize_t n;
    while ((n = recv(c, tmp, sizeof(tmp), 0)) > 0) {
      line.append(tmp, n);
      size_t nl = line.find('\n');
      if (nl != std::string::npos) { line.resize(nl); break; }
    }
    json req, rep;
    try { req = json::parse(line); } catch (...) {
      rep = {{"ok", false}, {"reason", "bad_json"}}; CtlReply(c, rep); close(c); continue;
    }
    std::string cmd = req.value("cmd", "");
    if (cmd == "ping") {
      rep = {{"ok", true}, {"routers", g_router_count}};
    } else if (cmd == "offline") {
      uint32_t rid = (uint32_t)req.value("router", 0);
      Router* r = LookupById(rid);
      if (!r) { rep = {{"ok", false}, {"reason", "unknown router"}, {"router", rid}}; }
      else {
        { std::lock_guard<std::mutex> lk(g_ctl_mtx);
          r->admin_offline = true; r->draining = false; r->ctl_action |= 1; r->drained = false; }
        WakeWorker(r);
        int timeout = req.value("timeout_ms", 8000);
        bool done = WaitRouterFlag(r, &Router::drained, timeout);
        rep = done ? json{{"ok", true}, {"router", rid}}
                   : json{{"ok", false}, {"reason", "timeout"}, {"router", rid}};
      }
    } else if (cmd == "online") {
      uint32_t rid = (uint32_t)req.value("router", 0);
      Router* r = LookupById(rid);
      if (!r) { rep = {{"ok", false}, {"reason", "unknown router"}, {"router", rid}}; }
      else {
        bool alive = r->fd >= 0 && !r->connecting;
        if (!alive) {
          { std::lock_guard<std::mutex> lk(g_ctl_mtx); r->admin_offline = false; r->ctl_up = false; r->ctl_action |= 2; }
          WakeWorker(r);
          int timeout = req.value("timeout_ms", 8000);
          alive = WaitRouterFlag(r, &Router::ctl_up, timeout);
        }
        rep = json{{"ok", alive}, {"router", rid}};
      }
    } else if (cmd == "quiescent") {
      // 阻塞直到最近一次 BGP 中继距今 >= ms 毫秒(全局静默)。poll 而非 cv:
      // 读 atomic 无数据竞争, 且 200ms 粒度对 iter 的 20s 尺度足够。
      long ms = req.value("ms", 20000L);
      while (true) {
        long idle = NowMs() - g_last_bgp_ms.load();
        if (idle >= ms) break;
        std::this_thread::sleep_for(
            std::chrono::milliseconds(std::min<long>(ms - idle, 200)));
      }
      rep = {{"ok", true}, {"idle_ms", (long)(NowMs() - g_last_bgp_ms.load())}};
    } else if (cmd == "shutdown") {
      // 收到 shutdown: 应答后直接终止整个 controller(含后台 worker 线程)
      rep = {{"ok", true}};
      CtlReply(c, rep);
      close(c);
      Log("ctl 收到 shutdown, controller 退出");
      std::exit(0);
    } else {
      rep = {{"ok", false}, {"reason", "unknown cmd"}, {"cmd", cmd}};
    }
    CtlReply(c, rep);
    close(c);
  }
}