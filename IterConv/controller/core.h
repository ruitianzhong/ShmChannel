// 数据面核心共享头: Router/Link 数据结构 + 跨翻译单元的共享状态/函数声明。
// controller.cpp(worker/epoll 主逻辑)与 ctl.cpp(unix 命令服务)共用; 全局状态在
// controller.cpp 定义、此处 extern 声明。ctl 的命令服务接口见 ctl.h。
#ifndef CORE_H
#define CORE_H

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "../common/protocol.h"

struct Router {
  uint32_t id = 0;
  std::string name, vm_ip, dial_ip;
  uint32_t frr_ip = 0;              // 主本端 frr 地址(=frr_ips 首元素, 日志/兼容)
  std::vector<uint32_t> frr_ips;    // 全部本端 frr 地址(多邻居时 >1), g_reg 按地址登记别名
  uint16_t port = 0;      // 拨号该 agent 用的端口, 0=用全局 control_port

  // ---- 连接(仅属主线程读写 fd/ev_events/connecting; txbuf 跨线程由 tx_mtx 保护)
  int fd = -1;
  uint32_t ev_events = 0;   // 当前注册到本人 epoll 的事件掩码
  std::string buf;          // 消息读缓冲
  long next_try_ms = 0;
  bool connecting = false;

  // ---- 节点冻结/恢复编排(经 unix ctl 接口置; 由 worker 属主线程读写执行)
  bool admin_offline = false;  // 期望离线: 不主动连接、收到流量只缓存
  bool draining = false;       // 正在优雅排空(SHUT_WR 半关交换中)
  int  ctl_action = 0;         // 位1=要求下线, 位2=要求上线(worker 消费后清零)
  bool drained = false;        // 排空完成(worker 置, ctl 线程等)
  bool ctl_up = false;         // online 后连接已就绪(worker 置, ctl 线程等)

  // ---- 发送队列: 跨线程(任意 worker 向此连接转发) 入队, 属主线程用 EPOLLOUT 续发
  std::string txbuf;        // 待发字节(字节序: 前面先发)
  std::mutex tx_mtx;        // 串行化对该 socket 的发送(含跨线程)
  bool need_epollout = false;  // 有积压、需挂 EPOLLOUT 续发
  int owner_efd = -1;       // 属主线程的 epoll fd
  int owner_wake = -1;      // 属主线程的 eventfd(用来唤醒它去 flush)
};
struct Link {
  uint32_t ip_a = 0, ip_b = 0; uint32_t rid_a = 0, rid_b = 0;
  bool open = false;  // 该 link 的 BGP 是否已达 Established(见到 OPEN), 仅 g_ctl_mtx 下读写
};

// ---- 跨单元共享状态(定义在 controller.cpp, 此处 extern) ----
extern std::unordered_map<uint32_t, Router*> g_reg;   // frr_ip -> router(启动即全登记)
extern int g_router_count;                            // distinct router 数(ping 上报)
extern std::atomic<long> g_last_bgp_ms;               // 最近一次中继 MSG_BGP 的单调时钟
extern std::mutex g_ctl_mtx;                          // 保护 admin_offline/open/排空标志
extern std::condition_variable g_ctl_cv;              // 与 g_ctl_mtx 配对, 排空/上线回报

// ---- 跨单元函数(定义在 controller.cpp, ctl.cpp 引用) ----
void Log(const std::string& s);
long NowMs();
void SendToRouter(Router* r, const vxdp::MsgHeader& h, const char* payload);
Router* LookupConn(uint32_t frr_ip);
Router* LookupById(uint32_t id);
bool ConnReady(const Router* r);

#endif  // CORE_H