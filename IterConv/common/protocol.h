// veth-only 定制数据面 - 共享协议定义。
// agent(VM内) 与 controller(host) 之间的 TCP 控制/数据消息。
// 所有多字节字段按 little-endian 线序 (本机即 x86, 直接读写结构体)。
#ifndef INTERCEPT_PROTOCOL_H
#define INTERCEPT_PROTOCOL_H

#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <string>

namespace vxdp {

constexpr uint32_t MSG_MAGIC = 0x50445856;      // "VXDP"
constexpr uint16_t MSG_VERSION = 1;

enum MsgType : uint16_t {
  MSG_CTRL_HELLO = 1,      // agent->controller 注册: 负载 = 序列化的 veth 表(JSON)
  MSG_CTRL_ACK = 2,        // 通用确认
  MSG_CTRL_UP = 3,         // agent->controller: 本地已有 FRR 连到某 fake_ip:179
  MSG_CTRL_ESTABLISH = 4,  // controller->agent: 提示外部发起(重)连接; 低id拒绝
  MSG_CTRL_CLOSE = 5,      // 通知对端某会话断开
  MSG_BGP = 6,             // 负载 = 单条完整 BGP PDU
  MSG_RAW = 7,             // 负载 = 单条原始以太网帧 (AF_PACKET, 非 TCP)
  MSG_CTRL_OFFLINE = 8,    // controller->agent: 开始优雅下线(排空后 shutdown 写端)
};

#pragma pack(push, 1)
struct MsgHeader {
  uint32_t magic;
  uint16_t version;
  uint16_t type;
  uint32_t src_router;  // 发送方 router_id
  uint32_t dst_router;  // 目标 router_id, 0 = 广播/all
  uint32_t src_ip;      // FRR 视角源 IP (本端 FRR ns 源地址, 如 vm1=10.0.0.1)
  uint32_t dst_ip;      // FRR 视角目的 IP (对端 FRR 地址, 如 vm2=10.0.0.2)
  uint32_t veth_idx;    // 归属 veth 索引 (0 = 控制面, >=1 = 映射 veth)
  uint32_t len;         // 负载字节数 (不含 header)
};
#pragma pack(pop)
static_assert(sizeof(MsgHeader) == 32, "MsgHeader must be 32 bytes");

inline uint32_t ipv4(const char* s) { return inet_addr(s); }  // 已是网络字节序
inline std::string ipstr(uint32_t ip_be) {
  char buf[16];
  inet_ntop(AF_INET, &ip_be, buf, sizeof(buf));
  return buf;
}

}  // namespace vxdp

#endif  // INTERCEPT_PROTOCOL_H