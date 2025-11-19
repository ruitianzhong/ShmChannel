#define _GNU_SOURCE
#include "reorder.h"

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "assert.h"
#include "send_recv.h"
#include "shm_channel.h"

reorder_queue_group* reorder_queue_group_create(int batch_size, int q_len) {
  reorder_queue_group* group = calloc(1, sizeof(reorder_queue_group));

  reorder_queue* rq = calloc(batch_size, sizeof(reorder_queue));

  group->queues = rq;
  group->queue_len = q_len;
  group->num_queue = batch_size;

  for (int i = 0; i < batch_size; i++) {
    rq[i].len = q_len;
    rq[i].pkts = calloc(q_len, sizeof(task_descriptor));
  }
  return group;
}

reorder_module* reorder_module_init(endpoint* ep) {
  reorder_module* module = calloc(1, sizeof(reorder_module));
  int batch_size = 8, q_len = 16, overflow_queue_len = 32;
  module->tcp_queue_group = reorder_queue_group_create(batch_size, q_len);
  module->udp_queue_group = reorder_queue_group_create(batch_size, q_len);
  module->overflow_queue_len = overflow_queue_len;
  module->overflow_queue = calloc(overflow_queue_len, sizeof(task_descriptor));
  module->ep = ep;
  return module;
}

static int flow_key_equal(const reorder_flow_key* a,
                          const reorder_flow_key* b) {
  return (a->protocol == b->protocol && a->src_ip == b->src_ip &&
          a->dst_ip == b->dst_ip && a->src_port == b->src_port &&
          a->dst_port == b->dst_port);
}

static int extract_flow_key(const uint8_t* packet_data, size_t packet_len,
                            reorder_flow_key* key) {
  struct ip* ip_header;
  struct tcphdr* tcp_header;
  struct udphdr* udp_header;
  int ip_header_len;

  if (packet_len < sizeof(struct ip)) {
    fprintf(stderr, "packet len is too short\n");
    return -1;
  }

  ip_header = (struct ip*)packet_data;
  ip_header_len = ip_header->ip_hl * 4;

  if (ip_header_len < sizeof(struct ip) || packet_len < ip_header_len) {
    fprintf(stderr, "无效的IP头部长度\n");
    return -1;
  }
  key->src_ip = ip_header->ip_src.s_addr;
  key->dst_ip = ip_header->ip_dst.s_addr;
  key->protocol = ip_header->ip_p;
  switch (key->protocol) {
    case IPPROTO_TCP:
      if (packet_len < ip_header_len + sizeof(struct tcphdr)) {
        fprintf(stderr, "TCP数据包太短\n");
        return -1;
      }
      tcp_header = (struct tcphdr*)(packet_data + ip_header_len);
      key->src_port = tcp_header->source;
      key->dst_port = tcp_header->dest;
      break;

    case IPPROTO_UDP:
      if (packet_len < ip_header_len + sizeof(struct udphdr)) {
        fprintf(stderr, "UDP数据包太短\n");
        return -1;
      }
      udp_header = (struct udphdr*)(packet_data + ip_header_len);
      key->src_port = udp_header->source;
      key->dst_port = udp_header->dest;
      break;

    default:
      fprintf(stderr, "不支持的协议类型: %d\n", key->protocol);
      return -1;
  }

  return 0;
}

static void print_flow(const reorder_flow_key* key) {
  char src_ip_str[INET_ADDRSTRLEN];
  char dst_ip_str[INET_ADDRSTRLEN];

  inet_ntop(AF_INET, key->src_ip, src_ip_str, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, key->dst_ip, dst_ip_str, INET_ADDRSTRLEN);

  printf("流信息: %s:%d -> %s:%d, 协议: %s", src_ip_str, ntohs(key->src_port),
         dst_ip_str, ntohs(key->dst_port),
         key->protocol == IPPROTO_TCP ? "TCP" : "UDP");
}
// FNV-1a
static uint64_t reorder_calculate_flow_hash(reorder_flow_key* key) {
  uint32_t src_ip = key->src_ip, dst_ip = key->dst_ip;
  uint16_t src_port = key->src_port, dst_port = key->dst_port;
  uint8_t proto = key->protocol;

  uint64_t hash = 0xcbf29ce484222325ULL;
  const uint64_t fnv_prime = 0x100000001b3ULL;
  if (src_ip > dst_ip || (src_ip == dst_ip && src_port > dst_port)) {
    uint16_t temp_ip = src_ip;
    src_ip = dst_ip;
    dst_ip = temp_ip;

    uint16_t temp_port = src_port;
    src_port = dst_port;
    dst_port = temp_port;
  }
  // src ip
  for (int i = 0; i < 4; i++) {
    hash ^= (src_ip >> (i * 8)) & 0xFF;
    hash *= fnv_prime;
  }

  // dst ip
  for (int i = 0; i < 4; i++) {
    hash ^= (dst_ip >> (i * 8)) & 0xFF;
    hash *= fnv_prime;
  }

  // src port
  for (int i = 0; i < 2; i++) {
    hash ^= (src_port >> (i * 8)) & 0xFF;
    hash *= fnv_prime;
  }

  // dst port
  for (int i = 0; i < 2; i++) {
    hash ^= (dst_port >> (i * 8)) & 0xFF;
    hash *= fnv_prime;
  }

  // proto
  hash ^= proto;
  hash *= fnv_prime;

  return hash;
}

static int reorder_dispatch_to_queue(reorder_queue_group* group,
                                     task_descriptor* pkt,
                                     reorder_flow_key* flow_key) {
  uint64_t hash = reorder_calculate_flow_hash(flow_key);
  int queue_idx = hash % group->num_queue;
  reorder_queue* q = &group->queues[queue_idx];
  if (q->is_full) {
    return -2;
  }

  q->pkts[q->tail] = *pkt;
  q->tail++;
  if (q->tail == q->head) {
    q->is_full = 1;
  }
}

int reorder_dispatch(reorder_module* m, task_descriptor* pkt) {
  reorder_flow_key key;
  if (extract_flow_key(pkt->start_addr, pkt->len, &key) == -1) {
    printf("bad packet\n");
    return 0;
  }

  int res = -1;
  if (key.protocol == IPPROTO_TCP) {
    res = reorder_dispatch_to_queue(m->tcp_queue_group, pkt, &key);
  } else if (key.protocol == IPPROTO_UDP) {
    res = reorder_dispatch_to_queue(m->udp_queue_group, pkt, &key);
  } else {
    printf("bad packet\n");
  }

  return res;
}

int reorder_group_schedule(reorder_queue_group* grp, task_descriptor* descs,
                           int batch_size) {
  int idx = 0;
  for (int i = 0; i < grp->num_queue && idx < batch_size; i++) {
    reorder_queue* q = &grp->queues[i];
    if (!q->is_full && q->head == q->tail) {
      continue;
    }

    descs[idx] = q->pkts[q->head];

    q->head = (q->head + 1) % q->len;
    if (q->is_full) {
      q->is_full = 0;
    }
    ++idx;
  }

  return idx;
}

void reorder_receive_pkts(reorder_module* m, task_descriptor* descs,
                          int batch_size) {
  // read the
  int res = 0;
  while (m->overflow_cur_len > 0) {
    task_descriptor* pkt = &m->overflow_queue[m->overflow_queue_head];

    res = reorder_dispatch(m, pkt);
    if (res != 0) {
      break;
    }

    m->overflow_queue_head =
        (m->overflow_queue_head + 1) % (m->overflow_queue_len);
    m->overflow_cur_len--;
  }

  int bs = m->overflow_cur_len < 32 ? m->overflow_cur_len : 32;

  int num_recv = shm_channel_recv_burst(m->ep->chan, m->pkt_buf, bs);

  for (int i = 0; i < num_recv; i++) {
    task_descriptor* pkt = &m->pkt_buf[i];
    res = reorder_dispatch(m, pkt);
    if (res != 0) {
      assert(m->overflow_cur_len < m->overflow_queue_len);
      m->overflow_cur_len++;
      m->overflow_queue[m->overflow_queue_tail] = *pkt;
      m->overflow_queue_tail =
          (m->overflow_queue_tail + 1) % m->overflow_queue_len;
    }
  }

  // now schedule one batch for the receiver
  for (int i = 0; i < 2; i++) {
    if (m->current_group == 0) {
      res = reorder_group_schedule(m->tcp_queue_group, descs, batch_size);
    } else {
      res = reorder_group_schedule(m->udp_queue_group, descs, batch_size);
    }

    if (res == 0) {
      m->current_group = (m->current_group + 1) % 2;
    } else {
      break;
    }
  }
  return res;
}
