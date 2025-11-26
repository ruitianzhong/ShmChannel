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
static const int reclaim_freq = 1;
static const uint64_t hash_seed = 0x12345678;

int flow_key_equal(reorder_flow_key* k1, reorder_flow_key* k2) {
  return k1->src_ip == k2->src_ip && k1->dst_ip == k2->dst_ip &&
         k1->src_port == k2->src_port && k1->dst_port == k2->dst_port &&
         k1->protocol == k2->protocol;
}

reorder_hashtable* hashtable_create(int num_buckets, int reserved) {
  reorder_hashtable* ht = calloc(1, sizeof(reorder_hashtable));
  assert(ht != NULL);
  ht->buckets = calloc(num_buckets, sizeof(reorder_ht_entry*));
  ht->num_buckets = num_buckets;
  ht->mem_chunks = calloc(reserved, sizeof(reorder_ht_entry));

  for (int i = 0; i < reserved - 1; i++) {
    ht->mem_chunks[i].next = &ht->mem_chunks[i + 1];
  }

  ht->free_list_head.next = &ht->mem_chunks[0];
  return ht;
}

void hashtable_free(reorder_hashtable* ht) {
  assert(ht);
  free(ht->buckets);
  free(ht->mem_chunks);
  free(ht);
}

void flow_queue_add_last(reorder_flow_queue* fq, reorder_packet* pkt) {
  pkt->next = NULL;
  if (fq->head == NULL) {
    fq->head = pkt;
    fq->tail = pkt;
    return;
  }

  fq->tail->next = pkt;
  fq->tail = pkt;
  return;
}

reorder_packet* flow_queue_delete_first(reorder_flow_queue* fq) {
  reorder_packet* ret = NULL;
  if (fq->head == NULL) {
    return ret;
  }
  ret = fq->head;

  if (fq->head == fq->tail) {
    fq->head = NULL;
    fq->tail = NULL;

  } else {
    fq->head = ret->next;
  }
  ret->next = NULL;
  return ret;
}

static uint64_t reorder_calculate_flow_hash(reorder_flow_key* key,
                                            uint64_t seed);

static reorder_ht_entry* allocate_ht_entry(reorder_hashtable* ht) {
  assert(ht->free_list_head.next);
  reorder_ht_entry* ret = ht->free_list_head.next;
  ht->free_list_head.next = ret->next;
  ret->next = NULL;
  ret->queue.head = NULL;
  ret->queue.tail = NULL;
  return ret;
}

static void free_ht_entry(reorder_hashtable* ht, reorder_ht_entry* entry) {
  entry->next = ht->free_list_head.next;
  ht->free_list_head.next = entry;
  return;
}

reorder_ht_entry* hashtable_insert(reorder_hashtable* ht, reorder_flow_key* key,
                                   reorder_packet* pkt, int* created) {
  uint64_t hash = reorder_calculate_flow_hash(key, hash_seed);

  int idx = hash % ht->num_buckets;

  reorder_ht_entry* p = ht->buckets[idx];

  while (p) {
    if (flow_key_equal(key, &p->queue.key)) {
      reorder_flow_queue* fq = &p->queue;

      flow_queue_add_last(fq, pkt);
      *created = 0;
      return p;
    }
    p = p->next;
  }

  reorder_ht_entry* new_entry = allocate_ht_entry(ht);
  new_entry->next = ht->buckets[idx];
  ht->buckets[idx] = new_entry;
  *created = 1;
  new_entry->queue.empty_cnt = reclaim_freq;

  return new_entry;
}

void hashtable_delete(reorder_hashtable* ht, reorder_flow_key* key) {
  uint64_t hash = reorder_calculate_flow_hash(key, 0x12345678);

  int idx = hash % ht->num_buckets;

  reorder_ht_entry* p = ht->buckets[idx];

  reorder_ht_entry* prev = NULL;

  while (p) {
    if (flow_key_equal(key, &p->queue.key)) {
      // reorder_flow_queue* fq = &p->queue;
      if (prev == NULL) {
        ht->buckets[idx] = p->next;
      } else {
        prev->next = p->next;
      }
      p->next = NULL;
      free_ht_entry(ht, p);
      return;
    }
    prev = p;
    p = p->next;
  }
  return;
}

static uint64_t g_total_pkts = 0;
static uint64_t g_total_cnt = 0;

static reorder_queue_group* reorder_queue_group_create() {
  reorder_queue_group* group = calloc(1, sizeof(reorder_queue_group));

  return group;
}

static void reorder_queue_group_free(reorder_queue_group* group) {
  assert(group);
  free(group);
}

reorder_packet* allocate_packet(reorder_module* m) {
  assert(m->num_free_packets);
  m->num_free_packets--;
  reorder_packet* ret = m->free_packet_head.next;
  m->free_packet_head.next = ret->next;
  ret->next = NULL;
  return ret;
}

void free_packet(reorder_module* m, reorder_packet* pkt) {
  m->num_free_packets++;
  pkt->next = m->free_packet_head.next;
  m->free_packet_head.next = pkt;
  return;
}

reorder_module* reorder_module_init(endpoint* ep, int num_reserved_pkts,
                                    int num_buckets, int reserved_entry) {
  reorder_module* module = calloc(1, sizeof(reorder_module));
  module->tcp_queue_group = reorder_queue_group_create();
  module->udp_queue_group = reorder_queue_group_create();

  module->num_free_packets = num_reserved_pkts;
  module->packet_mempool = calloc(num_reserved_pkts, sizeof(reorder_packet));

  for (int i = 0; i < num_reserved_pkts - 1; i++) {
    module->packet_mempool[i].next = &module->packet_mempool[i + 1];
  }

  module->free_packet_head.next = &module->packet_mempool[0];

  module->ht = hashtable_create(num_buckets, reserved_entry);

  module->ep = ep;
  return module;
}

void reorder_module_free(reorder_module* m) {
  reorder_queue_group_free(m->tcp_queue_group);
  reorder_queue_group_free(m->udp_queue_group);
  free(m->packet_mempool);
  hashtable_free(m->ht);
  free(m);

  printf("[reorder module] average batch_size=%.2f\n",
         (double)g_total_pkts / (double)g_total_cnt);
}

static int extract_flow_key(const uint8_t* packet_data, size_t packet_len,
                            reorder_flow_key* key) {
  assert(packet_len > 14);
  packet_data += 14;
  packet_len -= 14;
  struct ip* ip_header;
  struct tcphdr* tcp_header;
  struct udphdr* udp_header;
  size_t ip_header_len;

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

  if (key->src_ip > key->dst_ip ||
      (key->src_ip == key->dst_ip && key->src_port > key->dst_port)) {
    uint32_t temp_ip = key->src_ip;
    key->src_ip = key->dst_ip;
    key->dst_ip = temp_ip;

    uint16_t temp_port = key->src_port;
    key->src_port = key->dst_port;
    key->dst_port = temp_port;
  }

  return 0;
}
#ifdef REORDER_DEBUG
static void print_flow(const reorder_flow_key* key) {
  char src_ip_str[INET_ADDRSTRLEN];
  char dst_ip_str[INET_ADDRSTRLEN];

  inet_ntop(AF_INET, &key->src_ip, src_ip_str, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &key->dst_ip, dst_ip_str, INET_ADDRSTRLEN);

  printf("流信息: %s:%d -> %s:%d, 协议: %s ", src_ip_str, ntohs(key->src_port),
         dst_ip_str, ntohs(key->dst_port),
         key->protocol == IPPROTO_TCP ? "TCP" : "UDP");
}
#endif
static uint64_t reorder_calculate_flow_hash(reorder_flow_key* key,
                                            uint64_t seed) {
  uint32_t src_ip = key->src_ip, dst_ip = key->dst_ip;
  uint16_t src_port = key->src_port, dst_port = key->dst_port;
  uint8_t proto = key->protocol;

  uint64_t hash = seed;

  if (src_ip > dst_ip || (src_ip == dst_ip && src_port > dst_port)) {
    uint32_t temp_ip = src_ip;
    src_ip = dst_ip;
    dst_ip = temp_ip;

    uint16_t temp_port = src_port;
    src_port = dst_port;
    dst_port = temp_port;
  }

  hash ^= src_ip;
  hash *= 0x5bd1e995;
  hash ^= hash >> 47;

  hash ^= dst_ip;
  hash *= 0x5bd1e995;
  hash ^= hash >> 47;

  uint32_t ports = (uint32_t)src_port << 16 | dst_port;
  hash ^= ports;
  hash *= 0x5bd1e995;
  hash ^= hash >> 47;

  hash ^= proto;
  hash *= 0x5bd1e995;
  hash ^= hash >> 47;

  return hash;
}

void reorder_queue_group_add_last(reorder_queue_group* grp,
                                  reorder_flow_queue* fq) {
  if (grp->head == NULL) {
    grp->head = fq;
    grp->tail = fq;
    return;
  }
  grp->tail->next_flow = fq;
  grp->tail = fq;
  fq->next_flow = NULL;
}

reorder_flow_queue* reorder_queue_group_remove_first(reorder_queue_group* grp) {
  if (grp->head == NULL) {
    return NULL;
  }
  reorder_flow_queue* ret = grp->head;
  if (grp->head == grp->tail) {
    grp->head = NULL;
    grp->tail = NULL;
  } else {
    grp->head = ret->next_flow;
  }
  ret->next_flow = NULL;
  return ret;
}

static int reorder_dispatch_to_queue(reorder_hashtable* ht,
                                     reorder_queue_group* group,
                                     reorder_packet* pkt,
                                     reorder_flow_key* flow_key) {
  int created = 0;
  reorder_ht_entry* entry = hashtable_insert(ht, flow_key, pkt, &created);

  if (entry == NULL) {
    assert(0);
  }

  reorder_flow_queue* fq = &entry->queue;

  fq->key = *flow_key;

  if (created) {
    reorder_queue_group_add_last(group, fq);
  }

  flow_queue_add_last(fq, pkt);
  return 0;
}

int reorder_dispatch(reorder_module* m, reorder_packet* pkt) {
  reorder_flow_key key;
  if (extract_flow_key(pkt->task.start_addr, pkt->task.len, &key) == -1) {
    printf("bad packet\n");
    return 0;
  }

  int res = -1;
  if (key.protocol == IPPROTO_TCP) {
    res = reorder_dispatch_to_queue(m->ht, m->tcp_queue_group, pkt, &key);
  } else if (key.protocol == IPPROTO_UDP) {
    res = reorder_dispatch_to_queue(m->ht, m->udp_queue_group, pkt, &key);
  } else {
    printf("bad packet\n");
  }

  return res;
}

int reorder_group_schedule(reorder_module* m, reorder_queue_group* grp,
                           task_descriptor* descs, int batch_size) {
  reorder_flow_queue* tail = grp->tail;
  int cnt = 0;
  while (grp->head && cnt < batch_size) {
    reorder_flow_queue* cur = reorder_queue_group_remove_first(grp);
    reorder_packet* pkt = flow_queue_delete_first(cur);
    if (pkt != NULL) {
      descs[cnt] = pkt->task;
      cnt++;
      cur->empty_cnt = reclaim_freq;
      reorder_queue_group_add_last(grp, cur);
      free_packet(m, pkt);

    } else {
      if (cur->empty_cnt == 0) {
        hashtable_delete(m->ht, &cur->key);
      } else {
        cur->empty_cnt--;
        reorder_queue_group_add_last(grp, cur);
      }
    }

    if (cur == tail) {
      break;
    }
  }

  return cnt;
}

int reorder_receive_pkts(reorder_module* m, task_descriptor* descs,
                         int batch_size) {
  int bs = m->num_free_packets < 32 ? m->num_free_packets : 32;

  int num_recv = shm_channel_recv_burst(m->ep->chan, m->pkt_buf, bs);

  int res = -1;

  for (int i = 0; i < num_recv; i++) {
    task_descriptor* pkt = &m->pkt_buf[i];
    reorder_packet* r_pkt = allocate_packet(m);
    r_pkt->task = *pkt;
    res = reorder_dispatch(m, r_pkt);
  }

  // now schedule one batch for the receiver
  for (int i = 0; i < 2; i++) {
    if (m->current_group == 0) {
      res = reorder_group_schedule(m, m->tcp_queue_group, descs, batch_size);
    } else {
      res = reorder_group_schedule(m, m->udp_queue_group, descs, batch_size);
    }

    if (res == 0) {
      m->current_group = (m->current_group + 1) % 2;
    } else {
      break;
    }
  }
  if (res > 0) {
    g_total_cnt++;
    g_total_pkts += res;
#ifdef REORDER_DEBUG
    printf("Batch %ld ret=%d\n", g_total_cnt - 1, res);
    for (int i = 0; i < res; i++) {
      reorder_flow_key key;
      extract_flow_key(descs[i].start_addr, descs[i].len, &key);
      print_flow(&key);
    }
    printf("\n\n");
#endif
  }
  return res;
}
