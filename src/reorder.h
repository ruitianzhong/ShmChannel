#ifndef __REORDER_H
#include <send_recv.h>
#define __REORDER_H

typedef struct {
  uint8_t protocol;
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
} reorder_flow_key;

typedef struct reorder_packet {
  task_descriptor task;
  struct reorder_packet* next;

} reorder_packet;
typedef struct reorder_flow_queue {
  struct reorder_flow_queue* next_flow;

  struct reorder_packet* head;
  struct reorder_packet* tail;

  reorder_flow_key key;
  int empty_cnt;
} reorder_flow_queue;

struct reorder_hashtable_entry {
  struct reorder_hashtable_entry* next;
  struct reorder_flow_queue queue;
};

typedef struct reorder_hashtable_entry reorder_ht_entry;

typedef struct hashtable {
  reorder_ht_entry** buckets;

  reorder_ht_entry free_list_head;
  int num_buckets;

  reorder_ht_entry* mem_chunks;

} reorder_hashtable;

typedef struct {
  reorder_flow_queue* head;
  reorder_flow_queue* tail;
} reorder_queue_group;

typedef struct {
  reorder_queue_group* tcp_queue_group;
  reorder_queue_group* udp_queue_group;

  endpoint* ep;

  task_descriptor pkt_buf[32];

  reorder_packet free_packet_head;

  reorder_packet* packet_mempool;

  int num_free_packets;

  reorder_hashtable* ht;

  int current_group;

} reorder_module;

reorder_module* reorder_module_init(endpoint* ep, int num_reserved_pkts,
                                    int num_buckets, int reserved_entry);
int reorder_receive_pkts(reorder_module* m, task_descriptor* descs,
                         int batch_size);
void reorder_module_free(reorder_module* m);

#endif