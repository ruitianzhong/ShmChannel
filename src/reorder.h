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

typedef struct {
  task_descriptor* pkts;
  int len;
  int head;
  int tail;
  int is_full;
} reorder_queue;

typedef struct {
  reorder_queue* queues;
  int num_queue;
  int queue_len;
} reorder_queue_group;

typedef struct {
  reorder_queue_group* tcp_queue_group;
  reorder_queue_group* udp_queue_group;

  task_descriptor* overflow_queue;
  int overflow_queue_len;
  int overflow_queue_head;
  int overflow_queue_tail;
  int overflow_cur_len;

  endpoint* ep;

  task_descriptor pkt_buf[32];

  int current_group;

} reorder_module;

reorder_module* reorder_module_init(endpoint* ep);
int reorder_receive_pkts(reorder_module* m, task_descriptor* descs,
                         int batch_size);

#endif