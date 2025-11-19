#ifndef __REORDER_H

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

#endif