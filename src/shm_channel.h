#include <stdint.h>
#ifndef __SHM_CHANNEL__
#define __SHM_CHANNEL__
#define SHM_MAGIC_NUMBER 0x2025
#define X86_CACHE_LINE_SIZE 64

// in shared memory
struct task_descriptor {
  // to check integrity, set by ShmChannel
  int magic;
  // set by caller
  void* start_addr;
  int len;
};

typedef struct task_descriptor task_descriptor;

// in shared memory
struct ring_queue {
  // Avoid false sharing
  // only receiver modify it
  volatile int head_idx __attribute__((aligned(X86_CACHE_LINE_SIZE)));
  // Avoid false sharing
  // only sender modify it
  volatile int tail_idx __attribute__((aligned(X86_CACHE_LINE_SIZE)));
  // ptr to ring queue region
  task_descriptor* ring_queue_region;
  // queue depth for ring_queue (actually allocate q_depth+1 slots)
  volatile int q_depth;

  volatile int magic;
};

typedef struct ring_queue ring_queue;

struct shm_channel {
  // shared by sender and receiver
  ring_queue* ring_queue;
};

typedef struct shm_channel shm_channel;

shm_channel* shm_channel_open(int q_depth);

void shm_channel_close(shm_channel*);

int shm_channel_send_burst(shm_channel* chan, task_descriptor* send_descs,
                           int num_descriptors);

int shm_channel_recv_burst(shm_channel* chan, task_descriptor* recv_descs,
                           int num_descriptor);

int shm_channel_free_count(shm_channel* chan);

int shm_channel_used_count(shm_channel* chan);

#endif