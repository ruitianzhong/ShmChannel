// Needed by MAP_ANONYMOUS
#define _GNU_SOURCE

#include "shm_channel.h"
#define barrier() __asm__ __volatile__("" : : : "memory")

#include <fcntl.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "assert.h"

shm_channel* shm_channel_open(int q_depth) {
  assert(q_depth > 0 && q_depth <= 65535);

  shm_channel* chan = (shm_channel*)calloc(1, sizeof(shm_channel));

  if (chan == NULL) {
    return NULL;
  }

  ring_queue* ring_queue =
      mmap(NULL, sizeof(ring_queue), PROT_READ | PROT_WRITE,
           MAP_SHARED | MAP_ANONYMOUS, -1, 0);

  if (MAP_FAILED == ring_queue) {
    free(chan);
    perror("ring_queue mmap failed");
    return NULL;
  }

  ring_queue->head_idx = 0;
  ring_queue->tail_idx = 0;
  ring_queue->q_depth = q_depth;
  ring_queue->magic = SHM_MAGIC_NUMBER;

  ring_queue->ring_queue_region =
      mmap(NULL, sizeof(task_descriptor) * (q_depth + 1),
           PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);

  if (NULL == ring_queue->ring_queue_region) {
    int ret = munmap(ring_queue, sizeof(ring_queue));
    assert(ret == 0);
    free(chan);
    perror("ring_queue_region mmap failed");
    return NULL;
  }
  chan->ring_queue = ring_queue;

  return chan;
}

void shm_channel_close(shm_channel* chan) {
  assert(chan != NULL);
  int ret = munmap(chan->ring_queue->ring_queue_region,
                   (chan->ring_queue->q_depth + 1) * sizeof(task_descriptor));
  if (-1 == ret) {
    perror("shm_channel_close munmap ring_queue_region");
  }

  ret = munmap(chan->ring_queue, sizeof(ring_queue));

  if (-1 == ret) {
    perror("shm_channel_close munmap ring_queue");
  }

  return;
}
// trust the caller and do not perform any check
int shm_channel_send_burst(shm_channel* chan, task_descriptor* send_descs,
                           int num_descriptors) {
  ring_queue* rq = chan->ring_queue;

  int num_sent_descs = 0;
  // atomic load under x86, ok here. For portability use "stdatomic" instead
  int head_idx = rq->head_idx, tail_idx = rq->tail_idx;

  int available_slots =
      rq->q_depth - (tail_idx - head_idx + rq->q_depth + 1) % (rq->q_depth + 1);

  for (int i = 0; i < num_descriptors && i < available_slots;
       i++, num_sent_descs++) {
    memcpy(&rq->ring_queue_region[tail_idx], &send_descs[i],
           sizeof(task_descriptor));
    tail_idx = (tail_idx + 1) % (rq->q_depth + 1);
  }

  // Barrier to ensure receiver does not see the uninitialized descriptor.
  // Under TSO model (x86), read/write instruction to different address may be
  // re-ordered, so barrier is necessary.
  barrier();

  rq->tail_idx = tail_idx;
  return num_sent_descs;
}
// trust the caller and do not perform any check
int shm_channel_recv_burst(shm_channel* chan, task_descriptor* recv_descs,
                           int num_descriptor) {
  int num_recv_descs = 0;

  ring_queue* rq = chan->ring_queue;
  int head_idx = rq->head_idx, tail_idx = rq->tail_idx;

  int available_slot_to_recv =
      (tail_idx - head_idx + rq->q_depth + 1) % (rq->q_depth + 1);

  for (int i = 0; i < num_descriptor && i < available_slot_to_recv;
       i++, num_recv_descs++) {
    memcpy(&recv_descs[i], (void*)&rq->ring_queue_region[head_idx],
           sizeof(task_descriptor));
    head_idx = (head_idx + 1) % (rq->q_depth + 1);
  }
  // Avoid read/write instruction re-ordering
  barrier();

  rq->head_idx = head_idx;

  return num_recv_descs;
}

int shm_channel_free_count(shm_channel* chan) {
  ring_queue* rq = chan->ring_queue;
  return rq->q_depth -
         (rq->tail_idx - rq->head_idx + rq->q_depth + 1) % (rq->q_depth + 1);
}

int shm_channel_used_count(shm_channel* chan) {
  ring_queue* rq = chan->ring_queue;
  return (rq->tail_idx - rq->head_idx + rq->q_depth + 1) % (rq->q_depth + 1);
}