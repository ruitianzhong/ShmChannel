#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <wait.h>

#include "shm_channel.h"

void sender(shm_channel* chan, int num_requests) {
  task_descriptor task = {
      .magic = 0,
  };

  while (num_requests) {
    int ret = shm_channel_send_burst(chan, &task, 1);
    if (ret == 1) {
      --num_requests;
      task.magic += 1;
    } else {
      assert(ret == 0);
    }
  }
}

void receiver(shm_channel* chan, int num_requests) {
  task_descriptor task;
  int idx = 0;
  while (idx < num_requests) {
    int ret = shm_channel_recv_burst(chan, &task, 1);

    if (ret == 1) {
      assert(idx == task.magic);
      ++idx;
    } else {
      assert(ret == 0);
    }
  }

  assert(shm_channel_free_count(chan) == chan->ring_queue->q_depth);
  assert(shm_channel_used_count(chan) == 0);
}
/*
Command line: ./test_single_request [q_depth] [num_total_request]
*/
int main(int argc, char const* argv[]) {
  assert(argc == 3);

  int q_depth = atoi(argv[1]);
  int request_to_sent = atoi(argv[2]);

  assert(q_depth > 0 && request_to_sent >= 0);

  shm_channel* chan = shm_channel_open(q_depth);

  assert(chan != NULL);

  int ret = fork();

  assert(ret != -1);

  if (ret == 0) {
    sender(chan, request_to_sent);
  } else {
    receiver(chan, request_to_sent);

    // clean up the subprocess
    int status;
    pid_t pid = wait(&status);
    assert(pid != -1);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS);
  }

  shm_channel_close(chan);
  if (ret) {
    printf("[PASSED] test_single_request: q_depth=%d total_requests=%d\n",
           q_depth, request_to_sent);
  }

  exit(EXIT_SUCCESS);
}