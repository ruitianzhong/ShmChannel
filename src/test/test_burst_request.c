#include <assert.h>
#include <shm_channel.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <wait.h>
// performance test
void sender(shm_channel *chan, int num_requests, int batch_size) {
  task_descriptor *batch = calloc(batch_size, sizeof(task_descriptor));
  for (int i = 0; i < batch_size; i++) {
    batch[i].magic = i;
  }

  int sent = 0;

  while (sent < num_requests) {
    if (sent > 0) {
      for (int i = 0; i < batch_size; i++) {
        batch[i].magic += batch_size;
      }
    }

    int current_batch_size =
        batch_size < (num_requests - sent) ? batch_size : (num_requests - sent);

    // send all
    int batch_sent = 0;
    while (batch_sent < current_batch_size) {
      int ret = shm_channel_send_burst(chan, &batch[batch_sent],
                                       current_batch_size - batch_sent);
      batch_sent += ret;
      sent += ret;
    }
    assert(batch_sent == current_batch_size);
  }

  free(batch);
  return;
}

void receiver(shm_channel *chan, int num_requests, int batch_size) {
  task_descriptor *batch = calloc(batch_size, sizeof(task_descriptor));

  int received = 0, expect_magic = 0;
  while (received < num_requests) {
    int current_batch_size = batch_size < (num_requests - received)
                                 ? batch_size
                                 : (num_requests - received);

    int offset = 0;

    do {
      int ret = shm_channel_recv_burst(chan, &batch[offset],
                                       current_batch_size - offset);
      offset += ret;
      received += ret;
    } while (offset < current_batch_size);

    for (int i = 0; i < current_batch_size; i++) {
      if (batch[i].magic!=expect_magic){
        printf("%d %d i=%d received=%d cur_bs=%d\n", batch[i].magic, expect_magic, i,
               received, current_batch_size);
      }
      assert(batch[i].magic == expect_magic);
      expect_magic++;
    }
  }

  free(batch);

  return;
}
/*
Command line: ./test_burst_request.c [q_depth] [batch_size] [num_requests]
*/
int main(int argc, char const *argv[]) {
  int q_depth, batch_size, num_requests;
  assert(argc == 4);
  q_depth = atoi(argv[1]);
  batch_size = atoi(argv[2]);
  num_requests = atoi(argv[3]);

  shm_channel *chan = shm_channel_open(q_depth);

  assert(chan != NULL);
  int ret = fork();

  assert(ret != -1);

  if (ret == 0) {
    sender(chan, num_requests, batch_size);
  } else {
    receiver(chan, num_requests, batch_size);
    int status;
    pid_t pid = wait(&status);
    assert(pid != -1);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS);
  }

  shm_channel_close(chan);
  // clean up the subprocess
  if (ret) {
    printf(
        "[PASSED] test_burst_request: q_depth=%d batch_size=%d "
        "num_requests=%d\n",
        q_depth, batch_size, num_requests);
  }
  exit(EXIT_SUCCESS);
}
