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
        batch[i].magic++;
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
    }
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

    int ret = shm_channel_recv_burst(chan, &batch[0], current_batch_size);

    received += ret;
    for (int i = 0; i < ret; i++) {
      assert(batch[i].magic == expect_magic);
      expect_magic++;
    }
  }

  free(batch);

  return;
}

int main(int argc, char const *argv[]) {
  printf("test_burst_request PASSED\n");

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
  }

  shm_channel_close(chan);
  // clean up the subprocess
  int status;
  pid_t pid = wait(&status);
  assert(pid != -1);
  assert(WIFEXITED(status) && WEXITSTATUS(status));
  exit(EXIT_SUCCESS);
}
