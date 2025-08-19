#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wait.h>

#include "send_recv.h"
void receiver(endpoint *ep) {
  task_descriptor *batch = calloc(g_config.batch_size, sizeof(task_descriptor));

  assert(batch != NULL);

  uint64_t total_recv = 0;

  int bs = g_config.batch_size;

  struct timespec start, end;

  if (clock_gettime(CLOCK_MONOTONIC, &start) == -1) {
    perror("receiver clock_gettime");
    exit(EXIT_FAILURE);
  }
  for (int iter = 0; iter < g_config.loop_time; iter++) {
    int expect_magic = 0, recv = 0;
    while (recv < ep->packet_cnt) {
      int current_bs =
          bs < (ep->packet_cnt - recv) ? bs : (ep->packet_cnt - recv);

      int ret = shm_channel_recv_burst(ep->chan, batch, current_bs);
      recv += ret;
      total_recv += ret;
      // sanity check
      for (int i = 0; i < ret; i++) {
        assert(batch[i].magic == expect_magic);
        expect_magic++;
      }
    }
  }

  if (clock_gettime(CLOCK_MONOTONIC, &end) == -1) {
    perror("receiver clock_gettime");
    exit(EXIT_FAILURE);
  }

  uint64_t ns_elapsed =
      (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
  double receive_pps = (double)(1e9 * total_recv) / (double)ns_elapsed;
  printf("receive pps=%.2f kpps=%.2f\n", receive_pps, receive_pps / 1000.0);
}

void parse_cli_option(int argc, char const *argv[]) {
  if (argc == 1) {
    return;
  }
  int idx = 1;
  while (idx < argc) {
    if (strncmp(argv[idx], "--pcap-file-path", 17) == 0 && idx + 1 < argc) {
      g_config.pcap_file_path = calloc(strlen(argv[idx + 1]) + 1, sizeof(char));

      assert(g_config.pcap_file_path != NULL);
      strncpy(g_config.pcap_file_path, argv[idx + 1], strlen(argv[idx + 1]));
      idx += 2;
    } else if (strncmp(argv[idx], "--pps", 6) == 0 && idx + 1 < argc) {
      g_config.send_pps = atoi(argv[idx + 1]);
      idx += 2;
    } else if (strncmp(argv[idx], "--elapsed-second", 17) == 0 &&
               idx + 1 < argc) {
      g_config.elapsed_second = atoi(argv[idx + 1]);
      idx += 2;
    } else if (strncmp(argv[idx], "--max_sent_packet_number", 25) == 0 &&
               idx + 1 < argc) {
      g_config.elapsed_second = atoi(argv[idx + 1]);
      idx += 2;
    } else if (strncmp(argv[idx], "--queue-depth", 14) == 0 && idx + 1 < argc) {
      g_config.q_depth = atoi(argv[idx + 1]);
      idx += 2;
    } else if (strcmp(argv[idx], "--batch-size") == 0 && idx + 1 < argc) {
      g_config.batch_size = atoi(argv[idx + 1]);
      idx += 2;
    } else if (strcmp(argv[idx], "--sender-cpu") == 0 && idx + 1 < argc) {
      g_config.sender_cpu_id = atoi(argv[idx + 1]);
      idx += 2;
    } else if (strcmp(argv[idx], "--recv-cpu") == 0 && idx + 1 < argc) {
      g_config.receiver_cpu_id = atoi(argv[idx + 1]);
      idx += 2;
    } else if (strcmp(argv[idx], "--loop-time") == 0 && idx + 1 < argc) {
      g_config.loop_time = atoi(argv[idx + 1]);
      idx += 2;
    } else if (strcmp(argv[idx], "--enable-ip-rewrite") == 0 &&
               idx + 1 < argc) {
      g_config.enable_ip_rewrite = atoi(argv[idx + 1]);
      idx += 2;
    } else {
      printf("wrong option %s\n", argv[idx]);
      exit(EXIT_FAILURE);
    }
  }
}

int main(int argc, char const *argv[]) {
  parse_cli_option(argc, argv);
  // sender process is created automatically
  endpoint *recv_ep = get_recv_endpoint();
  assert(recv_ep != NULL);
  receiver(recv_ep);
  clean_up_recv_endpoint(recv_ep);

  return 0;
}
