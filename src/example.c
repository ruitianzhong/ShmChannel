#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <wait.h>

#include "reorder.h"
#include "send_recv.h"
// ./send_recv --pcap-file-path packet.pcap --pps 0  --queue-depth 1024 --batch-size 32 --loop-time 50 --enable-reorder 1 --service-time-us 20  --interactive 1

int double_compare(const void* a, const void* b) {
  double num1 = *(const double*)a;
  double num2 = *(const double*)b;

  if (num1 > num2) {
    return 1;
  } else if (num1 < num2) {
    return -1;
  } else {
    return 0;
  }
}

void print_timings(double timings[], int len) {
  double p99 = timings[(int)(len * 0.99)];
  double p999 = timings[(int)(len * 0.999)];
  double p9999 = timings[(int)(len * 0.9999)];
  double p50 = timings[(int)(len * 0.5)];
  double max_time = timings[0];
  double sum = 0.0;
  for (int i = 0; i < len; i++) {
    if (timings[i] > max_time) {
      max_time = timings[i];
    }
    sum += timings[i];
  }

  double avg = sum / (double)len;

  printf("p50=%.2f p99=%.2f p999=%.2f p9999=%.2f max_time=%.2f avg=%.2f\n", p50,
         p99, p999, p9999, max_time, avg);
}

static reorder_module* reorder_m = NULL;

static inline void busy_wait(uint64_t ns) {
  if (ns == 0) {
    return;
  }

  struct timespec start, end;

  if (clock_gettime(CLOCK_MONOTONIC, &start) == -1) {
    perror("busy_wait clock_gettime");
    exit(EXIT_FAILURE);
  }
  uint64_t delta = 0;

  do {
    if (clock_gettime(CLOCK_MONOTONIC, &end) == -1) {
      perror("busy_wait clock_gettime");
      exit(EXIT_FAILURE);
    }

    delta = (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);

  } while (delta < ns);
}

void receiver(endpoint* ep) {
  task_descriptor* batch = calloc(g_config.batch_size, sizeof(task_descriptor));

  if (g_config.enable_reorder) {
    reorder_m = reorder_module_init(ep, 4096, 1024, 4096);
  }

  assert(batch != NULL);

  uint64_t total_recv = 0;

  int bs = g_config.batch_size;

  struct timespec start, end;

  if (clock_gettime(CLOCK_MONOTONIC, &start) == -1) {
    perror("receiver clock_gettime");
    exit(EXIT_FAILURE);
  }
#ifdef MAGIC_VERIFY
  int expect_magic = 0;
#endif
  for (int iter = 0; iter < g_config.loop_time; iter++) {
    int recv = 0;
    while (recv < ep->packet_cnt) {
      int current_bs =
          bs < (ep->packet_cnt - recv) ? bs : (ep->packet_cnt - recv);
      int ret = 0;
      if (g_config.enable_reorder) {
        ret = reorder_receive_pkts(reorder_m, batch, current_bs);
      } else {
        ret = shm_channel_recv_burst(ep->chan, batch, current_bs);
      }
      for (int i = 0; i < ret; i++) {
        // handle packet
        if (g_config.service_time_us > 0) {
          busy_wait(g_config.service_time_us * 1000);
        }

        struct timespec curr;
        assert(clock_gettime(CLOCK_MONOTONIC, &curr) != -1);
        double elapsed_us =
            (double)(curr.tv_sec - batch[i].sent_time.tv_sec) * 1E6 +
            (curr.tv_nsec - batch[i].sent_time.tv_nsec) / 1000.0;

        ep->timings[iter * ep->packet_cnt + recv + i] = elapsed_us;
#ifdef MAGIC_VERIFY

        if (batch[i].magic != expect_magic) {
          printf("%d %d i=%d received=%d cur_bs=%d\n", batch[i].magic,
                 expect_magic, i, ret, current_bs);
        }
        assert(batch[i].magic == expect_magic);
        expect_magic++;

#endif
      }
      recv += ret;
      total_recv += ret;
    }
  }

  if (clock_gettime(CLOCK_MONOTONIC, &end) == -1) {
    perror("receiver clock_gettime");
    exit(EXIT_FAILURE);
  }
  printf("experiment done. Process the data\n");
  qsort(ep->timings, ep->packet_cnt * g_config.loop_time, sizeof(double),
        double_compare);
  print_timings(ep->timings, ep->packet_cnt * g_config.loop_time);
  uint64_t ns_elapsed =
      (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
  double receive_pps = (double)(1e9 * total_recv) / (double)ns_elapsed;
  printf("receive pps=%.2f kpps=%.2f\n", receive_pps, receive_pps / 1000.0);

  if (g_config.enable_reorder) {
    reorder_module_free(reorder_m);
  }
}

void parse_cli_option(int argc, char const* argv[]) {
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
    } else if (strcmp(argv[idx], "--enable-reorder") == 0 && idx + 1 < argc) {
      g_config.enable_reorder = atoi(argv[idx + 1]);
      idx += 2;
    } else if (strcmp(argv[idx], "--service-time-us") == 0 && idx + 1 < argc) {
      g_config.service_time_us = atoi(argv[idx + 1]);
      idx += 2;
    } else if (strcmp(argv[idx], "--interactive") == 0 && idx + 1 < argc) {
      g_config.interactive = atoi(argv[idx + 1]);
      idx += 2;
    } else {
      printf("wrong option %s\n", argv[idx]);
      exit(EXIT_FAILURE);
    }
  }
}

int main(int argc, char const* argv[]) {
  printf("sender process pid %d\n", getpid());

  int x = 0;

  parse_cli_option(argc, argv);
  if (g_config.interactive) {
    printf("receiver pid=%d\nPlease enter a number: ", getpid());
    scanf("%d", &x);
  }

  printf("start the experiment\n");
  // sender process is created automatically
  endpoint* recv_ep = get_recv_endpoint();
  assert(recv_ep != NULL);
  receiver(recv_ep);
  clean_up_recv_endpoint(recv_ep);

  return 0;
}
