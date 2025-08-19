#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <netinet/in.h>
#include <pcap.h>
#include <sched.h>
#include <shm_channel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include <wait.h>

#define MAKE_IP_ADDR(a, b, c, d) \
  (((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | (uint32_t)d)

struct config {
  // packet per second
  int send_pps;
  // total time
  int elapsed_second;
  //  max sent packet number
  int max_sent_packet_number;
  // pcap file path
  char *pcap_file_path;
  // ring queue depth
  int q_depth;
  // sender core affinity mask
  int sender_cpu_id;
  // receiver core affinity mask
  int receiver_cpu_id;
  // batch_size
  int batch_size;
  // loop time
  int loop_time;
  // sanity check flag
  int sanity_check;
  // enable rewriting
  int enable_ip_rewrite;
};

struct config g_config = {
    .send_pps = 0,
    .max_sent_packet_number = -1,
    .pcap_file_path = "packet.pcap",
    .q_depth = 128,
    .batch_size = 32,
    .loop_time = 10,
    .sender_cpu_id = -1,
    .receiver_cpu_id = -1,
    .enable_ip_rewrite = 0,
};

struct packet_info {
  char *addr;
  int len;
};

struct endpoint {
  shm_channel *chan;
  void *data_region;
  int data_region_length;
  struct packet_info *packet_info;
  int packet_cnt;
};

typedef struct endpoint endpoint;

void load_pcap_packet(endpoint *ep) {
  int packet_cnt = 0, byte_cnt = 0;

  char err_buf[PCAP_ERRBUF_SIZE];

  pcap_t *handle = pcap_open_offline(g_config.pcap_file_path, err_buf);

  if (handle == NULL) {
    printf("Failed to open pcap file: %s\n", err_buf);
    exit(EXIT_FAILURE);
  }
  const u_char *packet;
  struct pcap_pkthdr pkthdr;

  while ((packet = pcap_next(handle, &pkthdr)) != NULL) {
    packet_cnt++;
    // actually catured
    byte_cnt += pkthdr.caplen;
  }

  pcap_close(handle);

  if (g_config.enable_ip_rewrite) {
    // ensure that we can safely rewrite IP header
    if (packet_cnt < g_config.batch_size * 2 + g_config.q_depth) {
      printf("packet number is too small\n");
      exit(EXIT_FAILURE);
    }
  }

  void *memory_region = mmap(NULL, byte_cnt, PROT_READ | PROT_WRITE,
                             MAP_SHARED | MAP_ANONYMOUS, -1, 0);

  if (memory_region == MAP_FAILED) {
    perror("load_pcap_packet mmap");
    exit(EXIT_FAILURE);
  }
  struct packet_info *info = calloc(packet_cnt, sizeof(struct packet_info));

  assert(info != NULL);

  // re-open it

  handle = pcap_open_offline(g_config.pcap_file_path, err_buf);

  if (handle == NULL) {
    printf("Failed to open pcap file: %s\n", err_buf);
    exit(EXIT_FAILURE);
  }

  int idx = 0;
  void *cur_addr = memory_region;

  while ((packet = pcap_next(handle, &pkthdr)) != NULL) {
    assert(cur_addr + pkthdr.caplen <= memory_region + byte_cnt);
    memcpy(cur_addr, packet, pkthdr.caplen);
    info[idx].addr = cur_addr;
    info[idx].len = pkthdr.caplen;
    cur_addr = cur_addr + pkthdr.caplen;
    idx++;
  }

  pcap_close(handle);

  ep->data_region = memory_region;
  ep->data_region_length = byte_cnt;
  ep->packet_info = info;
  ep->packet_cnt = packet_cnt;
}

endpoint *endpoint_create() {
  endpoint *ep = (endpoint *)calloc(sizeof(endpoint), 1);

  if (ep == NULL) {
    return NULL;
  }

  ep->chan = shm_channel_open(g_config.q_depth);

  if (NULL == ep->chan) {
    free(ep);
    return NULL;
  }

  load_pcap_packet(ep);

  return ep;
}

void endpoint_free(endpoint *ep) {
  assert(ep != NULL);
  if (munmap(ep->data_region, ep->data_region_length) == -1) {
    perror("endpoint_free munmap");
  }
  free(ep->packet_info);
  shm_channel_close(ep->chan);
  free(ep);
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

uint64_t calculate_batch_interval_ns(int batch_size, int pps) {
  if (pps == 0) {
    return 0;
  }

  uint64_t ns_per_second = 1e9;
  uint64_t interval_ns = (ns_per_second / pps) * batch_size;
  return interval_ns;
}

void rewrite_src_ip(u_char *pkt, int pkt_len) {
  if (pkt_len < 30) {
    return;
  }
  // ipv4 src ip
  uint32_t *src = (uint32_t *)(pkt + 26);
  // get the deterministic result for each flow
  // srand(*src); // high overhead, not use it.
  // can be improved with better strategy
  *src = (*src) + 1;

  return;
}

void set_cpu_affinity(int cpuid) {
  cpu_set_t cpu_set;
  CPU_ZERO(&cpu_set);
  CPU_SET(cpuid, &cpu_set);
  if (sched_setaffinity(0, sizeof(cpu_set), &cpu_set) < 0) {
    perror("sched_setaffinity");
    exit(EXIT_FAILURE);
  }

  return;
}

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

void sender(endpoint *ep) {
  if (g_config.sender_cpu_id != -1) {
    printf("sender bind cpu %d\n", g_config.sender_cpu_id);
    set_cpu_affinity(g_config.sender_cpu_id);
  }

  int batch_size = g_config.batch_size;

  task_descriptor *batch = calloc(g_config.batch_size, sizeof(task_descriptor));

  uint64_t wait_ns = calculate_batch_interval_ns(batch_size, g_config.send_pps);

  assert(batch != NULL);

  for (int iter = 0; iter < g_config.loop_time; iter++) {
    int sent = 0;
    while (sent < ep->packet_cnt) {
      for (int j = 0; j < batch_size; j++) {
        if (sent == 0) {
          batch[j].magic = j;
        } else {
          batch[j].magic += batch_size;
        }
      }

      int current_batch = batch_size < (ep->packet_cnt - sent)
                              ? batch_size
                              : (ep->packet_cnt - sent);

      // replenish the packet

      for (int i = 0; i < current_batch; i++) {
        batch[i].len = ep->packet_info[i + sent].len;
        batch[i].start_addr = ep->packet_info[i + sent].addr;
        if (sent && g_config.enable_ip_rewrite) {
          rewrite_src_ip(batch[i].start_addr, batch[i].len);
        }
      }

      int idx = 0;

      while (idx < current_batch) {
        int ret =
            shm_channel_send_burst(ep->chan, &batch[idx], current_batch - idx);

        idx += ret;
        sent += ret;
      }

      busy_wait(wait_ns);
    }
  }
}

void receiver(endpoint *ep) {
  if (g_config.receiver_cpu_id != -1) {
    printf("receiver bind cpu %d\n", g_config.sender_cpu_id);

    set_cpu_affinity(g_config.receiver_cpu_id);
  }

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

int main(int argc, char const *argv[]) {
  parse_cli_option(argc, argv);

  endpoint *ep = endpoint_create();

  assert(ep != NULL);

  int ret = fork();

  assert(ret != -1);

  if (ret == 0) {
    sender(ep);
  } else {
    receiver(ep);
    int status;
    pid_t pid = wait(&status);
    assert(pid != -1);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS);
  }

  endpoint_free(ep);
  return 0;
}
