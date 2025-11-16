#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <math.h>
#include <netinet/in.h>
#include <pcap.h>
#include <sched.h>
#include <send_recv.h>
#include <shm_channel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include <wait.h>

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
    .seed = 42,
    .dist_type = "exp",
};

#define MAKE_IP_ADDR(a, b, c, d) \
  (((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | (uint32_t)d)

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

void debug_pcap(endpoint *ep) {
  int debug_pkt = ep->packet_cnt > 10 ? 10 : ep->packet_cnt;
  pcap_t *pcap_handle;
  pcap_dumper_t *dumper;
  // max packet length 65535
  pcap_handle = pcap_open_dead(DLT_EN10MB, 65535);
  if (pcap_handle == NULL) {
    fprintf(stderr, "cannot create pcap handle\n");
    exit(EXIT_FAILURE);
  }

  dumper = pcap_dump_open(pcap_handle, "debug.pcap");
  if (dumper == NULL) {
    fprintf(stderr, "can not open %s\n", pcap_geterr(pcap_handle));
    pcap_close(pcap_handle);
    exit(EXIT_FAILURE);
  }

  for (int i = 0; i < debug_pkt; i++) {
    struct pcap_pkthdr header;

    header.caplen = ep->packet_info[i].len;
    header.len = header.caplen;

    pcap_dump((unsigned char *)dumper, &header,
              (unsigned char *)ep->packet_info[i].addr);
  }

  pcap_dump_close(dumper);
  pcap_close(pcap_handle);
  printf("debug end\n");
  return;
}

void random_init(unsigned int seed) { srand(seed); }

double exponetial_random(double lambda) {
  assert(lambda > 0);
  double u;
  do {
    u = (double)rand() / (RAND_MAX + 1.0);
  } while (u == 0.0);

  return -log(u) / lambda;
}

void endpoint_init_relative_send_ts(endpoint* ep) {
  if (g_config.send_pps <= 0) {
    return;
  }
  ep->send_us_timestamp =
      calloc(ep->packet_cnt * g_config.loop_time, sizeof(double));
  assert(ep->send_us_timestamp != NULL);
  double start = 0.0;
  double lambda = 1 / (1E6 / g_config.send_pps);
  for (int i = 0; i < ep->packet_cnt * g_config.loop_time; i++) {
    start += exponetial_random(lambda);
    ep->send_us_timestamp[i] = start;
  }
}

void endpoint_destroy_relative_send_ts(endpoint* ep) {
  if (g_config.send_pps <= 0) {
    return;
  }
  free(ep->send_us_timestamp);
}

endpoint *endpoint_create() {
  endpoint *ep = (endpoint *)calloc(sizeof(endpoint), 1);

  if (ep == NULL) {
    return NULL;
  }

  ep->chan = shm_channel_open(g_config.q_depth);
  ep->send_proc_pid = 0;

  if (NULL == ep->chan) {
    free(ep);
    return NULL;
  }

  load_pcap_packet(ep);

  endpoint_init_relative_send_ts(ep);

  return ep;
}

void endpoint_free(endpoint *ep) {
  assert(ep != NULL);
  if (munmap(ep->data_region, ep->data_region_length) == -1) {
    perror("endpoint_free munmap");
  }
  free(ep->packet_info);
  shm_channel_close(ep->chan);
  endpoint_destroy_relative_send_ts(ep);
  free(ep);
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

// ensure that g_config is correctly init before calling init_all
endpoint *get_recv_endpoint() {
  endpoint *ep = endpoint_create();
  assert(ep != NULL);
  int ret = fork();

  assert(ret != -1);

  if (ret == 0) {
    if (g_config.sender_cpu_id != -1) {
      printf("sender bind cpu %d\n", g_config.sender_cpu_id);
      set_cpu_affinity(g_config.sender_cpu_id);
    }

    sender(ep);
    endpoint_free(ep);
    exit(EXIT_SUCCESS);
  }

  if (g_config.receiver_cpu_id != -1) {
    printf("receiver bind cpu %d\n", g_config.receiver_cpu_id);

    set_cpu_affinity(g_config.receiver_cpu_id);
  }
  ep->send_proc_pid = ret;

  return ep;
}

void clean_up_recv_endpoint(endpoint *receive_endpoint) {
  int status;
  pid_t pid = waitpid(receive_endpoint->send_proc_pid, &status, 0);
  assert(pid != -1);
  assert(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS);
}
