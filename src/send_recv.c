#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <pcap.h>
#include <shm_channel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

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
  uint64_t sender_affinity_mask;
  // receiver core affinity mask
  uint64_t receiver_affinity_mask;
  // batch_size
  int batch_size;
};

struct config g_config = {
    .send_pps = 100,
    .elapsed_second = 5,
    .max_sent_packet_number = -1,
    .pcap_file_path = "packet.pcap",
    .q_depth = 128,
    .sender_affinity_mask = 0,
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
  char *packet;
  struct pcap_pkthdr pkthdr;

  while (packet = pcap_next(handle, &pkthdr)) {
    packet_cnt++;
    // actually catured
    byte_cnt += pkthdr.caplen;
  }

  pcap_close(handle);

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
  char *cur_addr = memory_region;

  while (packet = pcap_next(handle, &pkthdr)) {
    assert(cur_addr + pkthdr.caplen < memory_region + byte_cnt);
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

int parse_cli_option(int argc, char const *argv[]) {
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
    } else if (strcmp(argv[idx], "--sender-mask") == 0 && idx + 1 < argc) {
      g_config.sender_affinity_mask = atoi(argv[idx + 1]);
      idx += 2;
    } else if (strcmp(argv[idx], "--recv-mask") == 0 && idx + 1 < argc) {
      g_config.receiver_affinity_mask = atoi(argv[idx + 1]);
      idx += 2;
    } else {
      printf("wrong option %s\n", argv[idx]);
      exit(EXIT_FAILURE);
    }
  }
}

uint64_t calculate_batch_interval_ns(int batch_size, int pps) {
  uint64_t ns_per_second = 1e9;
  uint64_t interval_ns = (ns_per_second / pps) * batch_size;
  return interval_ns;
}

void busy_wait(uint64_t ns) {
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
  int sent = 0, batch_size = g_config.batch_size;

  task_descriptor *batch = calloc(g_config.batch_size, sizeof(task_descriptor));

  uint64_t wait_ns = calculate_batch_interval_ns(batch_size, g_config.send_pps);

  assert(batch != NULL);

  while (sent < ep->packet_cnt) {
    int current_batch =
        batch_size < (ep->packet_cnt - sent) ? batch_size : (ep->packet_cnt);

    // replenish the packet

    for (int i = 0; i < current_batch; i++) {
      batch[i].len = ep->packet_info[i + sent].len;
      batch[i].start_addr = ep->packet_info[i + sent].addr;
    }

    task_descriptor *batch_ptr = batch;

    while (current_batch) {
      int ret = shm_channel_send_burst(ep->chan, batch_ptr, current_batch);

      current_batch -= ret;
      batch_ptr += ret;
      sent += ret;
    }

    busy_wait(wait_ns);
  }
}

void receiver(endpoint *ep) {
  task_descriptor *batch = calloc(g_config.batch_size, sizeof(task_descriptor));

  assert(batch != NULL);

  int total_recv = 0;

  int recv = 0, bs = g_config.batch_size;

  struct timespec start, end;

  if (clock_gettime(CLOCK_MONOTONIC, &start) == -1) {
    perror("receiver clock_gettime");
    exit(EXIT_FAILURE);
  }

  while (recv < ep->packet_cnt) {
    int current_bs =
        bs < (ep->packet_cnt - recv) ? bs : (ep->packet_cnt - recv);

    int ret = shm_channel_recv_burst(ep->chan, batch, current_bs);
    recv += ret;
    total_recv += ret;
  }

  if (clock_gettime(CLOCK_MONOTONIC, &end) == -1) {
    perror("receiver clock_gettime");
    exit(EXIT_FAILURE);
  }

  uint64_t ns_elapsed =
      (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);

  double receive_pps = (double)(1e9 * total_recv) / (double)ns_elapsed;

  printf("receive pps= %.2f\n", receive_pps);
}

int main(int argc, char const *argv[]) {
  parse_cli_option(argc, argv);

  endpoint *ep = endpoint_create();

  assert(ep != NULL);

  int ret = fork();

  assert(ret != -1);

  if (ret == 0) {
    sender(ep);

    int status;
    pid_t pid = wait(&status);
    assert(pid != -1);
    assert(WIFEXITED(status) && WEXITSTATUS(status));
  } else {
    receiver(ep);
  }

  endpoint_free(ep);
  return 0;
}
