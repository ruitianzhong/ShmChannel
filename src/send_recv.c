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
};

struct config g_config = {
    .send_pps = 100,
    .elapsed_second = 5,
    .max_sent_packet_number = -1,
    .pcap_file_path = "packet.pcap",
    .q_depth = 128,
};

struct endpoint {
  shm_channel *chan;
  void *data_region;
  int data_region_length;
};

typedef struct endpoint endpoint;

struct packet_info {
  char *addr;
  int len;
};

void load_pcap_packet() {
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
  shm_channel_close(ep->chan);
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
    } else if (strncmp(argv[idx], "--max_sent_packet_number") == 0 &&
               idx + 1 < argc) {
      g_config.elapsed_second = atoi(argv[idx + 1]);
      idx += 2;
    } else if (strncmp(argv[idx], "--queue-depth", 14) == 0 && idx + 1 < argc) {
      g_config.q_depth = atoi(argv[idx + 1]);
      idx += 2;
    } else {
      printf("wrong option %s\n", argv[idx]);
      exit(EXIT_FAILURE);
    }
  }
}

int main(int argc, char const *argv[]) { return 0; }
