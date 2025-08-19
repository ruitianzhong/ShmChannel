#include <shm_channel.h>

#ifndef _SEND_RECV
#define _SEND_RECV

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
  pid_t send_proc_pid;
};

typedef struct endpoint endpoint;
extern struct config g_config;
endpoint *endpoint_create();
void endpoint_free(endpoint *ep);
endpoint *get_recv_endpoint();
void clean_up_recv_endpoint(endpoint *receive_endpoint);
#endif
