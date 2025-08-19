# ShmChannel


## Install Dependencies

```bash
# To run testing scripts
pip install scapy matplotlib pytest
sudo apt install libpcap-dev cmake
```

## Build

```bash
mkdir build && cd build
cmake ..
make
```

## Usage

Run basic testing programs, and they will check wether the requests are delivered in order.

```bash
cd build
# send `num_requests` requests with a specific batch_size
./test_burst_request [q_depth] [batch_size] [num_requests]
# send `num_requests` requests one by one (i.e., batch_size=1)
./test_single_request [q_depth] [num_total_request]
# Automatic test with many combinations
./script/test_shm_channel.py
```


Run the send-recv app:
```bash
cd build
# generate packet.pcap 
./script/pcap_packet_gen.py --packet-num=4096 --filename=packet.pcap
# pps is unlimited
./send_recv --pcap-file-path packet.pcap --pps 0 --queue-depth 1024 --batch-size 32 --loop-time 1000
# pps is set
./send_recv --pcap-file-path packet.pcap --pps 20000 --queue-depth 1024 --batch-size 32 --loop-time 100
# pps is set
./send_recv --pcap-file-path packet.pcap --pps 1024 --queue-depth 1024 --batch-size 32 --loop-time 5
# Enable CPU binding
./send_recv --pcap-file-path packet.pcap --pps 0  --queue-depth 1024 --batch-size 32 --loop-time 100000 --sender-cpu 0 --recv-cpu 1 --enable-ip-rewrite 1
```


## ShmChannel API

+ `shm_channel* shm_channel_open(int q_depth)`

+ `void shm_channel_close(shm_channel*)`

`int shm_channel_send_burst(shm_channel* chan, task_descriptor* send_descs,int num_descriptors)`

`int shm_channel_recv_burst(shm_channel* chan, task_descriptor* recv_descs, int num_descriptor)`

`int shm_channel_free_count(shm_channel* chan)`

`int shm_channel_used_count(shm_channel* chan)`