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

Testing program:
```bash
# send `num_requests` requests with a specific batch_size
./test_burst_request.c [q_depth] [batch_size] [num_requests]
# send `num_requests` requests one by one (i.e., batch_size=1)
./test_single_request [q_depth] [num_total_request]
```