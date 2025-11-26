#! /usr/bin/python3
import time
import random
import argparse

from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.http import HTTPRequest, HTTP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

SRC_MAC = "6C:B3:11:50:D3:DA"
DST_MAC = "3C:FD:FE:EC:48:11"


def generate_random_ip():
    return str(random.randint(1, 255)) + "." + str(random.randint(1, 255)) + "." + str(
        random.randint(1, 255)) + "." + str(
        random.randint(1, 255))


def generate_packets(args):
    pkt_list = []
    for packet_idx in range(args.packet_num):
        src_ip = generate_random_ip()
        dst_ip = generate_random_ip()
        src_port = random.randint(1024, 65535)
        dst_port = random.randint(1024, 65535)
        eth = Ether(src=SRC_MAC, dst=DST_MAC)
        ip = IP(src=src_ip, dst=dst_ip)
        udp = UDP(sport=src_port, dport=dst_port)
        http = HTTP()
        httpreq = HTTPRequest()
        # It may not be realistic for HTTP over UDP, but it's a synthetic test and
        # we use it anyway.
        pkt = eth / ip / udp / http / httpreq
        pkt_list.append(pkt)

    return pkt_list


def generate_multi_bidirectional_flows(num_flows, num_pkts_per_flow):
    pkts = []

    for flow_idx in range(num_flows):
        src_ip = generate_random_ip()
        dst_ip = generate_random_ip()
        src_port = random.randint(1024, 65535)
        dst_port = random.randint(1024, 65535)

        for pkt_idx in range(num_pkts_per_flow):
            eth = Ether(src=SRC_MAC, dst=DST_MAC)
            ip = IP(src=src_ip, dst=dst_ip)
            tcp = TCP(sport=src_port, dport=dst_port)
            http = HTTP()
            httpreq = HTTPRequest()
            # It may not be realistic for HTTP over UDP, but it's a synthetic test and
            # we use it anyway.
            pkt = eth / ip / tcp / http / httpreq

            pkts.append(pkt)

            eth = Ether(src=DST_MAC, dst=SRC_MAC)
            ip = IP(src=dst_ip, dst=src_ip)
            tcp = TCP(sport=dst_port, dport=src_port)
            http = HTTP()
            httpreq = HTTPRequest()
            # It may not be realistic for HTTP over UDP, but it's a synthetic test and
            # we use it anyway.
            pkt = eth / ip / tcp / http / httpreq

            pkts.append(pkt)
    wrpcap("multi_flow.pcap", pkts)
    return pkts


def generate_tcp_udp_mix_flow(num_flows, num_pkts_per_flow):
    pkts = []

    for flow_idx in range(num_flows):
        src_ip = generate_random_ip()
        dst_ip = generate_random_ip()
        src_port = random.randint(1024, 65535)
        dst_port = random.randint(1024, 65535)

        for pkt_idx in range(num_pkts_per_flow):
            eth = Ether(src=SRC_MAC, dst=DST_MAC)
            ip = IP(src=src_ip, dst=dst_ip)
            tcp = TCP(sport=src_port, dport=dst_port)
            pkt = eth / ip / tcp

            pkts.append(pkt)

            eth = Ether(src=SRC_MAC, dst=DST_MAC)
            ip = IP(src=src_ip, dst=dst_ip)
            udp = UDP(sport=src_port, dport=dst_port)

            pkt = eth / ip / udp

            pkts.append(pkt)
    wrpcap("mix_flow.pcap", pkts)
    return pkts

def store_packets_to_pcap_file(args, packets_list):
    print("Store the generated packets to synthetic_packets.pcap")
    print(f"Total packets: {len(packets_list)}")
    filename = args.filename
    wrpcap(filename, packets_list)
    print("Done!")


"""
Make sure you have installed scapy: pip install scapy
To view the parameter, please run the following command:
./test_packet_gen.py -h 
Just for quick verification.
"""
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--packet-num", help="Total Packet Number", type=int, default=10)

    parser.add_argument(
        "--filename", help="pcap file name", type=str, default="packet.pcap"
    )

    parser.add_argument(
        "--seed", help="seed for random", type=int, default=42
    )

    parser.add_argument("--num_flows", type=int, default=8)
    parser.add_argument("--packet_per_flow", type=int, default=4)

    args = parser.parse_args()
    # For reproducible experiments
    random.seed(args.seed)
    start_time = time.time_ns()
    packets = generate_packets(args=args)
    store_packets_to_pcap_file(args, packets)
    end_time = time.time_ns()
    print(f"Total time: {(end_time - start_time) / 1000 / 1000} ms")

    generate_multi_bidirectional_flows(num_flows=args.num_flows,
                                       num_pkts_per_flow=args.packet_per_flow)
    generate_tcp_udp_mix_flow(num_flows=args.num_flows,
                              num_pkts_per_flow=args.packet_per_flow)
