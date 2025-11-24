#!/bin/env python3
import argparse
from scapy.layers.inet import IP, UDP, TCP
from scapy.utils import rdpcap, wrpcap
if __name__ == "__main__":
    parser = argparse.ArgumentParser("pcap_filter")
    parser.add_argument("--input", type=str)
    parser.add_argument("--output", type=str)

    args = parser.parse_args()

    pkts = rdpcap(args.input)

    saved = []

    for pkt in pkts:
        if pkt.haslayer(TCP) or pkt.haslayer(UDP):
            saved.append(pkt)
    wrpcap(args.output, saved)
