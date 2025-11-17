#! /bin/env python3
import argparse
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.http import HTTPRequest, HTTP
from scapy.layers.l2 import Ether
import random
from scapy.utils import wrpcap, rdpcap
from dataclasses import dataclass


SRC_MAC = "6C:B3:11:50:D3:DA"
DST_MAC = "3C:FD:FE:EC:48:11"


def generate_random_ipv4_addr():
    a = random.randrange(1, 255)
    b = random.randrange(1, 255)
    c = random.randrange(1, 255)
    d = random.randrange(1, 255)
    return f"{a}.{b}.{c}.{d}"


def check_if_tcp_or_udp(pkt):
    return pkt.haslayer(IP) and pkt.haslayer(TCP) or pkt.haslayer(UDP)


def generate_single_flow_template_pcap():
    # each packet in a single flow is considered a "stage"
    pass
    src_ip, dst_ip = generate_random_ipv4_addr(), generate_random_ipv4_addr()
    eth = Ether(src=SRC_MAC, dst=DST_MAC)
    ip = IP(src=src_ip, dst=dst_ip)
    # Assumed we have differenct stage
    pkts = []
    tcp = TCP(flags="S", sport=1025, seq=0)

    syn = eth / ip / tcp
    pkts.append(syn)

    tcp = TCP(flags="A", sport=1025, seq=1)

    ack = eth / ip / tcp

    pkts.append(ack)

    tcp = TCP(flags="F", sport=1025, seq=1)

    fin = eth/ip/tcp

    pkts.append(fin)

    return pkts


def generate_packet_from_template_flow(pkts, num_flows):
    pass
    flows = []
    # dst_port = 1025
    for flow_idx in range(num_flows):
        flow_pkts = []
        src_ip = generate_random_ipv4_addr()

        for pkt in pkts:
            pkt = pkt.copy()
            assert pkt.haslayer(IP)
            ip_layer = pkt.getlayer(IP)
            tcp_layer = pkt.getlayer(TCP)
            # tcp_layer.
            ip_layer.src = src_ip
            flow_pkts.append(pkt)
        flows.append(flow_pkts)

    num_stages = len(pkts)

    result = []

    for stage in range(num_stages):
        for flow_idx in range(num_flows):
            result.append(flows[flow_idx][stage])

    return result


class Endpoint:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    def __eq__(self, other):
        return self.ip == other.ip and self.port == other.port

    def __str__(self):
        return f"ip={self.ip},port={self.port}"

    def __lt__(self, other):
        if self.ip < other.ip:
            return True
        elif self.ip > other.ip:
            return False

        if self.port < other.port:
            return True

        return False


class EndpointPair:
    def __init__(self, ep_a: Endpoint, ep_b: Endpoint, proto: str):
        if ep_a < ep_b:
            self.ep1 = ep_a
            self.ep2 = ep_b
        else:
            self.ep1 = ep_b
            self.ep2 = ep_a
        self.proto = proto

    def __hash__(self):
        return hash(str(self.ep1)+" "+str(self.ep2)+" "+self.proto)

    def __eq__(self, other):
        return self.ep1 == other.ep1 and self.ep2 == other.ep2 and self.proto == other.proto
    


def add_flow_dict(flow_dict: dict, ep_pair: EndpointPair, pkt):
    if ep_pair not in flow_dict:
        flow_dict[ep_pair] = {"pkts": [pkt], "cur_idx": 0}
    else:
        flow_dict[ep_pair]['pkts'].append(pkt)
    


def construct_flow_from_template_pcap(template_pkts, num_flows, consecutive_packets):

    tcp_flow_dict = dict()
    udp_flow_dict = dict()
    all_flow_dict = dict()

    for pkt in template_pkts:
        if not check_if_tcp_or_udp(pkt):
            continue
        ip_layer = pkt.getlayer(IP)
        src_ip, dst_ip = ip_layer.src, ip_layer.dst
        if pkt.haslayer(TCP):
            tcp_layer = pkt.getlayer(TCP)
            proto = "TCP"
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
        elif pkt.haslayer(UDP):
            udp_layer = pkt.getlayer(UDP)
            proto = "UDP"
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
        else:
            raise "Not supported packet"
        
        src_endpoint, dst_endpoint = Endpoint(
            src_ip, src_port), Endpoint(dst_ip, dst_port)
        
        pair = EndpointPair(src_endpoint, dst_endpoint, proto)

        if proto == "TCP":
            add_flow_dict(tcp_flow_dict, pair, pkt)
        elif proto =="UDP":
            add_flow_dict(udp_flow_dict, pair, pkt)
        
        add_flow_dict(all_flow_dict, pair, pkt)
        
    tcp_flows = list(tcp_flow_dict.values())
    udp_flows = list(udp_flow_dict.values())
    pkts_list = []

    for wnd_idx in range((len(tcp_flows)+num_flows)//num_flows):
        wnd_left = wnd_idx*num_flows
        wnd_right = min((wnd_idx+1)*num_flows, len(tcp_flows))

        tcp_subflows = tcp_flows[wnd_left:wnd_right]

        while True:
            found = False
            for tcp_flow in tcp_subflows:
                for _ in range(consecutive_packets):
                    cur = tcp_flow['cur_idx']
                    if len(tcp_flow['pkts']) == cur:
                        break

                    found = True
                    pkts_list.append(tcp_flow['pkts'][cur])
                    tcp_flow['cur_idx'] = cur+1
            if not found:
                break

    return pkts_list
    

if __name__ == "__main__":
    random.seed(42)
    parser = argparse.ArgumentParser("transform_pcap")
    parser.add_argument("--template",
                        help="pcap file name of the template flow", type=str, default=None)
    parser.add_argument(
        "--num-flow", help="number of the flow in the generated pcap", type=int, default=4)
    parser.add_argument(
        '--consecutive-packets', type=int, default=4
    )
    parser.add_argument(
        "--output", help="output file name", default="transformed.pcap", type=str
    )

    args = parser.parse_args()
    if args.template != None:
        template = rdpcap(args.template)
        wrpcap("template.pcap", template)
    else:
        template = generate_single_flow_template_pcap()

    # result = generate_packet_from_template_flow(
    #     template, num_flows=args.num_flow)

    result = construct_flow_from_template_pcap(
        template_pkts=template, num_flows=args.num_flow, consecutive_packets=args.consecutive_packets)
    wrpcap(args.output, result)
