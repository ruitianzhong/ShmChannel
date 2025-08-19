import argparse
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.http import HTTPRequest, HTTP
from scapy.layers.l2 import Ether
import random
from scapy.utils import wrpcap, rdpcap


SRC_MAC = "6C:B3:11:50:D3:DA"
DST_MAC = "3C:FD:FE:EC:48:11"

def generate_random_ipv4_addr():
    a = random.randrange(1, 255)
    b = random.randrange(1, 255)
    c = random.randrange(1, 255)
    d = random.randrange(1, 255)
    return f"{a}.{b}.{c}.{d}"


def generate_single_flow_template_pcap():
    # each packet in a single flow is considered a "stage"
    pass    
    src_ip, dst_ip = generate_random_ipv4_addr(), generate_random_ipv4_addr()
    eth = Ether(src=SRC_MAC, dst=DST_MAC)
    ip = IP(src=src_ip, dst=dst_ip)
    # Assumed we have differenct stage
    pkts = []
    tcp = TCP(flags="S", sport=1025, seq=0)

    syn = eth / ip /tcp
    pkts.append(syn)

    tcp = TCP(flags="A",sport=1025,seq=1)

    ack = eth / ip /tcp

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


if __name__ == "__main__":
    random.seed(42)
    parser = argparse.ArgumentParser("transform_pcap")
    parser.add_argument("--template",
                        help="pcap file name of the template flow", type=str, default=None)
    parser.add_argument(
        "--num-flow", help="number of the flow in the generated pcap", type=int, default=4)
    parser.add_argument(
        "--output", help="output file name", default="transformed.pcap", type=str
    )

    args = parser.parse_args()
    if args.template != None:
        template = rdpcap(args.template)
        wrpcap("template.pcap", template)
    else:
        template = generate_single_flow_template_pcap()
   
    result = generate_packet_from_template_flow(
        template, num_flows=args.num_flow)
    wrpcap(args.output, result)
