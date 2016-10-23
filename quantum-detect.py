# To detect:
# read a packet's seq/ack nums and payload size
# if another packet has the same seq/ack nums, consider it for alerting.
# Throw out all others
# Before alerting, check the see if the payload is mostly identical.
# Alert if so, otherwise throw it out.

# That sounds n^2.  Any way to do it better?

# python 2.7
# how to run: python quantum.py --interface eth0 --regexp /^regex$/ --datafile someFIle expr
import argparse
from scapy.all import *

parser = argparse.ArgumentParser(description='idk')
parser.add_argument("--interface", help="interface")

parser.add_argument("--file", help="tcpdump input to parse and check for injections")
parser.add_argument("expression", help="straight up input")

args = parser.parse_args()

sniffed_packets = []

if (args.file):
    input_dump = rdpcap(args.file)
    sorted_dump = sorted(input_dump, key=lambda pkt: pkt[TCP].seq)
    find_injected_packets(sorted_dump)
else:
    global sniffed_packets = sniff(iface=args.interface, filter="tcp and port 80", lfilter=lambda p: "GET" in str(p),
        prn=determine_sniffed_injection)

def determine_sniffed_injection(packet):
    global sniffed_packets.sort(key=lambda pkt: pkt[TCP].seq)
    find_injected_packets(sniffed_packets)

def find_injected_packets(pkt_list):
    for index, packet in enumerate(pkt_list):
        try:
            packet[TCP][Raw]
        except IndexError:
            print 'packet doesnt have raw payload'
        else:
            if packet[TCP].seq == pkt_list[index+1][TCP].seq:
                # the sequence numbers are equal. Might be a duplicate!
                # Let's check for equivalent acks too
                if packet[TCP].ack == pkt_list[index+1][TCP].ack:
                    # the ack numbers are equal too!
                    # If the payload is not the same, then
                    # we can say the packet that came first is injected
                    if packet[TCP][Raw].load != pkt_list[index+1][TCP][Raw].load:
                        print 'Looks like an injected packet!'
                        print packet.summary()
