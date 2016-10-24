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
import re
from time import *


parser = argparse.ArgumentParser()
parser.add_argument("-i", "--interface", dest="interface", help="interface", required=True)

parser.add_argument("-r", "--file", dest="file", help="tcpdump input to parse and check for injections")

args = parser.parse_args()

sniffed = []

def find_injected_packets(pkt_list):
    #print 'hello'
    for index, packet in enumerate(pkt_list):
        #print index
        #print sniffed_packets
        try:
            packet[TCP][Raw]
        except IndexError:
            print 'packet doesnt have raw payload'
        else:
            try:
                pkt_list[index+1][TCP][Raw]
            except IndexError:
                print 'packet doesnt have raw payload'
            else:
                if index < len(pkt_list) - 1:
                    #print packet[TCP].seq
                    if packet[TCP].seq == pkt_list[index+1][TCP].seq:
                        # the sequence numbers are equal. Might be a duplicate!
                        # Let's check for equivalent acks too
                        print 'matched seqnum'
                        if packet[TCP].ack == pkt_list[index+1][TCP].ack:
                            # the ack numbers are equal too!
                            # If the payload is not the same, then
                            # we can say the packet that came first is injected
                            print 'matched acknum'
                            #print packet[TCP][Raw].load
                            #print pkt_list[index+1][TCP][Raw].load
                            if packet[TCP][Raw].load != pkt_list[index+1][TCP][Raw].load:
                                print 'Looks like an injected packet!'
                                print packet[TCP][Raw].load


def append_pkt(pkt):
    print 'append packet'
    global sniffed
    if len(sniffed) > 500:
        print 'got to 500 packets!'
        sniffed.sort(key=lambda pkt: pkt[TCP].seq)
        find_injected_packets(sniffed)
        sniffed = sniffed[400:500]
    else:
        sniffed.append(pkt)

if (args.file):
    input_dump = rdpcap(args.file)
    sorted_dump = sorted(input_dump, key=lambda pkt: pkt[TCP].seq)
    find_injected_packets(sorted_dump)
else:
    sniffed_packets = sniff(iface=args.interface, filter="tcp port 80", lfilter=lambda r: r.haslayer(Raw), prn=append_pkt)
