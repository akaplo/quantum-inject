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

def find_injected_packets(packet):
    # We know the packet has the Raw layer, make sure it has a payload too
    if hasattr(packet.getlayer('Raw'), 'load'):
        # Go through every other sniffed packet and see if this one matches any
        for check_against in sniffed:
            # IP destination is same?
            if check_against[IP].dst == packet[IP].dst:
                # IP source is same?
                if check_against[IP].src == packet[IP].src:
                    # TCP source port is same?
                    if check_against[TCP].sport == packet[TCP].sport:
                        # IP destination port is same?
                        if check_against[TCP].dport == packet[TCP].dport:
                            # TCP sequence number is same?
                            if check_against[TCP].seq == packet[TCP].seq:
                                # TCP ack number is same?
                                if check_against[TCP].ack == packet[TCP].ack:
                                    # So far, we'd match any packet that's a duplicate
                                    # or retransmision.
                                    # If the packet was injected, all of the above would still
                                    # hold, but the payload wouldn't match:
                                    if check_against[TCP][Raw].load != packet[TCP][Raw].load:
                                        print '************************************************************************'
                                        print 'injection motherfucker'
                                        # We can assume that the legitmate packet arrived after the
                                        # injected one, so check_against must've been injected, since
                                        # the nature of this function is such that a packet from the global
                                        # list is less recent than the packet that this function was called with.
                                        print "Injected packet's payload:"
                                        print check_against[Raw].load
                                        print "Legitmate packet's payload:"
                                        print packet[Raw].load
                                        print '************************************************************************'
        # Now outside of the loop, we add the newest packet to the
        # global list so that it can be used to check against newer packets
        sniffed.append(packet)

if (args.file):
    packets = sniff(offline=args.file, filter="tcp and port 80", lfilter=lambda r: r.haslayer(Raw), prn=lambda pkt: find_injected_packets(pkt))
else:
    # Sniff packets straight from the given network interface.

    # We arbitrarily limit the number of packets to capture before closing up shop
    # for the sake of speed.  If packets are coming rapid-fire, find_injected_packets
    # may get so far behind (sure, it's a linear function, but still...)
    # that the script will be reporting injected packets
    # long after the fact.
    sniffed_packets = sniff(count=5000, iface=args.interface, filter="tcp and port 80", lfilter=lambda r: r.haslayer(Raw), prn=lambda k: find_injected_packets(k))
