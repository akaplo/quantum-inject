# python 2.7
# how to run: python quantum.py --interface eth0 --regexp /^regex$/ --datafile someFIle expr
import argparse
from scapy.all import *
import re

parser = argparse.ArgumentParser(description='idk')
parser.add_argument("--interface", help="interface")
parser.add_argument("--regexp", help="regular expression")
parser.add_argument("--datafile", help="datafile input")
parser.add_argument("expression", help="straight up input")

args = parser.parse_args()
# print args
# print args.interface
# print args.regexp
# print args.datafile
# print args.expression

# callback, called for each sniffed packet
# Determine whether we should allow it or not.
def determine_bad_packet(packet):
    print packet[IP].src, packet[IP].dst
    # compile the given regex for use
    regex = re.compile(args.regexp)
    # If the regex has any matches in the tcp
    # payload, we should inject a packet!
    if (re.search(regex, packet[TCP][Raw].load)):
        print 'matched'
        inject_packet(packet)

# Given a flagged packet, injects a packet
def inject_packet (flagged_packet):


# sniff the given interface for tcp packets
packets = sniff(iface=args.interface, count=10, filter="tcp", prn=determine_bad_packet)

# must check each packet individually
# for packet in  packets:
#     # re.match vs re.search?
#     # packet must be a string, so this may not work
#     # See if the packet matches the given regex
#     if(re.search(regex, packet)):
#         print packet
