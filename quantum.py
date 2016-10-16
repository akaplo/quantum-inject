# python 2.7
# how to run: python quantum.py --interface eth0 --regexp /^regex$/ --datafile someFIle expr
import argparse
import scapy
import re

parser = argparse.ArgumentParser(description='idk')
parser.add_argument("--interface", help="interface")
parser.add_argument("--regexp", help="regular expression")
parser.add_argument("--datafile", help="datafile input")
parser.add_argument("expression", help="straight up input")

args = parser.parse_args()
print args
print args.interface
print args.regexp
print args.datafile
print args.expression

# sniff the given interface for tcp packets
packets = scapy.sniff(iface=args.interface, filter="tcp")
# compile the given regex for use
regex = re.compile(args.regexp)
# must check each packet individually
for packet in  packets:
    # re.match vs re.search?
    # packet must be a string, so this may not work
    # See if the packet matches the given regex
    if(re.search(regex, packet)):
        print packet
