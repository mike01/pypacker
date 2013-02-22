from pypacker import pypacker
from pypacker.pypacker import Packet
from pypacker import ppcap
from pypacker.layer12.ethernet import Ethernet
from pypacker.layer3.ip import IP
from pypacker.layer3.icmp import ICMP
from pypacker.layer4.tcp import TCP

import socket
import os

# create packets using raw bytes
BYTES_ETH_IP_ICMPREQ	= b"\x52\x54\x00\x12\x35\x02\x08\x00\x27\xa9\x93\x9e\x08\x00\x45\x00\x00\x54\x00\x00\x40\x00\x40\x01\x54\xc1\x0a\x00" + \
			  b"\x02\x0f\xad\xc2\x2c\x17\x08\x00\xec\x66\x09\xb1\x00\x01\xd0\xd5\x18\x51\x28\xbd\x05\x00\x08\x09\x0a\x0b\x0c\x0d" + \
			  b"\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29" + \
			  b"\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37"
packet1 = Ethernet(BYTES_ETH_IP_ICMPREQ)
print("packet contents: %s" % packet1)
print("packet as bytes: %s" % packet1.bin())
# create custom packets and concat them
packet1 = Ethernet(dst_s="aa:bb:cc:dd:ee:ff", src_s="ff:ee:dd:cc:bb:aa") + IP(src_s="192.168.0.1", dst_s="192.168.0.2") + ICMP(type=8)
print("custom packet: %s" % packet1)
# recalculate checksum by changing packet
packet1[IP].sum = 0
print("new checksum: %s" % packet1)
# get specific layers
layers = [packet1[Ethernet], packet1[IP], packet1[ICMP]]

for l in layers:
	if l is not None:
		print("found layer: %s" % l)
# check direction
packet2 = Ethernet(dst_s="ff:ee:dd:cc:bb:aa", src_s="aa:bb:cc:dd:ee:ff") + IP(src_s="192.168.0.2", dst_s="192.168.0.1") + ICMP(type=8)
dir = packet1.direction(packet2)

if dir == Packet.DIR_SAME:
	print("same direction for packet 1/2")
elif dir == Packet.DIR_REV:
	print("reverse direction for packet 1/2")
else:
	print("unknown direction for packet 1/2, type: %d" % dir)
# read packets from pcap-file using pypacker-reader
f = open("packets.pcap", "rb")
pcap = ppcap.Reader(f)
cnt = 0

for ts, buf in pcap:
	cnt += 1
	eth = Ethernet(buf)

	if eth[TCP] is not None:
		print("%9.3f: %s:%s -> %s:%s" % (ts, eth[IP].src_s, eth[TCP].sport, eth[IP].dst_s, eth[TCP].dport))
# read packets from pcap-file/network-interface using pylibpcap
try:
	print("trying to read packets using pylibpcap (must be installed)")
	import pcap
	p = pcap.pcapObject()
	#dev = pcap.lookupdev()
	#net, mask = pcap.lookupnet(dev)
	# note:    to_ms does nothing on linux
	#p.open_live(dev, 1600, 0, 100)
	p.dump_open("packets.pcap")
	p.setfilter("tcp", 0, 0)

	cnt = 0
	for pktlen, data, timestamp in p:
		cnt += 1
		eth = Ethernet(data)

		if eth[TCP] is not None:
			print("%9.3f: %s:%s -> %s:%s", (ts, ether[IP].src_s, ether[TCP].src_s, ether[IP].dst_s, ether[IP].dst_s))
except:
	pass
# read packets from network
#sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
#packet3 = Ethernet(sock.recv(4096))
#print("got a packet from network:")
#print(packet3)
# send packets back to network
#print("sending packet back")
#sock.send(packet3.bin())
