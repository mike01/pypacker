from pypacker.pypacker import Packet
from pypacker import ppcap
from pypacker import psocket
from pypacker.layer12 import arp, ethernet, radiotap
from pypacker.layer3 import ip, icmp
from pypacker.layer4 import udp, tcp

import socket

## create packets using raw bytes
BYTES_ETH_IP_ICMPREQ	= b"\x52\x54\x00\x12\x35\x02\x08\x00\x27\xa9\x93\x9e\x08\x00\x45\x00\x00\x54\x00\x00\x40\x00\x40\x01\x54\xc1\x0a\x00" + \
			  b"\x02\x0f\xad\xc2\x2c\x17\x08\x00\xec\x66\x09\xb1\x00\x01\xd0\xd5\x18\x51\x28\xbd\x05\x00\x08\x09\x0a\x0b\x0c\x0d" + \
			  b"\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29" + \
			  b"\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37"
packet1 = ethernet.Ethernet(BYTES_ETH_IP_ICMPREQ)
print("packet contents: %s" % packet1)
print("packet as bytes: %s" % packet1.bin())
## create custom packets and concat them
packet1 = ethernet.Ethernet(dst_s="aa:bb:cc:dd:ee:ff", src_s="ff:ee:dd:cc:bb:aa") +\
	ip.IP(src_s="192.168.0.1", dst_s="192.168.0.2") +\
	icmp.ICMP(type=8)
print("custom packet: %s" % packet1)
## get specific layers
layers = [packet1[ethernet.Ethernet], packet1[ip.IP], packet1[icmp.ICMP]]

for l in layers:
	if l is not None:
		print("found layer: %s" % l)
## check direction
packet2 = ethernet.Ethernet(dst_s="ff:ee:dd:cc:bb:aa", src_s="aa:bb:cc:dd:ee:ff") +\
	ip.IP(src_s="192.168.0.2", dst_s="192.168.0.1") +\
	icmp.ICMP(type=8)
dir = packet1.direction(packet2)

if dir == Packet.DIR_SAME:
	print("same direction for packet 1/2")
elif dir == Packet.DIR_REV:
	print("reverse direction for packet 1/2")
else:
	print("unknown direction for packet 1/2, type: %d" % dir)
## read packets from pcap-file using pypacker-reader
f = open("packets_ether.pcap", "rb")
pcap = ppcap.Reader(f)
cnt = 0

for ts, buf in pcap:
	cnt += 1
	eth = ethernet.Ethernet(buf)

	if eth[tcp.TCP] is not None:
		print("%9.3f: %s:%s -> %s:%s" % (ts, eth[ip.IP].src_s, eth[tcp.TCP].sport, eth[ip.IP].dst_s, eth[tcp.TCP].dport))
## send/receive packets to/from network using raw sockets (thx to oraccha)
try:
	psock = psocket.SocketHndl()
	print("please do a ping to localhost to receive bytes!")
	raw_bytes = psock.recv()
	print(raw_bytes)
	print(ethernet.Ethernet(raw_bytes))
except socket.error as e:
	print("you need to be root to execute the raw socket-examples!")
# read 802.11 packets from interface mon0
# command to create interface (replace wlanX with your managed wlan-interface):
# iw dev [wlanX] interface add mon0 type monitor
#try:
#	sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, ETH_P_IP)
#	sock.bind((INTERFACE, ETH_P_IP))
#	print("please wait for wlan traffic to show up")
#	raw_bytes = sock.recv(65536)
#	print(raw_bytes)
#	print(Radiotap(raw_bytes))
#except socket.error as e:
#	print("you need to be root to execute the raw socket-example!")
## write packets to network interface using raw sockets

# grab all beacons on the current channel
try:
	wlan_reader = psocket.SocketHndl("mon0")
	print("please wait for wlan traffic to show up")

	for i in range(10):
		rtap = radiotap.Radiotap(wlan_reader.recv())
		print(rtap)
		sign = rtap.flags.find_by_id(radiotap.ANT_SIG_MASK)[1]
		print("signal is: %s" % sign)
		channel = rtap.flags.find_by_id(radiotap.CHANNEL_MASK)[0]
		print("channel: %s" % radiotap.get_channelinfo(channel))

		try:
			beacon = rtap[ieee80211.IEEE80211.Beacon]
			print("beacon: %s" % beacon)
		except:
			pass
	wlan_reader.close()
except socket.error as e:
	print(e)


try:
	psock = psocket.SocketHndl()
	# send ARP request
	arpreq = ethernet.Ethernet(src_s="12:34:56:78:90:12", type=ethernet.ETH_TYPE_ARP) +\
		arp.ARP(sha_s="12:34:56:78:90:12", spa_s="192.168.0.2", tha_s="12:34:56:78:90:13", tpa_s="192.168.0.1")
	psock.send(arpreq.bin())
	# send ICMP request
	icmpreq = ethernet.Ethernet(src_s="12:34:56:78:90:12", dst_s="12:34:56:78:90:13", type=ethernet.ETH_TYPE_IP) +\
		ip.IP(p=ip.IP_PROTO_ICMP, src_s="192.168.0.2", dst_s="192.168.0.1") +\
		icmp.ICMP() +\
		icmp.Echo(id=1, ts=123456789, data=b"12345678901234567890")
	psock.send(icmpreq.bin())
	# send TCP SYN
	tcpsyn = ethernet.Ethernet(src_s="12:34:56:78:90:12", dst_s="12:34:56:78:90:13", type=ethernet.ETH_TYPE_IP) +\
		ip.IP(p=ip.IP_PROTO_TCP, src_s="192.168.0.2", dst_s="192.168.0.1") +\
		tcp.TCP(sport=12345, dport=80)
	psock.send(tcpsyn.bin())
	# send UDP data
	udpcon = ethernet.Ethernet(src_s="12:34:56:78:90:12", dst_s="12:34:56:78:90:13", type=ethernet.ETH_TYPE_IP) +\
		ip.IP(p=ip.IP_PROTO_UDP, src_s="192.168.0.2", dst_s="192.168.0.1") +\
		udp.UDP(sport=12345, dport=80)
	udpcon[udp.UDP].data = b"udpdata"
	psock.send(udpcon.bin())
	psock.close()
except socket.error as e:
	print("you need to be root to execute the raw socket-examples!")

## Usage hints:
# - Assemblation of TCP/UDP streams can be done by tshark using pipes with "-i -" and "-z follow,prot,mode,filter[,range]"
