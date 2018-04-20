import socket

import pypacker.pypacker as pypacker
from pypacker.pypacker import Packet
from pypacker import ppcap
from pypacker import psocket
from pypacker.layer12 import arp, ethernet, ieee80211, prism
from pypacker.layer3 import ip, icmp
from pypacker.layer4 import udp, tcp

wlan_monitor_if		= "wlan1"

#
# create packets using raw bytes
#
BYTES_ETH_IP_ICMPREQ = b"\x52\x54\x00\x12\x35\x02\x08\x00\x27\xa9\x93\x9e\x08\x00" +\
	b"\x45\x00\x00\x54\x00\x00\x40\x00\x40\x01\x54\xc1\x0a\x00" +\
	b"\x02\x0f\xad\xc2\x2c\x17\x08\x00\xec\x66\x09\xb1\x00\x01" +\
	b"\xd0\xd5\x18\x51\x28\xbd\x05\x00\x08\x09\x0a\x0b\x0c\x0d" +\
	b"\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b" +\
	b"\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29" +\
	b"\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37"
packet1 = ethernet.Ethernet(BYTES_ETH_IP_ICMPREQ)
print("packet contents: %s" % packet1)
print("packet as bytes: %s" % packet1.bin())
# create custom packets and concat them
packet1 = ethernet.Ethernet(dst_s="aa:bb:cc:dd:ee:ff", src_s="ff:ee:dd:cc:bb:aa") +\
	ip.IP(src_s="192.168.0.1", dst_s="192.168.0.2") +\
	icmp.ICMP(type=8) +\
	icmp.ICMP.Echo(id=1, ts=123456789, body_bytes=b"12345678901234567890")
print("custom packet: %s" % packet1)

# change dynamic header
packet1.ip.opts.append(ip.IPOptMulti(type=ip.IP_OPT_TS, len=3, body_bytes=b"\x00\x11\x22"))

# change dynamic header even more
# opts = [(ip.IP_OPT_TR, b"\x33\x44\x55"), (ip.IP_OPT_NOP, b"")]
opts = [ip.IPOptMulti(type=ip.IP_OPT_TR,
	len=3,
	body_bytes=b"\x33\x44\x55"),
	ip.IPOptSingle(type=ip.IP_OPT_NOP)]
packet1.ip.opts.extend(opts)

# get specific layers
layers = [packet1[ethernet.Ethernet], packet1[ip.IP], packet1[icmp.ICMP]]
# the same as above but without index notation
layers = [packet1, packet1.upper_layer, packet1.upper_layer.upper_layer]
# the same as above but without index notation and navigating downwards
pkt_icmp = layers[2]
layers = [pkt_icmp.lowest_layer, pkt_icmp.lower_layer, pkt_icmp]

for l in layers:
	if l is not None:
		print("found layer: %s" % l)

# check direction
packet2 = ethernet.Ethernet(dst_s="ff:ee:dd:cc:bb:aa", src_s="aa:bb:cc:dd:ee:ff") +\
	ip.IP(src_s="192.168.0.2", dst_s="192.168.0.1") +\
	icmp.ICMP(type=8) +\
	icmp.ICMP.Echo(id=1, ts=123456789, body_bytes=b"12345678901234567890")
print(packet1)
print(packet1.direction)
if packet1.is_direction(packet2, Packet.DIR_SAME):
	print("same direction for packet 1/2")
elif packet1.is_direction(packet2, Packet.DIR_REV):
	print("reverse direction for packet 1/2")
else:
	print("unknown direction for packet 1/2, type: %d" % dir)

#
# read packets from pcap-file using pypacker-reader
#

pcap = ppcap.Reader(filename="packets_ether.pcap")
cnt = 0

for ts, buf in pcap:
	cnt += 1
	eth = ethernet.Ethernet(buf)

	if eth[tcp.TCP] is not None:
		print("%d: %s:%s -> %s:%s" % (ts, eth[ip.IP].src_s, eth[tcp.TCP].sport,
			eth[ip.IP].dst_s, eth[tcp.TCP].dport))
pcap.close()
#
# send/receive packets to/from network using raw sockets
#
try:
	psock = psocket.SocketHndl(timeout=10)
	print("please do a ping to localhost to receive bytes!")
	raw_bytes = psock.recv()
	print(ethernet.Ethernet(raw_bytes))
	psock.close()
except socket.error as e:
	print("you need to be root to execute the raw socket-examples!")

# read 802.11 packets from wlan monitor interface
# command to create/remove interface (replace wlanX with your managed wlan-interface):
# iw dev [wlanX] interface add mon0 type monitor
# iw dev [wlanX] interface del

try:
	wlan_reader = psocket.SocketHndl(wlan_monitor_if)
	print("please wait for wlan traffic to show up")
	raw_bytes = wlan_reader.recv()
	# print(Radiotap(raw_bytes))
	print(prism.Prism(raw_bytes))

	# grab some beacons on the current channel
	bc_cnt = 0

	for i in range(10):
		raw_bytes = wlan_reader.recv()
		# drvinfo = radiotap.Radiotap(raw_bytes)
		drvinfo = prism.Prism(raw_bytes)

		try:
			beacon = drvinfo[ieee80211.IEEE80211.Beacon]
			if beacon is None:
				continue
			mac_ap = drvinfo[ieee80211.IEEE80211.MGMTFrame].bssid
			mac_ap = pypacker.mac_bytes_to_str(mac_ap)
			# print("beacon: %s" % beacon)
			# assume ascending order, 1st IE is Beacon
			ie_ssid = beacon.ies[0].body_bytes
			# Note: only for prism-header
			print("bssid: %s, ssid: %s (Signal: -%d dB, Quality: %d)"
				% (mac_ap,
				ie_ssid,
				0xffffffff ^ drvinfo.dids[3].value,
				drvinfo.dids[4].value)
			)
			bc_cnt += 1
		except Exception as e:
			print(e)

	if bc_cnt == 0:
		print("got no beacons, try to change channel or get closer to the AP")
	wlan_reader.close()
except socket.error as e:
	print(e)

# write packets to network interface (default lo) using raw sockets
try:
	#
	# send packets on layer 2
	#
	psock = psocket.SocketHndl(iface_name="lo", mode=psocket.SocketHndl.MODE_LAYER_2, timeout=10)

	# send ARP request
	arpreq = ethernet.Ethernet(src_s="12:34:56:78:90:12", type=ethernet.ETH_TYPE_ARP) +\
		arp.ARP(sha_s="12:34:56:78:90:12", spa_s="192.168.0.2",
			tha_s="12:34:56:78:90:13", tpa_s="192.168.0.1")
	psock.send(arpreq.bin())

	# send ICMP request
	icmpreq = ethernet.Ethernet(src_s="12:34:56:78:90:12", dst_s="12:34:56:78:90:13", type=ethernet.ETH_TYPE_IP) +\
		ip.IP(p=ip.IP_PROTO_ICMP, src_s="192.168.0.2", dst_s="192.168.0.1") +\
		icmp.ICMP(type=8) +\
		icmp.ICMP.Echo(id=1, ts=123456789, body_bytes=b"12345678901234567890")
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
	udpcon[udp.UDP].body_bytes = b"udpdata"
	psock.send(udpcon.bin())
	psock.close()
	#
	# send and receive packets on layer 3 (assumes running HTTP-server on port 80)
	#
	packet_ip = ip.IP(src_s="127.0.0.1", dst_s="127.0.0.1") + tcp.TCP(dport=80)
	psock = psocket.SocketHndl(mode=psocket.SocketHndl.MODE_LAYER_3, timeout=10)
	packets = psock.sr(packet_ip, max_packets_recv=1)

	for p in packets:
		print("got layer 3 packet: %s" % p)
	psock.close()
except socket.timeout as e:
	print("timeout!")
except socket.error as e:
	print("you need to be root to execute the raw socket-examples!")
