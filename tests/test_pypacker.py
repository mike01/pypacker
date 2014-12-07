from pypacker import pypacker
from pypacker.psocket import SocketHndl
from pypacker import multiproc_unpacker
import pypacker.ppcap as ppcap
import pypacker.pcapng as pcapng
from pypacker.layer12 import arp, dtp, ethernet, ieee80211, ppp, radiotap, stp, vrrp
from pypacker.layer3 import ip, ip6, ipx, icmp, igmp, ospf, pim
from pypacker.layer4 import tcp, udp, ssl, sctp
from pypacker.layer567 import diameter, dhcp, dns, hsrp, http, ntp, pmap, radius, rip, rtp, telnet, tpkt

import copy
import unittest
import time
import random

# General testcases:
# - Length comparing before/after parsing
# - Concatination via "+" (+parsing)
# - type finding via packet[type]
# - dynamic field modification
# - pcap-ng file format
# Things to test on every protocol:
# - raw byte parsing
# - header changes (dynamic/optional headers)
# - direction of packages
# - checksums
#
# Successfully tested:
# - Ethernet
# - Radiotap
# - IEEE80211
# - ARP
# - DNS
# - STP
# - PPP
# - OSPF
# - VRRP
# - DTP
#
# - IP
# - IP6
# - ICMP
# - PIM
# - IGMP
# - IPX
#
# - TCP
# - UDP
# - SCTP
#
# - HTTP
# - NTP
# - RTP
# - DHCP
# - RIP
# - SIP
# - Telnet
# - HSRP
# - Diameter
# - SSL
# - TPKT
# - Pmap
# - Radius
# - BGP
#
# TBD:
# - PPPoE
# - LLC
#
# - ICMP6
#
# - SCCP
#
# - RFB
# - RPC

# some predefined layers
#
# dst="52:54:00:12:35:02" src="08:00:27:a9:93:9e" type="0x08x00", type=2048
BYTES_ETH	= b"\x52\x54\x00\x12\x35\x02\x08\x00\x27\xa9\x93\x9e\x08\x00"
# src="10.0.2.15", dst="10.32.194.141", type=6 (TCP)
BYTES_IP	= b"\x45\x00\x00\xff\xc5\x78\x40\x00\x40\x06\x9c\x81\x0a\x00\x02\x0f\x0a\x20\xc2\x8d"
# sport=6667, dport=55211, win=46
BYTES_TCP	= b"\x1a\x0b\x00\x50\xb9\xb7\x74\xa9\xbc\x5b\x83\xa9\x80\x10\x00\x2e\xc0\x09\x00\x00\x01\x01\x08\x0a\x28\x2b\x0f\x9e\x05\x77\x1b\xe3"
# sport=38259, dport=53
BYTES_UDP	= b"\x95\x73\x00\x35\x00\x23\x81\x49"
BYTES_HTTP	= b"GET / HTTP/1.1\r\nHeader1: value1\r\nHeader2: value2\r\n\r\nThis is the body content\r\n"
BYTES_ETH_IP_TCP_HTTP = BYTES_ETH + BYTES_IP + BYTES_TCP + BYTES_HTTP
## NTP, port=123 (0x7B)
BYTES_NTP = BYTES_UDP[:3] + b"\x7B" + BYTES_UDP[4:] + b"\x24\x02\x04\xef\x00\x00\x00\x84\x00\x00\x33\x27" +\
	b"\xc1\x02\x04\x02\xc8\x90\xec\x11\x22\xae\x07\xe5\xc8\x90\xf9\xd9\xc0\x7e\x8c\xcd\xc8\x90\xf9\xd9\xda\xc5" +\
	b"\xb0\x78\xc8\x90\xf9\xd9\xda\xc6\x8a\x93"
## RIP
BYTES_RIP = b"\x02\x02\x00\x00\x00\x02\x00\x00\x01\x02\x03\x00\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00" +\
	b"\x00\x01\x00\x02\x00\x00\xc0\xa8\x01\x08\xff\xff\xff\xfc\x00\x00\x00\x00\x00\x00\x00\x01"


def print_header(msg):
	print()
	print(">>>>>>>>> " + msg + " <<<<<<<<<")


def get_pcap(fname, cnt=1000):
	"""
	Read cnt packets from a pcap file, default: 1000
	"""
	packet_bytes = []
	f = open(fname, "rb")
	pcap = ppcap.Reader(f)

	for ts, buf in pcap:
		packet_bytes.append(buf)
		cnt -= 1
		if cnt <= 0:
			break

	return packet_bytes


class GeneralTestCase(unittest.TestCase):
	def test_create_eth(self):
		print_header("CREATE TEST")
		eth = ethernet.Ethernet()
		#print(str(eth))
		self.assertTrue(eth.bin() == b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x08\x00")
		eth = ethernet.Ethernet(dst=b"\x00\x01\x02\x03\x04\x05", src=b"\x06\x07\x08\x09\x0A\x0B", type=2048)
		print(str(eth))
		print(eth.bin())
		self.assertTrue(eth.bin() == b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x08\x00")

	def test_len(self):
		print_header("LENGTH TEST")
		bts_list = get_pcap("tests/packets_ssl.pcap")

		for bts in bts_list:
			eth = ethernet.Ethernet(bts)
			print("%d = %d" % (len(bts), len(eth)))
			self.assertTrue(len(bts) == len(eth))

	def test_repr(self):
		print_header("REPR TEST")
		bts_list = get_pcap("tests/packets_ssl.pcap")

		for bts in bts_list:
			eth = ethernet.Ethernet(bts)
			print(eth)
			print(eth.ip)
			print(eth.ip.tcp)


class EthTestCase(unittest.TestCase):
	def test_eth(self):
		print_header("ETHERNET")
		# Ethernet without body
		s = b"\x52\x54\x00\x12\x35\x02\x08\x00\x27\xa9\x93\x9e\x08\x00"
		eth1 = ethernet.Ethernet(s)
		# parsing
		self.assertTrue(eth1.bin() == s)
		self.assertTrue(eth1.dst_s == "52:54:00:12:35:02")
		self.assertTrue(eth1.src_s == "08:00:27:A9:93:9E")

		# Ethernet without body + vlan
		s = b"\x52\x54\x00\x12\x35\x02\x08\x00\x27\xa9\x93\x9e\x81\x00\xff\xff\x08\x00"
		eth1b = ethernet.Ethernet(s)
		# parsing
		self.assertTrue(eth1b.bin() == s)
		self.assertTrue(eth1b.dst_s == "52:54:00:12:35:02")
		self.assertTrue(eth1b.src_s == "08:00:27:A9:93:9E")
		print(eth1b.vlan)
		print(eth1b.type)
		#print("%04X" % eth1b.type)
		self.assertTrue(eth1b.vlan == b"\x81\x00\xff\xff")
		self.assertTrue(eth1b.type == 0x0800)
		# header field update
		mac1 = "AA:BB:CC:DD:EE:00"
		mac2 = "AA:BB:CC:DD:EE:01"
		eth1.dst_s = mac2
		eth1.src_s = mac1
		self.assertTrue(eth1.dst_s == mac2)
		self.assertTrue(eth1.src_s == mac1)

		# Ethernet + IP
		s = b"\x52\x54\x00\x12\x35\x02\x08\x00\x27\xa9\x93\x9e\x08\x00\x45\x00\x00\x37\xc5\x78\x40\x00\x40\x11\x9c\x81\x0a\x00\x02\x0f\x0a\x20\xc2\x8d"
		eth2 = ethernet.Ethernet(s)
		# parsing
		self.assertTrue(eth2.bin() == s)
		self.assertTrue(type(eth2.ip).__name__ == "IP")
		print("Ethernet with IP: %s -> %s" % (eth2.ip.src, eth2.ip.dst))
		# reconstruate macs
		eth1.src = b"\x52\x54\x00\x12\x35\x02"
		eth1.dst = b"\x08\x00\x27\xa9\x93\x9e"
		# direction
		print("direction of eth: %d" % eth1.direction(eth1))
		self.assertTrue(eth1.is_direction(eth1, pypacker.Packet.DIR_SAME))


class IPTestCase(unittest.TestCase):
	def test_IP(self):
		print_header("IP")
		packet_bytes = get_pcap("tests/packets_dns.pcap")

		# IP without body
		ip1_bytes = packet_bytes[0][14:34]
		ip1 = ip.IP(ip1_bytes)
		self.assertTrue(ip1.bin() == ip1_bytes)
		self.assertTrue(ip1.src_s == "192.168.178.22")
		self.assertTrue(ip1.dst_s == "192.168.178.1")
		print("src: %s" % ip1.src_s)
		# header field udpate
		src = "1.2.3.4"
		dst = "4.3.2.1"
		print(ip1)
		ip1.src_s = src
		ip1.dst_s = dst
		self.assertTrue(ip1.src_s == src)
		self.assertTrue(ip1.dst_s == dst)
		self.assertTrue(ip1.direction(ip1) == pypacker.Packet.DIR_SAME | pypacker.Packet.DIR_REV)

		print(">>> checksum")
		ip2 = ip.IP(ip1_bytes)
		print("IP sum 1: %s" % ip2.sum)
		self.assertTrue(ip2.sum == 0x8e60)
		ip2.p = 6
		print("IP sum 2: %s" % ip2.sum)
		self.assertTrue(ip2.sum == 36459)
		ip2.p = 17
		print("IP sum 3: %s" % ip2.sum)
		self.assertTrue(ip2.sum == 0x8e60)

		# IP + options
		ip3_bytes = b"\x49" + ip1_bytes[1:] + b"\x03\04\x00\x07" + b"\x09\03\x07" + b"\x01"
		ip3 = ip.IP(ip3_bytes)

		print("opts 1")

		for o in ip3.opts:
			print(o)

		print(ip3_bytes)
		print(ip3.bin())

		self.assertTrue(ip3.bin() == ip3_bytes)
		del ip3.opts[2]
		self.assertTrue(len(ip3.opts) == 2)
		self.assertTrue(ip3.opts[0].type == 3)
		self.assertTrue(ip3.opts[0].len == 4)
		print("body bytes: %s" % ip3.opts[0].bin())
		self.assertTrue(ip3.opts[0].bin() == b"\x03\04\x00\x07")

		print("opts 2")
		for o in ip3.opts:
			print(o)

		#ip3.opts.append((ip.IP_OPT_TS, b"\x00\x01\x02\x03"))
		ip3.opts.append(ip.IPOptMulti(type=ip.IP_OPT_TS, len=6, body_bytes=b"\x00\x01\x02\x03"))
		self.assertTrue(len(ip3.opts) == 3)
		self.assertTrue(ip3.opts[2].type == ip.IP_OPT_TS)
		self.assertTrue(ip3.opts[2].len == 6)
		print(ip3.opts[2].body_bytes)
		self.assertTrue(ip3.opts[2].body_bytes == b"\x00\x01\x02\x03")

		print("opts 3")
		#ip3.opts.append((ip.IP_OPT_TS, b"\x00"))
		ip3.opts.append(ip.IPOptMulti(type=ip.IP_OPT_TS, len=4, body_bytes=b"\x00\x11"))

		totallen = 0
		for o in ip3.opts:
			totallen += len(o)
			print(o)

		print("ip len: 20+%d, in header: %d" % (totallen, (20+totallen)/4))
		print("header offset: %d" % ip3.hl)
		self.assertTrue(ip3.hl == 9)


class TCPTestCase(unittest.TestCase):
	def test_TCP(self):
		print_header("TCP")
		packet_bytes = get_pcap("tests/packets_ssl.pcap")

		# TCP without body
		tcp1_bytes = packet_bytes[0][34:66]
		tcp1 = tcp.TCP(tcp1_bytes)

		# parsing
		self.assertTrue(tcp1.bin() == tcp1_bytes)
		self.assertTrue(tcp1.sport == 37202)
		self.assertTrue(tcp1.dport == 443)
		# direction
		tcp2 = tcp.TCP(tcp1_bytes)
		tcp1.sport = 443
		tcp1.dport = 37202
		print("dir: %d" % tcp1.direction(tcp2))
		self.assertTrue( tcp1.is_direction(tcp2, pypacker.Packet.DIR_REV) )
		# checksum (no IP-layer means no checksum change)
		tcp1.win = 1234
		self.assertTrue(tcp1.sum == 0x9c2d)
		# checksum (IP + TCP)
		ip_tcp_bytes = packet_bytes[0][14:]
		ip1 = ip.IP(ip_tcp_bytes)
		tcp2 = ip1[tcp.TCP]
		print(ip1.bin())
		print(ip_tcp_bytes)
		self.assertTrue(ip1.bin() == ip_tcp_bytes)

		print("sum 1: %X" % tcp2.sum)
		self.assertTrue(tcp2.sum == 0x9c2d)

		tcp2.win = 0x0073
		print("sum 2: %X" % tcp2.sum)
		self.assertTrue(tcp2.sum == 0xea57)

		tcp2.win = 1234
		print("sum 3: %X" % tcp2.sum)
		self.assertTrue(tcp2.sum == 0xe5f8)

		tcp2.win = 0x0073
		print("sum 4: %X" % tcp2.sum)
		self.assertTrue(tcp2.sum == 0xea57)

		# options
		print("tcp options: %d" % len(tcp2.opts))
		self.assertTrue(len(tcp2.opts) == 3)
		self.assertTrue(tcp2.opts[2].type == tcp.TCP_OPT_TIMESTAMP)
		self.assertTrue(tcp2.opts[2].len == 10)
		print(tcp2.opts[2].header_bytes)
		print(tcp2.opts[2].bin())
		print(tcp2.opts[2].body_bytes)
		self.assertTrue(tcp2.opts[2].header_bytes == b"\x08\x0a")
		self.assertTrue(tcp2.opts[2].body_bytes == b"\x01\x0b\x5d\xb3\x21\x3d\xc7\xd9")

		#tcp2.opts.append((tcp.TCP_OPT_WSCALE, b"\x00\x01\x02\x03\x04\x05"))	# header length 20 + (12 + 8 options)
		tcp2.opts.append(tcp.TCPOptMulti(type=tcp.TCP_OPT_WSCALE, len=8, body_bytes=b"\x00\x01\x02\x03\x04\x05"))	# header length 20 + (12 + 8 options)
		totallen = 0

		for opt in tcp2.opts:
			totallen += len(opt)
			print(opt)
		self.assertTrue(len(tcp2.opts) == 4)
		self.assertTrue(tcp2.opts[3].type == tcp.TCP_OPT_WSCALE)
		print("len is: 20+%d, hlen: %d" % (totallen, (20+totallen)/4))
		print("offset is: %s" % tcp2.off)
		self.assertTrue(tcp2.off == 10)


class UDPTestCase(unittest.TestCase):
	def test_UDP(self):
		print_header("UDP")
		packet_bytes = get_pcap("tests/packets_dns.pcap")

		ip_udp_bytes = packet_bytes[0][14:]
		ip1 = ip.IP(ip_udp_bytes)
		self.assertTrue(ip1.bin() == ip_udp_bytes)

		# UDP + DNS
		udp1 = ip1[udp.UDP]
		# parsing
		self.assertTrue(udp1.sport == 42432)
		self.assertTrue(udp1.dport == 53)
		# direction
		udp2 = ip.IP(ip_udp_bytes)[udp.UDP]
		#print("direction: %d" % udp1.direction(udp2))
		self.assertTrue(udp1.is_direction(udp2, pypacker.Packet.DIR_SAME))
		# checksum
		self.assertTrue(udp1.sum == 0xf6eb)

		#print("setting new port")
		udp1.dport = 1234
		print("sum 1: %X" % udp1.sum)
		self.assertTrue(udp1.sum == 0xf24e)

		udp1.dport = 53
		print("sum 2: %X" % udp1.sum)
		self.assertTrue(udp1.sum == 0xf6eb)


class HTTPTestCase(unittest.TestCase):
	def test_HTTP(self):
		print_header("HTTP")
		# HTTP header + body
		s1 = b"GET / HTTP/1.1\r\nHeader1: value1\r\nHeader2: value2\r\n\r\nThis is the body content\r\n"
		http1 = http.HTTP(s1)
		self.assertTrue(http1.bin() == s1)
		# header changes
		s2 = b"POST / HTTP/1.1\r\nHeader1: value1\r\nHeader2: value2\r\n\r\nThis is the body content\r\n"
		print(">>> new startline POST")
		http1.startline = b"POST / HTTP/1.1"
		print("http bin: %s" % http1.bin())
		self.assertTrue(http1.bin() == s2)
		self.assertTrue(http1.header[0][1] == b"value1")
		print(">>> new startline GET")
		http1.startline = b"GET / HTTP/1.1"
		self.assertTrue(http1.bin() == s1)
		print(">>> resetting body")
		s3 = b"GET / HTTP/1.1\r\nHeader1: value1\r\nHeader2: value2\r\n\r\n"
		http1.body_bytes = b""
		print("http bin: %s" % http1.bin())
		self.assertTrue(http1.bin() == s3)
		# TODO: set ether + ip + tcp + http
		#print("HTTP headers: %s" % http1.headers)


class AccessConcatTestCase(unittest.TestCase):
	def test_concat(self):
		print_header("CONCAT")
		packet_bytes = get_pcap("tests/packets_telnet.pcap")

		# create single layers
		bytes_eth_ip_tcp_tn = packet_bytes[0]
		l_eth = bytes_eth_ip_tcp_tn[:14]
		l_ip = bytes_eth_ip_tcp_tn[14:34]
		l_tcp = bytes_eth_ip_tcp_tn[34:66]
		l_tn = bytes_eth_ip_tcp_tn[66:]

		p_all = ethernet.Ethernet(bytes_eth_ip_tcp_tn)
		self.assertTrue(p_all.bin() == bytes_eth_ip_tcp_tn)
		print(p_all)
		print(p_all.body_handler)
		print(p_all.body_handler.body_handler)
		print(p_all.body_handler.body_handler.body_handler)

		eth1 = ethernet.Ethernet(l_eth)
		ip1 = ip.IP(l_ip)
		tcp1 = tcp.TCP(l_tcp)
		print("tcp bytes: %s" % l_tcp)
		print(tcp1.opts)
		tn1 = telnet.Telnet(l_tn)

		self.assertTrue(type(p_all[ethernet.Ethernet]) == type(eth1))
		self.assertTrue(type(p_all[ip.IP]) == type(ip1))
		self.assertTrue(type(p_all[tcp.TCP]) == type(tcp1))
		self.assertTrue(type(p_all[telnet.Telnet]) == type(tn1))

		# clean parsed = reassembled
		bytes_concat = [eth1.bin(), ip1.bin(), tcp1.bin(), tn1.bin()]
		self.assertTrue(p_all.bin() == b"".join(bytes_concat))

		p_all_concat = eth1 + ip1 + tcp1 + tn1
		print(p_all)
		print(p_all[ip.IP])
		print(p_all_concat)
		print(p_all_concat[ip.IP])
		print(p_all.bin())
		print(p_all_concat.bin())
		self.assertTrue(p_all.bin() == bytes_eth_ip_tcp_tn)
		self.assertTrue(p_all.bin() == p_all_concat.bin())

		# create layers using keyword-constructor
		eth2 = ethernet.Ethernet(dst=eth1.dst, src=eth1.src, type=eth1.type)
		ip2 = ip.IP(v_hl=ip1.v_hl, tos=ip1.tos, len=ip1.len, id=ip1.id, off=ip1.off, ttl=ip1.ttl, p=ip1.p, sum=ip1.sum, src=ip1.src, dst=ip1.dst)
		tcp2 = tcp.TCP(sport=tcp1.sport, dport=tcp1.dport, seq=tcp1.seq, ack=tcp1.ack, off_x2=tcp1.off_x2, flags=tcp1.flags, win=tcp1.win, sum=tcp1.sum, urp=tcp1.urp)
		self.assertTrue(tcp1.off_x2 == tcp2.off_x2)

		for opt in ip1.opts:
			print("adding ip option: %s" % opt)
		totallen = 0
		for opt in tcp1.opts:
			print("adding tcp option: %s" % opt)
			tcp2.opts.append(copy.deepcopy(opt))
			totallen += len(opt)
		print("total length: 20+%d" % totallen)

		self.assertTrue(tcp1.off_x2 == tcp2.off_x2)

		print(tcp1.body_bytes)
		tn2 = telnet.Telnet(tcp1.body_bytes)
		print(tn2)

		p_all2 = eth2 + ip2 + tcp2 + tn2

		for l in [ethernet.Ethernet, ip.IP, tcp.TCP, telnet.Telnet]:
			print(p_all[l])
			print(p_all2[l])
			print("-----")

		print(p_all.bin())
		print(p_all2.bin())
		self.assertTrue(p_all2.bin() == p_all.bin())


class IterateTestCase(unittest.TestCase):
	def test_iter(self):
		print_header("ITERATE")
		bts_list = get_pcap("tests/packets_ssl.pcap")

		for bts in bts_list:
			eth1 = ethernet.Ethernet(bts)
			# TODO: tcp not parsed/shown using %r?
			#print("%r" % eth1.ip.tcp)

			for layer in eth1:
				print("%r" % layer)
			print()


class StaticFieldActivateDeactivateTestCase(unittest.TestCase):
	def test_static(self):
		print_header("static fields active/inactive")
		eth1 = ethernet.Ethernet(dst_s="00:11:22:33:44:55", src_s="11:22:33:44:55:66", vlan=b"\x22\x22\x22\x22", type=0)
		self.assertTrue(eth1.vlan == b"\x22\x22\x22\x22")
		eth1.vlan = None
		print(eth1.bin())
		self.assertTrue(eth1.bin() == b"\x00\x11\x22\x33\x44\x55\x11\x22\x33\x44\x55\x66\x00\x00")
		eth1 = ethernet.Ethernet(dst_s="00:11:22:33:44:55", src_s="11:22:33:44:55:66", type=0)
		eth1.vlan = b"\x22\x22\x22\x23"
		eth1.src = None
		eth1.dst = None
		eth1.type = None
		print(eth1.bin())
		self.assertTrue(eth1.bin() == b"\x22\x22\x22\x23")


class DynamicFieldTestCase(unittest.TestCase):
	def test_dynamicfield(self):
		print_header("dynamic fields")
		eth1 = ethernet.Ethernet() + ip.IP() + tcp.TCP()
		tcp1 = eth1[tcp.TCP]
		# find raw bytes
		tcp1.opts.extend([b"\x00\x11\x22", b"\x11\x11\x22", b"\x22\x11\x22", b"\x33\x11\x22"])
		self.assertTrue(tcp1.opts.find_pos(b"\x33\x11\x22") == 3)
		self.assertTrue(tcp1.opts.find_value(b"\x33\x11\x22") == b"\x33\x11\x22")
		# find tuples
		del tcp1.opts[:]
		tcp1.opts.extend([ (0, b"\x00\x11\x22"), (1, b"\x11\x11\x22"), (2, b"\x22\x11\x22"), (3, b"\x33\x11\x22") ])
		self.assertTrue(tcp1.opts.find_pos(3) == 3)
		self.assertTrue(tcp1.opts.find_value(3) == (3, b"\x33\x11\x22"))
		del tcp1.opts[:]
		tcp1.opts.extend([ (b"A", b"\x00\x11\x22"), (b"B", b"\x11\x11\x22"), (b"C", b"\x22\x11\x22") ])
		self.assertTrue(tcp1.opts.find_pos(b"A") == 0)
		self.assertTrue(tcp1.opts.find_value(b"a", preformat_cb=lambda x : x.lower()) == (b"A", b"\x00\x11\x22"))
		# find packets
		del tcp1.opts[:]
		tcp1.opts.extend([
					tcp.TCPOptMulti(type=0, len=3, body_bytes=b"\x00\x11\x22"),
					tcp.TCPOptSingle(type=1),
					tcp.TCPOptSingle(type=2)
				])
		self.assertTrue(tcp1.opts.find_pos(2, extract_cb=lambda x: x.type) == 2)


class ICMPTestCase(unittest.TestCase):
	def test_icmp(self):
		print_header("ICMP")
		bts = get_pcap("tests/packets_icmp.pcap", 1)[0]
		print(bts)
		eth = ethernet.Ethernet(bts)
		print(eth)
		print(eth[ip.IP])
		self.assertTrue(eth.bin() == bts)
		icmp1 = eth[icmp.ICMP]
		print(str(icmp1))
		self.assertTrue(icmp1.type == 8)
		# checksum handling
		print("sum 1: %d" % icmp1.sum)		# 0xEC66 = 22213
		self.assertTrue(icmp1.sum == 0x425c)
		self.assertTrue(icmp1.echo.seq == 2304)
		icmp1.code = 123
		eth.bin()
		self.assertTrue(icmp1.sum != 0x425c)
		icmp1.code = 0
		icmp1 = eth[icmp.ICMP]
		self.assertTrue(icmp1.sum == 0x425c)


class OSPFTestCase(unittest.TestCase):
	def test(self):
		print_header("OSPF")
		bts = get_pcap("tests/packets_ospf.pcap", 1)[0]

		eth = ethernet.Ethernet(bts)
		self.assertTrue(eth.bin() == bts)
		self.assertIsNotNone(eth[ethernet.Ethernet])
		self.assertIsNotNone(eth[ip.IP])
		self.assertIsNotNone(eth[ospf.OSPF])


class PPPTestCase(unittest.TestCase):
	def test_ppp(self):
		print_header("PPP")
		s = b"\x21" + BYTES_IP
		ppp1 = ppp.PPP(s)
		self.assertTrue(ppp1.bin() == s)
		self.assertTrue(type(ppp1[ip.IP]).__name__ == "IP")


class STPTestCase(unittest.TestCase):
	def test_stp(self):
		print_header("STP")
		s = b"AABCDEEEEEEEEFFFFGGGGGGGGHHIIJJKKLL"
		stp1 = stp.STP(s)
		self.assertTrue(stp1.bin() == s)


class VRRPTestCase(unittest.TestCase):
	def test_vrrp(self):
		print_header("VRRP")
		s = b"ABCDEFGG"
		vrrp1 = vrrp.VRRP(s)
		self.assertTrue(vrrp1.bin() == s)


class IGMPTestCase(unittest.TestCase):
	def test_igmp(self):
		print_header("IGMP")
		s = b"ABCCDDDD"
		igmp1 = igmp.IGMP(s)
		self.assertTrue(igmp1.bin() == s)


class IPXTestCase(unittest.TestCase):
	def test_ipx(self):
		print_header("IPX")
		s = b"AABBCDEEEEEEEEEEEEFFFFFFFFFFFF"
		ipx1 = ipx.IPX(s)
		self.assertTrue(ipx1.bin() == s)


class PIMTestCase(unittest.TestCase):
	def test_ipx(self):
		print_header("PIM")
		s = b"ABCC"
		pim1 = pim.PIM(s)
		self.assertTrue(pim1.bin() == s)


class HSRPTestCase(unittest.TestCase):
	def test_hsrp(self):
		print_header("HSRP")
		s = b"ABCDEFGHIIIIIIIIJJJJ"
		hsrp1 = hsrp.HSRP(s)
		self.assertTrue(hsrp1.bin() == s)


class DHCPTestCase(unittest.TestCase):
	def test_dhcp(self):
		print_header("DHCP")
		# this is a DHCP-Discover
		s = get_pcap("tests/packets_dhcp.pcap", 1)[0]
		dhcp1 = ethernet.Ethernet(s)
		self.assertTrue(s == dhcp1.bin())
		print("DHCP type: %s" % type(dhcp1[dhcp.DHCP]).__name__)
		self.assertTrue(type(dhcp1[dhcp.DHCP]).__name__ == "DHCP")
		dhcp2 = dhcp1[dhcp.DHCP]
		self.assertTrue(len(dhcp2.opts) == 5)
		self.assertTrue(dhcp2.opts[0].type == 0x35)
		self.assertTrue(dhcp2.opts[1].type == 0x3d)

		dhcp1 = ethernet.Ethernet(s)
		dhcp2 = dhcp1[dhcp.DHCP]
		# TODO: use "append/extend"
		#dhcp2.opts += [(dhcp.DHCP_OPT_TCPTTL, b"\x00\x01\x02")]
		#dhcp2.opts.insert(4, (dhcp.DHCP_OPT_TCPTTL, b"\x00\x01\x02"))
		dhcp2.opts.insert(4, dhcp.DHCPOptMulti(type=dhcp.DHCP_OPT_TCPTTL, len=5, body_bytes=b"\x00\x01\x02"))
		print("new TLlen: %d" % len(dhcp2.opts))
		self.assertTrue(len(dhcp2.opts) == 6)
		self.assertTrue(dhcp2.opts[4].type == dhcp.DHCP_OPT_TCPTTL)


class DNSTestCase(unittest.TestCase):
	def test_dns(self):
		print_header("DNS")
		packet_bytes = get_pcap("tests/packets_dns.pcap")

		dns1 = ethernet.Ethernet(packet_bytes[0])[dns.DNS]
		print(dns1.bin())
		print(packet_bytes[0][42:])
		self.assertTrue(dns1.bin() == packet_bytes[0][42:])
		self.assertTrue(len(dns1.queries) == 1)
		self.assertTrue(len(dns1.answers) == 0)
		self.assertTrue(len(dns1.auths) == 0)
		self.assertTrue(len(dns1.addrecords) == 1)

		dns2 = ethernet.Ethernet(packet_bytes[1])[dns.DNS]
		self.assertTrue(dns2.bin() == packet_bytes[1][42:])
		print("%s" % dns2)
		self.assertTrue(len(dns2.queries) == 1)
		self.assertTrue(len(dns2.answers) == 3)
		self.assertTrue(len(dns2.auths) == 0)
		self.assertTrue(len(dns2.addrecords) == 1)

		dns3 = ethernet.Ethernet(packet_bytes[2])[dns.DNS]
		self.assertTrue(dns3.bin() == packet_bytes[2][42:])
		print("%s" % dns3)
		self.assertTrue(len(dns3.queries) == 1)
		self.assertTrue(len(dns3.answers) == 0)
		self.assertTrue(len(dns3.auths) == 1)
		self.assertTrue(len(dns3.addrecords) == 0)


class NTPTestCase(unittest.TestCase):
	def test_ntp(self):
		print_header("NTP")
		global BYTES_NTP
		s = BYTES_NTP
		n = udp.UDP(s)
		self.assertTrue(s == n.bin())
		n = n[ntp.NTP]
		print("NTP flags 1")
		print(n)
		self.assertTrue(n.li == ntp.NO_WARNING)
		self.assertTrue(n.v == 4)
		self.assertTrue(n.mode == ntp.SERVER)
		self.assertTrue(n.stratum == 2)
		self.assertTrue(n.id == b"\xc1\x02\x04\x02")

		# test get/set functions
		print("NTP flags 2")
		n.li = ntp.ALARM_CONDITION
		n.v = 3
		n.mode = ntp.CLIENT
		self.assertTrue(n.li == ntp.ALARM_CONDITION)
		self.assertTrue(n.v == 3)
		self.assertTrue(n.mode == ntp.CLIENT)


class RIPTestCase(unittest.TestCase):
	def test_rip(self):
		global BYTES_RIP
		s = BYTES_RIP
		print_header("RIP")
		r = rip.RIP(s)
		self.assertTrue(s == r.bin())
		print("amount auth/rte: %d" % len(r.rte_auth))
		self.assertTrue(len(r.rte_auth) == 2)

		rte = r.rte_auth[1]
		self.assertTrue(rte.family == 2)
		self.assertTrue(rte.route_tag == 0)
		self.assertTrue(rte.metric == 1)


class SCTPTestCase(unittest.TestCase):
	def test_sctp(self):
		print_header("SCTP")
		packet_bytes = get_pcap("tests/packets_sctp.pcap")

		# parsing
		sct1_bytes = packet_bytes[0]
		eth_ip_sct = ethernet.Ethernet(sct1_bytes)
		sct = eth_ip_sct[sctp.SCTP]
		print(sct1_bytes)
		print(eth_ip_sct.bin())
		for chunk in sct.chunks:
			print("%s" % chunk.bin())
		self.assertTrue(eth_ip_sct.bin() == sct1_bytes)
		# checksum (CRC32)
		#print("sctp sum1: %X" % sct.sum)
		#self.assertTrue(sct.sum == 0x6db01882)

		#print(sct)
		#sct.vtag = sct.vtag
		#print("sctp sum3: %X" % sct.sum)
		#print(sct)
		#self.assertTrue(sct.sum == 0x6db01882)

		self.assertTrue(sct.sport == 16384)
		self.assertTrue(sct.dport == 2944)
		self.assertTrue(len(sct.chunks) == 1)

		chunk = sct.chunks[0]
		self.assertTrue(chunk.type == sctp.DATA)
		self.assertTrue(chunk.len == 91)
		# dynamic fields
		#sct.chunks.append((sctp.DATA, 0xff, b"\x00\x01\x02"))
		sct.chunks.append(sctp.Chunk(type=sctp.DATA, flags=0xff, len=8, body_bytes=b"\x00\x01\x02\x03"))
		self.assertTrue(len(sct.chunks) == 2)
		self.assertTrue(sct.chunks[1].body_bytes == b"\x00\x01\x02\x03")
		# lazy init of chunks
		sct2 = sctp.SCTP()
		sct2.chunks.append((sctp.DATA, 0xff, b"\x00\x01\x02\x03"))
		self.assertTrue(len(sct2.chunks) == 1)


class ReaderTestCase(unittest.TestCase):
	def test_reader(self):
		print_header("READER standard")
		reader = ppcap.Reader(filename="tests/packets_ether.pcap", ts_conversion=False, filter=lambda x: x[ethernet.Ethernet] is not None)

		cnt = 0
		proto_cnt = {
			arp.ARP : 4,
			tcp.TCP : 34,
			udp.UDP : 4,
			icmp.ICMP : 7,
			http.HTTP : 12	# HTTP found = TCP having payload!
		}
		for ts, buf in reader:
			if cnt == 0:
			# check timestamp (big endian)
				self.assertTrue(ts[0] == 0x5118d5d0)
				self.assertTrue(ts[1] == 0x00052039)

			cnt += 1
			#print("%02d TS: %.40f LEN: %d" % (cnt, ts, len(buf)))
			eth = ethernet.Ethernet(buf)
			keys = proto_cnt.keys()

			for k in keys:
				if eth[k] is not None:
					proto_cnt[k] -= 1
					#if k == http.HTTP:
					#	print("found HTTP at: %d" % cnt)
					#break

		self.assertTrue(cnt == 49)

		print("proto summary:")
		for k, v in proto_cnt.items():
			print("%s: %s" % (k.__name__, v))
			self.assertTrue(v == 0)
		reader.close()


class MultiprocUnpackerTest(unittest.TestCase):
	def filter_cb(pkt):
		return pkt[ethernet.Ethernet] is not None

	def test_unpacker(self):
		print_header("Multiproc unpacker")
		reader = ppcap.Reader(filename="tests/packets_ether.pcap",
					ts_conversion=True,
					lowest_layer=ethernet.Ethernet,
					filter=MultiprocUnpackerTest.filter_cb)

		cnt = 0
		proto_cnt = {
			arp.ARP : 4,
			tcp.TCP : 34,
			udp.UDP : 4,
			icmp.ICMP : 7,
			http.HTTP : 12	# HTTP found = TCP having payload!
		}

		for ts, pkt in reader:
			cnt += 1
			#print(pkt)
			#print("%02d TS: %.40f LEN: %d" % (cnt, ts, len(eth)))
			keys = proto_cnt.keys()

			for k in keys:
				if pkt[k] is not None:
					proto_cnt[k] -= 1
					#if k == http.HTTP:
					#	print("found HTTP at: %d" % cnt)
					#break

		reader.close()

		print("proto summary:")
		for k, v in proto_cnt.items():
			print("%s: %s" % (k.__name__, v))

		for k, v in proto_cnt.items():
			self.assertTrue(v == 0)
		self.assertTrue(cnt == 49)


class ReaderNgTestCase(unittest.TestCase):
	def test_reader(self):
		print_header("READER PCAP NG")
		import os
		print(os.getcwd())
		f = open("tests/packets_ether.pcapng", "r+b")
		pcap = ppcap.Reader(f)

		cnt = 0
		proto_cnt = {
			arp.ARP : 4,
			tcp.TCP : 34,
			udp.UDP : 4,
			icmp.ICMP : 7,
			http.HTTP : 12	# HTTP found = TCP having payload!
		}

		for ts, buf in pcap:
			cnt += 1
			#print("%02d TS: %.40f LEN: %d" % (cnt, ts, len(buf)))
			eth = ethernet.Ethernet(buf)
			keys = proto_cnt.keys()

			for k in keys:
				if eth[k] is not None:
					proto_cnt[k] -= 1
					#if k == http.HTTP:
					#	print("found HTTP at: %d" % cnt)
					#break

		self.assertTrue(cnt == 49)

		print("proto summary:")
		for k, v in proto_cnt.items():
			print("%s: %s" % (k.__name__, v))
			self.assertTrue(v == 0)


class ReaderPcapNgTestCase(unittest.TestCase):
	def test_reader(self):
		print_header("READER PCAP-NG File format")
		import os
		print(os.getcwd())
		f = open("tests/packets_ether2.pcapng", "r+b")
		pcap = pcapng.Reader(f)
			
		print("Section Header Block Start")
		print("  Block Type:",hex(pcap.shb.type))
		print("  Block Total Length:",pcap.shb.block_length)
		print("  Byte-Order Magic:",hex(pcap.shb.magic))
		print("  Major Version:",hex(pcap.shb.v_major))
		print("  Minor Version:",hex(pcap.shb.v_minor))
		print("  Section Length:",hex(pcap.shb.section_length))
		print("  Option header")
		for opt in pcap.shb.opts:
			print("    {}({}): {}".format(pcapng.SHB_OPTIONS.get(opt.code), opt.code, opt.data))
		print("Section Header Block End")

		for idb in pcap.idbs:
			print("Interface Description Block Start")
			print("  Block Type:",hex(idb.type))
			print("  Block Total Length:",idb.block_length)
			print("  LinkType:",hex(idb.linktype))
			print("  Reserved:",hex(idb.reserved))
			print("  SnapLen:",idb.snaplen)
			print("  Option header")
			for opt in idb.opts:
				print("    {}({}): {}".format(pcapng.IDB_OPTIONS.get(opt.code), opt.code, opt.data))
			print("Interface Description Block End")

		for isb in pcap.isbs:
			print("Interface Statistics Block Start")
			print("  Block Type:",hex(isb.type))
			print("  Block Total Length:",isb.block_length)
			print("  Interface ID:",hex(isb.interface_id))
			print("  Timestamp(high):",hex(isb.ts_high))
			print("  Timestamp(Low):",hex(isb.ts_low))
			print("  Option header")
			for opt in isb.opts:
				print("    {}({}): {}".format(pcapng.ISB_OPTIONS.get(opt.code), opt.code, opt.data))
			print("Interface Statistics Block End")

		print("Enhanced Packet Block Start")
		for count, (ts, epb) in enumerate(pcap, start=1):
			print("Packet #{}".format(count))
			print("  Time:", ts)
			print("  Interface ID:", epb.interface_id)
			print("  Capture length:", epb.cap_len)
			print("  Frame length:", epb.len)
			#print("  Hexdump:")
			#pypacker.hexdump(epb.data)
		print("Enhanced Packet Block End")

		self.assertTrue(count == 2)


class ReadWriteReadTestCase(unittest.TestCase):
	def test_read_write(self):
		print_header("pcap READ -> WRITE -> READ")
		filename_read = "tests/packets_ether.pcapng"
		filename_write = "tests/packets_ether.pcapng_tmp"

		reader = ppcap.Reader(filename=filename_read, lowest_layer=ethernet.Ethernet)
		writer = ppcap.Writer(filename=filename_write)
		pkts_read = []

		for ts, pkt in reader:
			# should allready be fully dissected but we want to be sure..
			pkts_read.append( tuple([ts, pkt.bin()]) )
			writer.write(pkt.bin(), ts=ts)
		writer.close()
		reader.close()

		reader = ppcap.Reader(filename=filename_write, lowest_layer=ethernet.Ethernet)

		for pos, ts_pkt in enumerate(reader):
		# timestamp and bytes should not have been changed: input = output
			ts = ts_pkt[0]
			bts = ts_pkt[1].bin()

			self.assertTrue(ts == pkts_read[pos][0])
			self.assertTrue(bts == pkts_read[pos][1])
		reader.close()


class RadiotapTestCase(unittest.TestCase):
	def test_radiotap(self):
		print_header("Radiotap")
		# radiotap: flags, rate channel, dBm Antenna, Antenna, RX Flags
		s = b"\x00\x00\x12\x00\x2e\x48\x00\x00\x00\x02\x6c\x09\xa0\x00\xc2\x07\x00\x00\xff\xff"
		rad = radiotap.Radiotap(s)
		self.assertTrue(rad.bin() == s)
		print(rad)

		self.assertTrue(rad.version == 0)
		print("len: %d" % rad.len)
		self.assertTrue(rad.len == 4608)	# 0x1200 = 18
		self.assertTrue(rad.present_flags == 0x2e480000)
		#channel_bytes = rad.flags[ bytes([radiotap.CHANNEL_MASK]) ][0][1]
		channel_bytes = rad.flags.find_value(radiotap.CHANNEL_MASK)[1]
		channel = radiotap.get_channelinfo(channel_bytes)

		print("channel: %d" % channel[0])
		print(type(channel[0]))
		self.assertTrue(channel[0] == 2412)
		print("channel type: %s" % channel[1])
		self.assertTrue(channel[1] == 160)
		print("flags: %x" % rad.present_flags)
		print("flags mask: %x" % radiotap.FLAGS_MASK)
		print("flags & flags mask: %x" % (rad.present_flags & radiotap.FLAGS_MASK))

		self.assertTrue(rad.present_flags & radiotap.TSFT_MASK == 0)
		self.assertTrue(rad.present_flags & radiotap.FLAGS_MASK != 0)
		self.assertTrue(rad.present_flags & radiotap.RATE_MASK != 0)
		#self.assertTrue(len(rad.fields) == 7)


class PerfTestCase(unittest.TestCase):
	def test_perf(self):
		# IP + ICMP
		s = b"E\x00\x00T\xc2\xf3\x00\x00\xff\x01\xe2\x18\n\x00\x01\x92\n\x00\x01\x0b\x08\x00\xfc" +\
			b"\x11:g\x00\x00A,\xc66\x00\x0e\xcf\x12\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15" +\
			b"\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f!__$%&\'()*+,-./01234567"
		cnt = 10000
		print_header("Performance Tests")
		print("nr = new results on this machine")
		print("or = original results (Intel QuadCore @ 2,2 GHz, 4GB RAM, Python v3.2)")
		print("rounds per test: %d" % cnt)
		print("=====================================")

		print(">>> parsing (IP + ICMP)")
		start = time.time()
		for i in range(cnt):
			ip1 = ip.IP(s)
		print("time diff: %ss" % (time.time() - start))
		print("nr = %d pps" % (cnt / (time.time() - start)) )
		print("or = 48289 pps")

		print(">>> creating/direct assigning (IP + data)")
		start = time.time()
		for i in range(cnt):
			#ip = IP(src="1.2.3.4", dst="1.2.3.5").bin()
			ip.IP(src=b"\x01\x02\x03\x04", dst=b"\x05\x06\x07\x08", p=17, len=1234, body_bytes=b"abcd")
			#ip = IP(src=b"\x01\x02\x03\x04", dst=b"\x05\x06\x07\x08", p=17, len=1234, body_bytes=b"abcd")
		print("time diff: %ss" % (time.time() - start))
		print("nr = %d pps" % (cnt / (time.time() - start)) )
		print("or = 52118 pps")

		print(">>> output without change (IP)")
		ip2 = ip.IP(src=b"\x01\x02\x03\x04", dst=b"\x05\x06\x07\x08", p=17, len=1234, body_bytes=b"abcd")
		start = time.time()
		for i in range(cnt):
			ip2.bin()
		print("time diff: %ss" % (time.time() - start))
		print("nr = %d pps" % (cnt / (time.time() - start)) )
		print("or = 222587 pps")

		print(">>> output with change/checksum recalculation (IP)")
		ip3 = ip.IP(src=b"\x01\x02\x03\x04", dst=b"\x05\x06\x07\x08", p=17, len=1234, body_bytes=b"abcd")
		start = time.time()
		for i in range(cnt):
			ip3.src = b"\x01\x02\x03\x04"
			ip3.bin()
		print("time diff: %ss" % (time.time() - start))
		print("nr = %d pps" % (cnt / (time.time() - start)) )
		print("or = 18109 pps")

		print(">>> parsing (Ethernet + IP + TCP + HTTP)")
		global BYTES_ETH_IP_TCP_HTTP
		start = time.time()
		for i in range(cnt):
			eth = ethernet.Ethernet(BYTES_ETH_IP_TCP_HTTP)
		print("time diff: %ss" % (time.time() - start))
		print("nr = %d pps" % (cnt / (time.time() - start)) )
		print("or = 56372 pps")

		print(">>> changing Triggerlist/binary proto (Ethernet + IP + TCP + HTTP)")
		start = time.time()
		eth1 = ethernet.Ethernet(BYTES_ETH_IP_TCP_HTTP)
		tcp1 = eth1[tcp.TCP]
		for i in range(cnt):
			tcp1.opts[0].type = tcp.TCP_OPT_WSCALE
		print("time diff: %ss" % (time.time() - start))
		print("nr = %d pps" % (cnt / (time.time() - start)) )
		print("or = 165404 pps")

		print(">>> changing Triggerlist/text based proto (Ethernet + IP + TCP + HTTP)")
		start = time.time()
		eth1 = ethernet.Ethernet(BYTES_ETH_IP_TCP_HTTP)
		http1 = eth1[http.HTTP]
		for i in range(cnt):
			http1.header[0] = (b"GET / HTTP/1.1",)
		print("time diff: %ss" % (time.time() - start))
		print("nr = %d pps" % (cnt / (time.time() - start)) )
		print("or = 96363 pps")

		print(">>> direct assigning and concatination (Ethernet + IP + TCP + HTTP)")
		start = time.time()
		for i in range(cnt):
			concat = ethernet.Ethernet(dst_s="ff:ff:ff:ff:ff:ff", src_s="ff:ff:ff:ff:ff:ff") +\
				ip.IP(src_s="127.0.0.1", dst_s="192.168.0.1") +\
				tcp.TCP(sport=1234, dport=123) +\
				http.HTTP()
		print("time diff: %ss" % (time.time() - start))
		print("nr = %d pps" % (cnt / (time.time() - start)) )
		print("or = 11405 pps")

		print(">>> full packet parsing (Ethernet + IP + TCP + HTTP)")

		start = time.time()
		for i in range(cnt):
			p = ethernet.Ethernet(BYTES_ETH_IP_TCP_HTTP)
			p.dissect_full()

		print("time diff: %ss" % (time.time() - start))
		print("nr = %d pps" % (cnt / (time.time() - start)) )
		print("or = 40104 pps")

		print(">>> scapy comparison (check perftest_scapy.py)")
		s = b"\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x08\x00\x45\x00\x00\x81\x00\x01" +\
			b"\x00\x00\x40\x06\x7c\x74\x7f\x00\x00\x01\x7f\x00\x00\x01\x00\x14\x00\x50\x00\x00" +\
			b"\x00\x00\x00\x00\x00\x00\x50\x02\x20\x00\x3c\xc9\x00\x00\x47\x45\x54\x20\x2f\x20" +\
			b"\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a\x48\x6f\x73\x74\x3a\x20\x31\x32\x37\x2e" +\
			b"\x30\x2e\x30\x2e\x31\x0d\x0a\x52\x65\x66\x65\x72\x65\x72\x3a\x20\x68\x74\x74\x70" +\
			b"\x3a\x2f\x2f\x77\x77\x77\x2e\x74\x65\x73\x74\x2e\x64\x65\x0d\x0a\x43\x6f\x6f\x6b" +\
			b"\x69\x65\x3a\x20\x53\x65\x73\x73\x69\x6f\x6e\x49\x44\x3d\x31\x32\x33\x34\x35\x0d" +\
			b"\x0a\x0d\x0a"

		# scapy doesn't parse HTTP so skipping upper layer should be more realistic
		start = time.time()
		for i in range(cnt):
			p = ethernet.Ethernet(s)
			#p.dissect_full()

		print("time diff: %ss" % (time.time() - start))
		print("nr = %d pps" % (cnt / (time.time() - start)) )
		print("or = 56078 pps")
		print("or (scapy) = 1769 pps")


def create_bigfile():
		print("creating big file")
		s = b"\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x08\x00\x45\x00\x00\x81\x00\x01" +\
			b"\x00\x00\x40\x06\x7c\x74\x7f\x00\x00\x01\x7f\x00\x00\x01\x00\x14\x00\x50\x00\x00" +\
			b"\x00\x00\x00\x00\x00\x00\x50\x02\x20\x00\x3c\xc9\x00\x00\x47\x45\x54\x20\x2f\x20" +\
			b"\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a\x48\x6f\x73\x74\x3a\x20\x31\x32\x37\x2e" +\
			b"\x30\x2e\x30\x2e\x31\x0d\x0a\x52\x65\x66\x65\x72\x65\x72\x3a\x20\x68\x74\x74\x70" +\
			b"\x3a\x2f\x2f\x77\x77\x77\x2e\x74\x65\x73\x74\x2e\x64\x65\x0d\x0a\x43\x6f\x6f\x6b" +\
			b"\x69\x65\x3a\x20\x53\x65\x73\x73\x69\x6f\x6e\x49\x44\x3d\x31\x32\x33\x34\x35\x0d" +\
			b"\x0a\x0d\x0a"

		pkt = ethernet.Ethernet(s)
		writer = ppcap.Writer(filename="packets_bigfile.pcap")

		for cnt in range(100000):
			#print("writing to file")
			writer.write(pkt.bin())
		writer.close()


class PerfTestPpcapBigfile(unittest.TestCase):
	def test_perf(self):
		print_header("Performance Tests big file parsing")
		#create_bigfile()
		#return
		reader = ppcap.Reader(filename="tests/packets_bigfile.pcap",
				ts_conversion=True,
				lowest_layer=ethernet.Ethernet,
				filter=filter_cb2)
		cnt = 0
		amount_packets = 100000
		start = time.time()

		for ts, pkt in reader:
			#tmp = pkt
			#if cnt % 10000 == 0:
			#	print(".")
			pass

		diff = time.time() - start
		reader.close()
		print("nr = %d pps" % (amount_packets / diff) )
		print("or = 17257 pps")


class IEEE80211TestCase(unittest.TestCase):
	def setUp(self):
		if hasattr(self, "packet_bytes"):
			return
		#print(">>>>>>>>> IEEE 802.11 <<<<<<<<<")
		print("loading IEEE packets")

		self.packet_bytes = get_pcap("tests/packets_rtap_sel.pcap")
		# >>> loaded bytes
		# Beacon
		# CTS
		# ACK
		# QoS Data
		# Action
		# Data
		# QoS Null function
		# Radiotap length: 18 bytes

	def _test_readdump(self):
		print_header("read dump")
		packet_bytes_dump = get_pcap("tests/packets_rtap_bugcheck.pcap", 99999)

		for cnt, bts in enumerate(packet_bytes_dump):
			try:
				rtap = radiotap.Radiotap(bts)
				rtap[ieee80211.IEEE80211.MGMTFrame]
				beacon = rtap[ieee80211.IEEE80211.Beacon]
				if beacon is not None:
					#pass
					print("ie length: %d" % len(beacon.ies))
					#print(beacon.ies)
			except Exception as e:
				print("!!! error at %d: %s" % (cnt, e))

	def test_ack(self):
		print_header("ACK")
		rlen = self.packet_bytes[2][2]
		ieee = ieee80211.IEEE80211(self.packet_bytes[2][rlen:])
		self.assertTrue(ieee.bin() == self.packet_bytes[2][rlen:])
		self.assertTrue(ieee.version == 0)
		self.assertTrue(ieee.type == ieee80211.CTL_TYPE)
		self.assertTrue(ieee.subtype == ieee80211.C_ACK)
		self.assertTrue(ieee.to_ds == 0)
		self.assertTrue(ieee.from_ds == 0)
		self.assertTrue(ieee.pwr_mgt == 0)
		self.assertTrue(ieee.more_data == 0)
		self.assertTrue(ieee.protected == 0)
		self.assertTrue(ieee.order == 0)
		#print(ieee)
		self.assertTrue(ieee.ack.dst == b"\x00\xa0\x0b\x21\x37\x84")

	def test_beacon(self):
		print_header("Beacon")
		rlen = self.packet_bytes[0][2]
		ieee = ieee80211.IEEE80211(self.packet_bytes[0][rlen:])
		self.assertTrue(ieee.bin() == self.packet_bytes[0][rlen:])
		self.assertTrue(ieee.version == 0)
		self.assertTrue(ieee.type == ieee80211.MGMT_TYPE)
		self.assertTrue(ieee.subtype == ieee80211.M_BEACON)
		self.assertTrue(ieee.to_ds == 0)
		self.assertTrue(ieee.from_ds == 0)
		self.assertTrue(ieee.pwr_mgt == 0)
		self.assertTrue(ieee.more_data == 0)
		self.assertTrue(ieee.protected == 0)
		self.assertTrue(ieee.order == 0)
		beacon = ieee[ieee80211.IEEE80211.Beacon]
		self.assertTrue(beacon.dst == b"\xff\xff\xff\xff\xff\xff")
		self.assertTrue(beacon.src == b"\x24\x65\x11\x85\xe9\xae")
		print("%04x" % beacon.capa)
		self.assertTrue(beacon.seq_frag == 0x702D)
		self.assertTrue(beacon.capa == 0x3104)
		#self.assertTrue(beacon.capa == 0x0431)
		# TODO: test IEs
		#self.assertTrue(ieee.capability.privacy == 1)
		#self.assertTrue(ieee.mgmtframe.beacon.body_bytes == "CAEN")
		#self.assertTrue(ieee.rate.body_bytes == b"\x82\x84\x8b\x0c\x12\x96\x18\x24")
		#self.assertTrue(ieee.ds.body_bytes == b"\x01")
		#self.assertTrue(ieee.tim.body_bytes == b"\x00\x01\x00\x00")

	def test_data(self):
		print_header("Data")
		rlen = self.packet_bytes[5][2]
		ieee = ieee80211.IEEE80211(self.packet_bytes[5][rlen:])
		self.assertTrue(ieee.bin() == self.packet_bytes[5][rlen:])
		self.assertTrue(ieee.type == ieee80211.DATA_TYPE)
		self.assertTrue(ieee.subtype == ieee80211.D_NORMAL)
		self.assertTrue(ieee.protected == 1)
		self.assertTrue(ieee.dataframe.dst == b"\x01\x00\x5e\x7f\xff\xfa")
		self.assertTrue(ieee.dataframe.src == b"\x00\x1e\xe5\xe0\x8c\x06")
		self.assertTrue(ieee.dataframe.seq_frag == 0x501e)
		print(ieee.dataframe.body_bytes)
		self.assertTrue(ieee.dataframe.body_bytes == b"\x62\x22\x39\x61\x98\xd1\xff\x34" +
		b"\x65\xab\xc1\x3c\x8e\xcb\xec\xef\xef\xf6\x25\xab\xe5\x89\x86\xdf\x74\x19\xb0" +
		b"\xa4\x86\xc2\xdb\x38\x20\x59\x08\x1f\x04\x1b\x96\x6b\x01\xd7\x6a\x85\x73\xf5" +
		b"\x4a\xf1\xa1\x2f\xf3\xfb\x49\xb7\x6b\x6a\x38\xef\xa8\x39\x33\xa1\xc8\x29\xc7" +
		b"\x0a\x88\x39\x7c\x31\xbf\x55\x96\x24\xd5\xe1\xbf\x62\x85\x2c\xe3\xdf\xb6\x80" +
		b"\x3e\x92\x1c\xbf\x13\xcd\x47\x00\x8e\x9f\xc6\xa7\x81\x91\x71\x9c\x0c\xad\x08" +
		b"\xe2\xe8\x5f\xac\xd3\x1c\x90\x16\x15\xa0\x71\x30\xee\xac\xdd\xe5\x8d\x1f\x5b" +
		b"\xbc\xb6\x03\x51\xf1\xee\xff\xaa\xc9\xf5\x16\x1d\x2c\x5e\x52\x49\x3c\xaf\x7f" +
		b"\x13\x12\x1a\x24\xfb\xb8\xc1\x4e\xb7\xd8\x53\xfb\x76\xc0\x6e\xc8\x30\x8d\x2a" +
		b"\x65\xfd\x5d\x1c\xee\x97\x0d\xa3\x5c\x0f\x6c\x08\x5b\x2c\x0b\xbf\x64\xdb\x52" +
		b"\x2d\x8e\x92\x4f\x12\xbe\x6c\x87\x78\xb7\x7d\xc8\x42\xd8\x68\x83\x29\x04\xb5" +
		b"\x20\x91\xb2\xc9\xb9\x65\x45\xf4\xf6\xf4\xb7\xbd\x9d\x86\xc4\xab\xbe\x95\x9e" +
		b"\xe3\x82\x39\xcf\x95\xf4\x68\x7c\xb7\x00\xbb\x5d\xab\x35\x86\xa0\x11\x49\x50" +
		b"\x6c\x28\xc4\x18\xb5\x2f\x3f\xfc\x23\x90\x1c\x9f\x81\x5a\x14\xcf\xbf\xc4\xf4" +
		b"\x38\x0b\x61\x6d\xd1\x57\x49\xba\x31\x2d\xa5\x0f\x3d\x76\x24\xb4\xf9\xa3\xe1" +
		b"\x33\xae\x9f\x69\x67\x23")

		#llc_pkt = LLC(ieee.data_frame.body_bytes)
		#ip_pkt = ip.IP(llc_pkt.body_bytes)
		#self.assertTrue(ip_pkt.dst == b"\x3f\xf5\xd1\x69")

	def test_data_qos(self):
		print_header("Data QoS")
		rlen = self.packet_bytes[3][2]
		ieee = ieee80211.IEEE80211(self.packet_bytes[3][rlen:])
		self.assertTrue(ieee.bin() == self.packet_bytes[3][rlen:])
		self.assertTrue(ieee.type == ieee80211.DATA_TYPE)
		self.assertTrue(ieee.subtype == ieee80211.D_QOS_DATA)
		self.assertTrue(ieee.dataframe.bssid == b"\x24\x65\x11\x85\xe9\xae")
		self.assertTrue(ieee.dataframe.src == b"\x00\xa0\x0b\x21\x37\x84")
		self.assertTrue(ieee.dataframe.seq_frag == 0xd008)
		print(ieee.dataframe.body_bytes)
		self.assertTrue(ieee.dataframe.body_bytes == b"\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01" +
		b"\x08\x00\x06\x04\x00\x01\x00\xa0\x0b\x21\x37\x84\xc0\xa8\xb2\x16\x00\x00\x00\x00" +
		b"\x00\x00\xc0\xa8\xb2\x01")
		#self.assertTrue(ieee.qos_data.control == 0x0)

	def test_rtap_ieee(self):
		print_header("Radiotap IEEE 80211")
		rtap_ieee = radiotap.Radiotap(self.packet_bytes[0])
		self.assertTrue(rtap_ieee.bin() == self.packet_bytes[0])
		self.assertTrue(rtap_ieee.version == 0)
		print("len: %d" % rtap_ieee.len)
		self.assertTrue(rtap_ieee.len == 0x1200)	# 0x1200 = 18
		self.assertTrue(rtap_ieee.present_flags == 0x2e480000)


class IP6TestCase(unittest.TestCase):
	def test_IP6(self):
		print_header("IPv6")
		packet_bytes = get_pcap("tests/packets_ip6.pcap")
		s = packet_bytes[0]

		eth = ethernet.Ethernet(s)
		ip = eth[ip6.IP6]
		print(s)
		self.assertTrue(eth.bin() == s)
		self.assertTrue(len(ip.opts) == 1)
		self.assertTrue(len(ip.opts[0].opts) == 2)
		self.assertTrue(ip.opts[0].opts[0].type == 5)
		self.assertTrue(ip.opts[0].opts[1].type == 1)


class DTPTestCase(unittest.TestCase):
	def test_DTP(self):
		print_header("DTP")
		s = b"\x01\x00\x01\x00\x08\x4c\x61\x62\x00\x00\x02\x00\x05\x04\x00\x03\x00\x05\x40\x00\x04\x00\x0a\x00\x19\x06\xea\xb8\x85"
		dtp1 = dtp.DTP(s)
		self.assertTrue(dtp1.bin() == s)
		for tv in dtp1.tvs:
			print("%s" % tv)
		self.assertTrue(len(dtp1.tvs) == 4)


class TelnetTestCase(unittest.TestCase):
	def test_telnet(self):
		print_header("Telnet")
		packet_bytes = get_pcap("tests/packets_telnet.pcap")

		telnet1 = ethernet.Ethernet(packet_bytes[0])[telnet.Telnet]
		print(telnet1.bin())
		print(packet_bytes[0][66:])
		self.assertTrue(telnet1.bin() == packet_bytes[0][66:])


class SSLTestCase(unittest.TestCase):
	def test_ssl(self):
		print_header("SSL")
		packet_bytes = get_pcap("tests/packets_ssl.pcap")

		ssl1 = ssl.SSL(packet_bytes[0][66:])
		self.assertTrue(ssl1.bin() == packet_bytes[0][66:])
		#print(packet_bytes[0][66:])

		ssl2 = ssl.SSL(packet_bytes[1][66:])
		self.assertTrue(ssl2.bin() == packet_bytes[1][66:])
		#print(packet_bytes[1][66:])

		ssl3 = ssl.SSL(packet_bytes[2][66:])
		self.assertTrue(ssl3.bin() == packet_bytes[2][66:])
		#print(packet_bytes[2][66:])

		ssl4 = ssl.SSL(packet_bytes[3][66:])
		self.assertTrue(ssl4.bin() == packet_bytes[3][66:])
		#print(packet_bytes[3][66:])


class TPKTTestCase(unittest.TestCase):
	def test_tpkt(self):
		print_header("TPKT")
		tpkt1 = tpkt.TPKT()
		tpkt1.bin()
		#bts = get_pcap("tests/packets_tpkt.pcap", 1)[0]
		#ether = ethernet.Ethernet(bts)
		#self.assertTrue(ether.bin() == bts)
		#self.assertTrue(ether[tpkt.TPKT] != None)


class PMAPTestCase(unittest.TestCase):
	def test_pmap(self):
		print_header("Pmap")
		pmap1 = pmap.Pmap()
		pmap1.bin()
		#bts = get_pcap("tests/packets_pmap.pcap", 1)[0]
		#ether = ethernet.Ethernet(bts)
		#self.assertTrue(ether.bin() == bts)
		#self.assertTrue(ether[pmap.Pmap] != None)


class RadiusTestCase(unittest.TestCase):
	def test_radius(self):
		print_header("Radius")
		radius1 = radius.Radius()
		radius1.bin()
		#bts = get_pcap("tests/packets_radius.pcap", 1)[0]
		#ether = ethernet.Ethernet(bts)
		#self.assertTrue(ether.bin() == bts)
		#self.assertTrue(ether[radius.Radius] != None)


class DiameterTestCase(unittest.TestCase):
	def test_diameter(self):
		print_header("Diameter")
		packet_bytes = get_pcap("tests/packets_diameter.pcap")

		# parsing
		dia_bytes = packet_bytes[0][62:]
		dia1 = diameter.Diameter(dia_bytes)

		self.assertTrue(dia1.bin() == dia_bytes)
		self.assertTrue(dia1 is not None)
		self.assertTrue(dia1.v == 1)
		self.assertTrue(dia1.len == b"\x00\x00\xe8")
		# dynamic fields
		print("AVPs: %d" % len(dia1.avps))
		self.assertTrue(len(dia1.avps) == 13)
		avp1 = dia1.avps[0]
		avp2 = dia1.avps[12]
		self.assertTrue(avp1.code == 268)
		self.assertTrue(avp2.code == 258)

		avp3 = diameter.AVP(code=1, flags=2, len=b"\x00\x00\x03", body_bytes=b"\xff\xff\xff")
		dia1.avps.append(avp3)
		self.assertTrue(len(dia1.avps) == 14)


class SocketTestCase(unittest.TestCase):
	def test_socket(self):
		print_header("Sockets")
		packet_eth = ethernet.Ethernet() +\
				ip.IP(src_s="192.168.178.27", dst_s="173.194.113.183") +\
				tcp.TCP(dport=80)
		packet_ip = ip.IP(src_s="192.168.178.27", dst_s="173.194.113.183") + tcp.TCP(dport=80)

		# Layer 2 Socket
		socket = SocketHndl(iface_name="eth1", mode=SocketHndl.MODE_LAYER_2)
		#socket.send(packet_eth.bin())
		packets = socket.sr(packet_eth)
		for p in packets:
			print(">>> %s" % p)
		socket.close()

		# Layer 3 Socket
		socket = SocketHndl(iface_name="eth1", mode=SocketHndl.MODE_LAYER_3)
		#socket.send(packet_ip.bin())
		packets = socket.sr(packet_ip)
		for p in packets:
			print(">>> %s" % p)
		socket.close()


class BGPTestCase(unittest.TestCase):
	def test_bgp(self):
		print_header("BGP")
		packet_bytes = get_pcap("tests/packets_bgp.pcap")

		# parsing
		bgp1_bytes = packet_bytes[0]
		bgp1 = ethernet.Ethernet(bgp1_bytes)
		bgp2_bytes = packet_bytes[1]
		bgp2 = ethernet.Ethernet(bgp2_bytes)
		bgp3_bytes = packet_bytes[2]
		bgp3 = ethernet.Ethernet(bgp3_bytes)

		self.assertTrue(bgp1.bin() == bgp1_bytes)
		self.assertTrue(bgp2.bin() == bgp2_bytes)
		self.assertTrue(bgp3.bin() == bgp3_bytes)


class ProducerConsumerTestCase(unittest.TestCase):
	def test_pc_iter(self):
		print_header("ProducerConsumer")
		ProducerConsumerTestCase.cnt = 0

		pc = producer_consumer.SortedProducerConsumer(ProducerConsumerTestCase.producer,
			ProducerConsumerTestCase.consumer)
		consumed = []

		for data in pc:
			consumed.append(data)
		print("finished SortedProducerConsumer")

		# data has to be returned in order
		cnt = 1
		for el in consumed:
			#print("%d = %d" % (el, cnt))
			self.assertTrue(el == cnt)
			cnt += 1
		pc.stop()
		self.assertTrue(pc.is_stopped)

	cnt = 0

	def producer():
		ProducerConsumerTestCase.cnt += 1
		if ProducerConsumerTestCase.cnt > 1000:
			raise StopIteration

		time.sleep(int(random.random()))
		print("produced: %d" % ProducerConsumerTestCase.cnt)
		return ProducerConsumerTestCase.cnt

	def consumer(data):
		time.sleep(int(random.random() * 2))
		print("consumed: %d" % data)
		return data


suite = unittest.TestSuite()
loader = unittest.defaultTestLoader

suite.addTests(loader.loadTestsFromTestCase(GeneralTestCase))
suite.addTests(loader.loadTestsFromTestCase(EthTestCase))
suite.addTests(loader.loadTestsFromTestCase(IPTestCase))
suite.addTests(loader.loadTestsFromTestCase(IP6TestCase))
suite.addTests(loader.loadTestsFromTestCase(TCPTestCase))
suite.addTests(loader.loadTestsFromTestCase(UDPTestCase))
suite.addTests(loader.loadTestsFromTestCase(HTTPTestCase))
suite.addTests(loader.loadTestsFromTestCase(AccessConcatTestCase))
suite.addTests(loader.loadTestsFromTestCase(IterateTestCase))
suite.addTests(loader.loadTestsFromTestCase(StaticFieldActivateDeactivateTestCase))
suite.addTests(loader.loadTestsFromTestCase(DynamicFieldTestCase))
suite.addTests(loader.loadTestsFromTestCase(ICMPTestCase))
suite.addTests(loader.loadTestsFromTestCase(OSPFTestCase))
suite.addTests(loader.loadTestsFromTestCase(PPPTestCase))
suite.addTests(loader.loadTestsFromTestCase(STPTestCase))
suite.addTests(loader.loadTestsFromTestCase(VRRPTestCase))
suite.addTests(loader.loadTestsFromTestCase(IGMPTestCase))
suite.addTests(loader.loadTestsFromTestCase(IPXTestCase))
suite.addTests(loader.loadTestsFromTestCase(PIMTestCase))
suite.addTests(loader.loadTestsFromTestCase(HSRPTestCase))
suite.addTests(loader.loadTestsFromTestCase(NTPTestCase))
suite.addTests(loader.loadTestsFromTestCase(DHCPTestCase))
suite.addTests(loader.loadTestsFromTestCase(RIPTestCase))
suite.addTests(loader.loadTestsFromTestCase(SCTPTestCase))
suite.addTests(loader.loadTestsFromTestCase(ReaderTestCase))
suite.addTests(loader.loadTestsFromTestCase(MultiprocUnpackerTest))
suite.addTests(loader.loadTestsFromTestCase(ReaderNgTestCase))
suite.addTests(loader.loadTestsFromTestCase(ReaderPcapNgTestCase))
suite.addTests(loader.loadTestsFromTestCase(ReadWriteReadTestCase))
suite.addTests(loader.loadTestsFromTestCase(RadiotapTestCase))
#suite.addTests(loader.loadTestsFromTestCase(PerfTestPpcapBigfile))
suite.addTests(loader.loadTestsFromTestCase(IEEE80211TestCase))
suite.addTests(loader.loadTestsFromTestCase(DTPTestCase))
suite.addTests(loader.loadTestsFromTestCase(DNSTestCase))
suite.addTests(loader.loadTestsFromTestCase(TelnetTestCase))
suite.addTests(loader.loadTestsFromTestCase(SSLTestCase))
suite.addTests(loader.loadTestsFromTestCase(TPKTTestCase))
suite.addTests(loader.loadTestsFromTestCase(PMAPTestCase))
suite.addTests(loader.loadTestsFromTestCase(RadiusTestCase))
suite.addTests(loader.loadTestsFromTestCase(DiameterTestCase))
suite.addTests(loader.loadTestsFromTestCase(BGPTestCase))

# uncomment this to enable performance tests
#suite.addTests(loader.loadTestsFromTestCase(PerfTestCase))
#suite.addTests(loader.loadTestsFromTestCase(PerfTestPpcapCase))
#suite.addTests(loader.loadTestsFromTestCase(SocketTestCase))
#suite.addTests(loader.loadTestsFromTestCase(ProducerConsumerTestCase))

unittest.TextTestRunner().run(suite)
