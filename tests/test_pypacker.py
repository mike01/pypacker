from pypacker import pypacker
from pypacker.psocket import SocketHndl
from pypacker import producer_consumer
import pypacker.ppcap as ppcap
# alternative ppcap implementation without ts conversion
try:
	import pypacker.ppcap_no_con as ppcap_no_con
except:
	pass
from pypacker.layer12 import arp, dtp, ethernet, ieee80211, ppp, radiotap, stp, vrrp
from pypacker.layer3 import ah, ip, ip6, ipx, icmp, igmp, ospf, pim
from pypacker.layer4 import tcp, udp, sctp, ssl
from pypacker.layer567 import diameter, dhcp, dns, hsrp, http, ntp, pmap, radius, rip, rtp, telnet, tftp, tpkt

import unittest
import time
import sys
import random

# General testcases:
# - Length comparing before/after parsing
# - Concatination via "+" (+parsing)
# - type finding via packet[type]
# Things to test on every protocol:
# - raw byte parsing
# - header changes
# - direction of packages
# - checksums
# - dynamic/optional headers
#
# Successfully tested:
# - Ethernet
# - Radiotap
# - IEEE 80211
# - ARP
# - DNS
# - STP
# - PPP
# - PPPoE
# - OSPF
# - STP
# - VRRP
# - DTP
#
# - IP
# - IP6
# - ICMP
# - PIM
# - AH
# - ESP
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
# - TFTP
# - Telnet
# - AIM
# - HSRP
# - Diameter
# - SSL
# - TPKT
# - Pmap
# - Radius
# - BGP
# 
# TBD:
# - CDP
# - LLC
#
# - ICMP6
#
# - SCCP
#
# - Netflow
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
BYTES_NTP = BYTES_UDP[:3] + b"\x7B" + BYTES_UDP[4:] + b"\x24\x02\x04\xef\x00\x00\x00\x84\x00\x00\x33\x27\xc1\x02\x04\x02\xc8\x90\xec\x11\x22\xae\x07\xe5\xc8\x90\xf9\xd9\xc0\x7e\x8c\xcd\xc8\x90\xf9\xd9\xda\xc5\xb0\x78\xc8\x90\xf9\xd9\xda\xc6\x8a\x93"
## RIP
BYTES_RIP = b"\x02\x02\x00\x00\x00\x02\x00\x00\x01\x02\x03\x00\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x02\x00\x00\xc0\xa8\x01\x08\xff\xff\xff\xfc\x00\x00\x00\x00\x00\x00\x00\x01"

def print_header(msg):
	print()
	print(">>>>>>>>> "+msg+" <<<<<<<<<")

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
		self.assertTrue(eth1.src_s == "08:00:27:a9:93:9e")
		# Ethernet without body + vlan
		s = b"\x52\x54\x00\x12\x35\x02\x08\x00\x27\xa9\x93\x9e\x81\x00\xff\xff\x08\x00"
		eth1b = ethernet.Ethernet(s)
		# parsing
		self.assertTrue(eth1b.bin() == s)
		self.assertTrue(eth1b.dst_s == "52:54:00:12:35:02")
		self.assertTrue(eth1b.src_s == "08:00:27:a9:93:9e")
		self.assertTrue(eth1b.vlan == b"\x81\x00\xff\xff")
		self.assertTrue(eth1b.type == 0x0800)
		# header field update
		mac1 = "aa:bb:cc:dd:ee:00"
		mac2 = "aa:bb:cc:dd:ee:01"
		eth1.dst_s = mac2
		eth1.src_s = mac1
		self.assertTrue(eth1.dst_s == mac2)
		self.assertTrue(eth1.src_s == mac1)
		# Ethernet + IP
		s= b"\x52\x54\x00\x12\x35\x02\x08\x00\x27\xa9\x93\x9e\x08\x00\x45\x00\x00\x37\xc5\x78\x40\x00\x40\x11\x9c\x81\x0a\x00\x02\x0f\x0a\x20\xc2\x8d"
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
		ip3_bytes = b"\x49"  + ip1_bytes[1:] + b"\x03\04\x00\x07" + b"\x09\03\x07" + b"\x01"
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
		self.assertTrue(ip3.opts[0].data == b"\x00\x07")

		print("opts 2")
		for o in ip3.opts:
			print(o)

		ip3.opts.append((ip.IP_OPT_TS, b"\x00\x01\x02\x03"))
		self.assertTrue(len(ip3.opts) == 3)
		self.assertTrue(ip3.opts[2].type == ip.IP_OPT_TS)
		self.assertTrue(ip3.opts[2].data == b"\x00\x01\x02\x03")

		print("opts 3")
		ip3.opts.append((ip.IP_OPT_TS, b"\x00"))

		for o in ip3.opts:
			print(o)

		print("header offset: %d" % ip3.hl)
		self.assertTrue(ip3.hl == 9)


class TCPTestCase(unittest.TestCase):
	def test_TCP(self):
		print_header("TCP")
		packet_bytes = []
		f = open("tests/packets_ssl.pcap", "rb")
		pcap = ppcap.Reader(f)

		for ts, buf in pcap:
			packet_bytes.append(buf)
			break

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
		self.assertTrue(tcp1.direction(tcp2) == pypacker.Packet.DIR_REV)
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
		print(tcp2.opts[2].data)
		self.assertTrue(tcp2.opts[2].data == b"\x01\x0b\x5d\xb3\x21\x3d\xc7\xd9")

		tcp2.opts.append((tcp.TCP_OPT_WSCALE, b"\x00\x01\x02\x03\x04\x05"))	# header length 20 + (12 + 8 options)
		for opt in tcp2.opts:
			print(opt)
		self.assertTrue(len(tcp2.opts) == 4)
		self.assertTrue(tcp2.opts[3].type == tcp.TCP_OPT_WSCALE)
		print("offset is: %s" % tcp2.off)
		self.assertTrue(tcp2.off == 10)


class UDPTestCase(unittest.TestCase):
	def test_UDP(self):
		print_header("UDP")
		packet_bytes = []
		f = open("tests/packets_dns.pcap", "rb")
		pcap = ppcap.Reader(f)

		for ts, buf in pcap:
			packet_bytes.append(buf)
			break

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
		http1.header[0] = (b"POST / HTTP/1.1",)
		print("http bin: %s" % http1.bin())
		self.assertTrue(http1.bin() == s2)
		self.assertTrue(http1.header[1][1] == b"value1")
		print(">>> new startline GET")
		http1.header[0] = (b"GET / HTTP/1.1",)
		self.assertTrue(http1.bin() == s1)
		print(">>> resetting body")
		s3 = b"GET / HTTP/1.1\r\nHeader1: value1\r\nHeader2: value2"
		http1.data = b""
		self.assertTrue(http1.bin() == s3)
		# TODO: set ether + ip + tcp + http
		#print("HTTP headers: %s" % http1.headers)


class AccessConcatTestCase(unittest.TestCase):
	def test_concat(self):
		print_header("CONCAT")
		packet_bytes = []
		f = open("tests/packets_telnet.pcap", "rb")
		pcap = ppcap.Reader(f)

		for ts, buf in pcap:
			packet_bytes.append(buf)

		# create single layers
		bytes_eth_ip_tcp_tn =  packet_bytes[0]
		l_eth = bytes_eth_ip_tcp_tn[:14]
		l_ip = bytes_eth_ip_tcp_tn[14:34]
		l_tcp = bytes_eth_ip_tcp_tn[34:66]
		l_tn = bytes_eth_ip_tcp_tn[66:]

		p_all = ethernet.Ethernet(bytes_eth_ip_tcp_tn)
		self.assertTrue(p_all.bin() == bytes_eth_ip_tcp_tn)

		eth1 = ethernet.Ethernet(l_eth)
		ip1 = ip.IP(l_ip)
		tcp1 = tcp.TCP(l_tcp)
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

		for opt in tcp1.opts:
			#print("adding option: %s" % opt)
			tcp2.opts.append(opt)

		tn2 = telnet.Telnet(l_tn)

		p_all2 = eth2 + ip2 + tcp2 + tn2

		for l in [ethernet.Ethernet, ip.IP, tcp.TCP, telnet.Telnet]:
			print(p_all[l])
			print(p_all2[l])
			print("-----")
		self.assertTrue(p_all2.bin() == p_all.bin())



class ICMPTestCase(unittest.TestCase):
	def test_concat(self):
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


class AHTestCase(unittest.TestCase):
	def test_ah(self):
		print_header("AH")
		s = b"\x06\x0c\x00\x00\x11\x11\x11\x11\x22\x22\x22\x22" + BYTES_TCP
		ah1 = ah.AH(s)
		self.assertTrue(ah1.bin() == s)


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
		dhcp2.opts.insert(4, (dhcp.DHCP_OPT_TCPTTL, b"\x00\x01\x02"))
		print("new TLlen: %d" % len(dhcp2.opts))
		self.assertTrue(len(dhcp2.opts) == 6)
		self.assertTrue(dhcp2.opts[4].type == dhcp.DHCP_OPT_TCPTTL)


class DNSTestCase(unittest.TestCase):
	def test_dns(self):
		print_header("DNS")
		packet_bytes = get_pcap("tests/packets_dns.pcap", 10)

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
		packet_bytes = []
		f = open("tests/packets_sctp.pcap", "rb")
		pcap = ppcap.Reader(f)

		for ts, buf in pcap:
			packet_bytes.append(buf)

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
		sct.chunks.append((sctp.DATA, 0xff, b"\x00\x01\x02"))
		self.assertTrue(len(sct.chunks) == 2)
		self.assertTrue(sct.chunks[1].data == b"\x00\x01\x02")
		# lazy init of chunks
		sct2 = sctp.SCTP()
		sct2.chunks.append((sctp.DATA, 0xff, b"\x00\x01\x02"))
		self.assertTrue(len(sct2.chunks) == 1)


class ReaderTestCase(unittest.TestCase):
	def test_reader(self):
		print_header("READER standard")
		import os
		print(os.getcwd())
		f = open("tests/packets_ether.pcap", "rb")
		pcap = ppcap.Reader(f, ts_conversion=False)

		cnt = 0
		proto_cnt = { arp.ARP:4,
				tcp.TCP:34,
				udp.UDP:4,
				icmp.ICMP:7,
				http.HTTP:12	# HTTP found = TCP having payload!
				}
		for ts, buf in pcap:
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
		for k,v in proto_cnt.items():
			print("%s: %s" % (k.__name__, v))
			self.assertTrue(v == 0)

	def test_reader_pmode(self):
		print_header("READER pmode")
		import os
		print(os.getcwd())
		f = open("tests/packets_ether.pcap", "rb")

		def filter(pkt):
			return pkt[ethernet.Ethernet] != None

		pcap = ppcap.Reader(f, lowest_layer=ethernet.Ethernet, filter=filter)

		cnt = 0
		proto_cnt = { arp.ARP:4,
				tcp.TCP:34,
				udp.UDP:4,
				icmp.ICMP:7,
				http.HTTP:12	# HTTP found = TCP having payload!
				}

		for ts, eth in pcap:
			#print("buf is: %s" % buf)
			cnt += 1
			#print("%02d TS: %.40f LEN: %d" % (cnt, ts, len(eth)))
			keys = proto_cnt.keys()

			for k in keys:
				if eth[k] is not None:
					proto_cnt[k] -= 1
					#if k == http.HTTP:
					#	print("found HTTP at: %d" % cnt)
					#break

		self.assertTrue(cnt == 49)

		print("proto summary:")
		for k,v in proto_cnt.items():
			print("%s: %s" % (k.__name__, v))
			self.assertTrue(v == 0)

class ReaderNgTestCase(unittest.TestCase):
	def test_reader(self):
		print_header("READER PCAP NG")
		import os
		print(os.getcwd())
		f = open("tests/packets_ether.pcapng", "rb")
		pcap = ppcap.Reader(f)

		cnt = 0
		proto_cnt = { arp.ARP:4,
				tcp.TCP:34,
				udp.UDP:4,
				icmp.ICMP:7,
				http.HTTP:12	# HTTP found = TCP having payload!
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
		for k,v in proto_cnt.items():
			print("%s: %s" % (k.__name__, v))
			self.assertTrue(v == 0)


class RadiotapTestCase(unittest.TestCase):
	def test_radiotap(self):
		print_header("Radiotap")
		# radiotap: flags, rate channel, dBm Antenna, Antenna, RX Flags
		s = b"\x00\x00\x12\x00\x2e\x48\x00\x00\x00\x02\x6c\x09\xa0\x00\xc2\x07\x00\x00\xff\xff"
		radiotap.Radiotap.skip_upperlayer = True
		rad = radiotap.Radiotap(s)
		self.assertTrue(rad.bin() == s)
		print(rad)

		self.assertTrue(rad.version == 0)
		print("len: %d" % rad.len)
		self.assertTrue(rad.len == 4608)	# 0x1200 = 18
		self.assertTrue(rad.present_flags == 0x2e480000)
		channel_bytes = rad.flags.find_by_id(radiotap.CHANNEL_MASK)[0][1]
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
		s = b"E\x00\x00T\xc2\xf3\x00\x00\xff\x01\xe2\x18\n\x00\x01\x92\n\x00\x01\x0b\x08\x00\xfc\x11:g\x00\x00A,\xc66\x00\x0e\xcf\x12\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f!"#$%&\'()*+,-./01234567"
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
		print("or = 37738 pps")

		print(">>> creating/direct assigning (IP + data)")
		start = time.time()
		for i in range(cnt):
			#ip = IP(src="1.2.3.4", dst="1.2.3.5").bin()
			ip.IP(src=b"\x01\x02\x03\x04", dst=b"\x05\x06\x07\x08", p=17, len=1234, data=b"abcd")
			#ip = IP(src=b"\x01\x02\x03\x04", dst=b"\x05\x06\x07\x08", p=17, len=1234, data=b"abcd")
		print("time diff: %ss" % (time.time() - start))
		print("nr = %d pps" % (cnt / (time.time() - start)) )
		print("or = 39124 pps")

		print(">>> output without change (IP)")
		ip2 = ip.IP(src=b"\x01\x02\x03\x04", dst=b"\x05\x06\x07\x08", p=17, len=1234, data=b"abcd")
		start = time.time()
		for i in range(cnt):
			ip2.bin()
		print("time diff: %ss" % (time.time() - start))
		print("nr = %d pps" % (cnt / (time.time() - start)) )
		print("or = 215713 pps")

		print(">>> output with change/checksum recalculation (IP)")
		ip3 = ip.IP(src=b"\x01\x02\x03\x04", dst=b"\x05\x06\x07\x08", p=17, len=1234, data=b"abcd")
		start = time.time()
		for i in range(cnt):
			ip3.src = b"\x01\x02\x03\x04"
			ip3.bin()
		print("time diff: %ss" % (time.time() - start))
		print("nr = %d pps" % (cnt / (time.time() - start)) )
		print("or = 15854 pps")

		print(">>> parsing (Ethernet + IP + TCP + HTTP)")
		global BYTES_ETH_IP_TCP_HTTP
		start = time.time()
		for i in range(cnt):
			eth = ethernet.Ethernet(BYTES_ETH_IP_TCP_HTTP)
		print("time diff: %ss" % (time.time() - start))
		print("nr = %d pps" % (cnt / (time.time() - start)) )
		print("or = 53208 pps")

		print(">>> changing Triggerlist/binary proto (Ethernet + IP + TCP + HTTP)")
		start = time.time()
		eth1 = ethernet.Ethernet(BYTES_ETH_IP_TCP_HTTP)
		tcp1 = eth1[tcp.TCP]
		for i in range(cnt):
			tcp1.opts[0].type = tcp.TCP_OPT_WSCALE
		print("time diff: %ss" % (time.time() - start))
		print("nr = %d pps" % (cnt / (time.time() - start)) )
		print("or = 146711 pps")

		print(">>> changing Triggerlist/text based proto (Ethernet + IP + TCP + HTTP)")
		start = time.time()
		eth1 = ethernet.Ethernet(BYTES_ETH_IP_TCP_HTTP)
		http1 = eth1[http.HTTP]
		for i in range(cnt):
			http1.header[0] = (b"GET / HTTP/1.1",)
		print("time diff: %ss" % (time.time() - start))
		print("nr = %d pps" % (cnt / (time.time() - start)) )
		print("or = 87691 pps")

		print(">>> direct assigning and concatination (Ethernet + IP + TCP + HTTP)")
		start = time.time()
		for i in range(cnt):
			concat = ethernet.Ethernet(dst_s="ff:ff:ff:ff:ff:ff", src_s="ff:ff:ff:ff:ff:ff") +\
				ip.IP(src_s="127.0.0.1", dst_s="192.168.0.1") +\
				tcp.TCP(sport=1234, dport=123) +\
				http.HTTP()
		print("time diff: %ss" % (time.time() - start))
		print("nr = %d pps" % (cnt / (time.time() - start)) )
		print("or = 9550 pps")

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
		#tcp.TCP.skip_upperlayer = True

		start = time.time()
		for i in range(cnt):
			p = ethernet.Ethernet(s)
		tcp.TCP.skip_upperlayer = False
			
		print("time diff: %ss" % (time.time() - start))
		print("nr = %d pps" % (cnt / (time.time() - start)) )
		print("or = 50191 pps")
		print("or (scapy) = 1769 pps")


class PerfTestPpcapCase(unittest.TestCase):
	def test_perf(self):
		print_header("Performance Tests for ppcap big file parsing")
		cnt = 1
		p = None

		print("time diff (ppcap reading without ts recalc to nanoseconds)")
		start = time.time()

		for a in range(cnt):
			#f = open("tests/packets_rtap.pcap", "rb")
			f = open("tests/packets_bigfile.pcap", "rb")
			#pcap = ppcap.Reader(f, ts_conversion=False)
			pcap = ppcap.Reader(f, ts_conversion=False)

			for ts, buf in pcap:
				p = ts
				p = buf
			pcap.close()

		diff = time.time() - start
		print("nr = %f sec" % diff)
		print("or = 0.619 sec")

		#ethernet.Ethernet.skip_upperlayer = True
		print("time diff (ppcap reading + parsing without ts recalc to nanoseconds)")
		start = time.time()
		#ip.IP.skip_upperlayer = True

		for a in range(cnt):
			#f = open("tests/packets_rtap.pcap", "rb")
			f = open("tests/packets_bigfile.pcap", "rb")
			#pcap = ppcap.Reader(f, ts_conversion=False)
			pcap = ppcap.Reader(f, lowest_layer=ethernet.Ethernet, ts_conversion=False)

			for ts, buf in pcap:
				p = ts
				p = buf
			pcap.close()

		diff = time.time() - start
		print("nr = %f sec" % diff)
		print("or = 6.274 sec")
		ethernet.Ethernet.skip_upperlayer = False


class IEEE80211TestCase(unittest.TestCase):
	def setUp(self):
		if hasattr(self, "packet_bytes"):
			return
		#print(">>>>>>>>> IEEE 802.11 <<<<<<<<<")
		print("loading IEEE packets")

		self.packet_bytes = []
		# >>> loaded bytes
		# Beacon
		# CTS 
		# ACK
		# QoS Data
		# Action
		# Data
		# QoS Null function
		# Radiotap length: 18 bytes
	
		f = open("tests/packets_rtap_sel.pcap", "rb")
		pcap = ppcap.Reader(f)

		for ts, buf in pcap:
			#print(".")
			self.packet_bytes.append(buf)


	def test_ack(self):
		print(">>>>>>>>> ACK <<<<<<<<<")
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
		self.assertTrue(ieee.wep == 0)
		self.assertTrue(ieee.order == 0)
		self.assertTrue(ieee.ack.dst == b"\x00\xa0\x0b\x21\x37\x84")

	def test_beacon(self):
		print(">>>>>>>>> Beacon <<<<<<<<<")
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
		self.assertTrue(ieee.wep == 0)
		self.assertTrue(ieee.order == 0)
		self.assertTrue(ieee.mgmtframe.dst == b"\xff\xff\xff\xff\xff\xff")
		self.assertTrue(ieee.mgmtframe.src == b"\x24\x65\x11\x85\xe9\xae")
		self.assertTrue(ieee.mgmtframe.beacon.capability == 0x3104)
		# TODO: test IEs
		#self.assertTrue(ieee.capability.privacy == 1)
		#self.assertTrue(ieee.mgmtframe.beacon.data == "CAEN")
		#self.assertTrue(ieee.rate.data == b"\x82\x84\x8b\x0c\x12\x96\x18\x24")
		#self.assertTrue(ieee.ds.data == b"\x01")
		#self.assertTrue(ieee.tim.data == b"\x00\x01\x00\x00")

	def test_data(self):
		print(">>>>>>>>> Data <<<<<<<<<")
		rlen = self.packet_bytes[5][2]
		ieee = ieee80211.IEEE80211(self.packet_bytes[5][rlen:])
		self.assertTrue(ieee.bin() == self.packet_bytes[5][rlen:])
		self.assertTrue(ieee.type == ieee80211.DATA_TYPE)
		self.assertTrue(ieee.subtype == ieee80211.D_DATA)
		print("type is: %s" % type(ieee.data))
		self.assertTrue(ieee.datafromds.dst == b"\x01\x00\x5e\x7f\xff\xfa")
		self.assertTrue(ieee.datafromds.src == b"\x00\x1e\xe5\xe0\x8c\x06")
		self.assertTrue(ieee.datafromds.frag_seq == 0x501e)
		self.assertTrue(ieee.datafromds.data == b"\x62\x22\x39\x61\x98\xd1\xff\x34\x65\xab\xc1\x3c\x8e\xcb\xec\xef\xef\xf6\x25\xab\xe5\x89\x86\xdf\x74\x19\xb0\xa4\x86\xc2\xdb\x38\x20\x59\x08\x1f\x04\x1b\x96\x6b\x01\xd7\x6a\x85\x73\xf5\x4a\xf1\xa1\x2f\xf3\xfb\x49\xb7\x6b\x6a\x38\xef\xa8\x39\x33\xa1\xc8\x29\xc7\x0a\x88\x39\x7c\x31\xbf\x55\x96\x24\xd5\xe1\xbf\x62\x85\x2c\xe3\xdf\xb6\x80\x3e\x92\x1c\xbf\x13\xcd\x47\x00\x8e\x9f\xc6\xa7\x81\x91\x71\x9c\x0c\xad\x08\xe2\xe8\x5f\xac\xd3\x1c\x90\x16\x15\xa0\x71\x30\xee\xac\xdd\xe5\x8d\x1f\x5b\xbc\xb6\x03\x51\xf1\xee\xff\xaa\xc9\xf5\x16\x1d\x2c\x5e\x52\x49\x3c\xaf\x7f\x13\x12\x1a\x24\xfb\xb8\xc1\x4e\xb7\xd8\x53\xfb\x76\xc0\x6e\xc8\x30\x8d\x2a\x65\xfd\x5d\x1c\xee\x97\x0d\xa3\x5c\x0f\x6c\x08\x5b\x2c\x0b\xbf\x64\xdb\x52\x2d\x8e\x92\x4f\x12\xbe\x6c\x87\x78\xb7\x7d\xc8\x42\xd8\x68\x83\x29\x04\xb5\x20\x91\xb2\xc9\xb9\x65\x45\xf4\xf6\xf4\xb7\xbd\x9d\x86\xc4\xab\xbe\x95\x9e\xe3\x82\x39\xcf\x95\xf4\x68\x7c\xb7\x00\xbb\x5d\xab\x35\x86\xa0\x11\x49\x50\x6c\x28\xc4\x18\xb5\x2f\x3f\xfc\x23\x90\x1c\x9f\x81\x5a\x14\xcf\xbf\xc4\xf4\x38\x0b\x61\x6d\xd1\x57\x49\xba\x31\x2d\xa5\x0f\x3d\x76\x24\xb4\xf9\xa3\xe1\x33\xae\x9f\x69\x67\x23")

		#llc_pkt = LLC(ieee.data_frame.data)
		#ip_pkt = ip.IP(llc_pkt.data)
		#self.assertTrue(ip_pkt.dst == b"\x3f\xf5\xd1\x69")

	def test_data_qos(self):
		print(">>>>>>>>> Data QoS <<<<<<<<<")
		rlen = self.packet_bytes[3][2]
		ieee = ieee80211.IEEE80211(self.packet_bytes[3][rlen:])
		self.assertTrue(ieee.bin() == self.packet_bytes[3][rlen:])
		self.assertTrue(ieee.type == ieee80211.DATA_TYPE)
		self.assertTrue(ieee.subtype == ieee80211.D_QOS_DATA)
		self.assertTrue(ieee.datatods.dst == b"\x24\x65\x11\x85\xe9\xac")
		self.assertTrue(ieee.datatods.src == b"\x00\xa0\x0b\x21\x37\x84")
		self.assertTrue(ieee.datatods.frag_seq == 0xd008)
		self.assertTrue(ieee.datatods.data == b"\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x00\xa0\x0b\x21\x37\x84\xc0\xa8\xb2\x16\x00\x00\x00\x00\x00\x00\xc0\xa8\xb2\x01")
		#self.assertTrue(ieee.qos_data.control == 0x0)


	def test_rtap_ieee(self):
		print(">>>>>>>>> Radiotap IEEE 80211 <<<<<<<<<")
		rtap_ieee = radiotap.Radiotap(self.packet_bytes[0])
		self.assertTrue(rtap_ieee.bin() == self.packet_bytes[0])
		self.assertTrue(rtap_ieee.version == 0)
		print("len: %d" % rtap_ieee.len)
		self.assertTrue(rtap_ieee.len == 4608)	# 0x1200 = 18
		self.assertTrue(rtap_ieee.present_flags == 0x2e480000)
		
	def _test_bug(self):
		s= b"\x88\x41\x2c\x00\x00\x26\xcb\x17\x44\xf0\x00\x1e\x52\x97\x14\x11\x00\x1f\x6d\xe8\x18\x00\xd0\x07\x00\x00\x6f\x00\x00\x20\x00\x00\x00\x00"
		ieee = ieee80211.IEEE80211(s)
		self.assertTrue(ieee.wep == 1)


class IP6TestCase(unittest.TestCase):
	def test_IP6(self):
		print(">>>>>>>>> IPv6 <<<<<<<<<")
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
		print(">>>>>>>>> DTP <<<<<<<<<")
		s = b"\x01\x00\x01\x00\x08\x4c\x61\x62\x00\x00\x02\x00\x05\x04\x00\x03\x00\x05\x40\x00\x04\x00\x0a\x00\x19\x06\xea\xb8\x85"
		dtp1 = dtp.DTP(s)
		self.assertTrue(dtp1.bin() == s)
		for tv in dtp1.tvs:
			print("%s" % tv)
		self.assertTrue(len(dtp1.tvs) == 4)


class TelnetTestCase(unittest.TestCase):
	def test_telnet(self):
		print(">>>>>>>>> Telnet <<<<<<<<<")
		packet_bytes = []
		f = open("tests/packets_telnet.pcap", "rb")
		pcap = ppcap.Reader(f)

		for ts, buf in pcap:
			packet_bytes.append(buf)

		telnet1 = ethernet.Ethernet(packet_bytes[0])[telnet.Telnet]
		print(telnet1.bin())
		print(packet_bytes[0][66:])
		self.assertTrue(telnet1.bin() == packet_bytes[0][66:])


class SSLTestCase(unittest.TestCase):
	def test_ssl(self):
		print(">>>>>>>>> SSL <<<<<<<<<")

		packet_bytes = []
		f = open("tests/packets_ssl.pcap", "rb")
		pcap = ppcap.Reader(f)

		print("reading packets")
		for ts, buf in pcap:
			packet_bytes.append(buf)

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
		print(">>>>>>>>> TPKT <<<<<<<<<")
		tpkt1 = tpkt.TPKT()
		tpkt1.bin()
		#bts = get_pcap("tests/packets_tpkt.pcap", 1)[0]
		#ether = ethernet.Ethernet(bts)
		#self.assertTrue(ether.bin() == bts)
		#self.assertTrue(ether[tpkt.TPKT] != None)

class PMAPTestCase(unittest.TestCase):
	def test_pmap(self):
		print(">>>>>>>>> Pmap <<<<<<<<<")
		pmap1 = pmap.Pmap()
		pmap1.bin()
		#bts = get_pcap("tests/packets_pmap.pcap", 1)[0]
		#ether = ethernet.Ethernet(bts)
		#self.assertTrue(ether.bin() == bts)
		#self.assertTrue(ether[pmap.Pmap] != None)

class RadiusTestCase(unittest.TestCase):
	def test_radius(self):
		print(">>>>>>>>> Radius <<<<<<<<<")
		radius1 = radius.Radius()
		radius1.bin()
		#bts = get_pcap("tests/packets_radius.pcap", 1)[0]
		#ether = ethernet.Ethernet(bts)
		#self.assertTrue(ether.bin() == bts)
		#self.assertTrue(ether[radius.Radius] != None)

class DiameterTestCase(unittest.TestCase):
	def test_diameter(self):
		print(">>>>>>>>> Diameter <<<<<<<<<")
		packet_bytes = []
		f = open("tests/packets_diameter.pcap", "rb")
		pcap = ppcap.Reader(f)

		for ts, buf in pcap:
			packet_bytes.append(buf)
			break

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

		avp3 = diameter.AVP(code=1, flags=2, len=b"\x00\x00\x03", data=b"\xff\xff\xff")
		dia1.avps.append(avp3)
		self.assertTrue(len(dia1.avps) == 14)


class SocketTestCase(unittest.TestCase):
	def test_socket(self):
		print(">>>>>>>>> SOCKETS <<<<<<<<<")
		packet_eth = ethernet.Ethernet() +\
			ip.IP(src_s="192.168.178.27", dst_s="173.194.113.183") +\
			tcp.TCP(dport=80)
		packet_ip = ip.IP(src_s="192.168.178.27", dst_s="173.194.113.183") +\
			tcp.TCP(dport=80)

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
		print(">>>>>>>>> BGP <<<<<<<<<")

		packet_bytes = []
		f = open("tests/packets_bgp.pcap", "rb")
		pcap = ppcap.Reader(f)

		print("reading packets")
		for ts, buf in pcap:
			packet_bytes.append(buf)

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
		print(">>>>>>>>> ProducerConsumer <<<<<<<<<")
		ProducerConsumerTestCase.cnt = 0

		pc = producer_consumer.SortedProducerConsumer(ProducerConsumerTestCase.producer,\
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
		self.assertTrue(pc.is_stopped == True)

	cnt = 0

	def producer():
		ProducerConsumerTestCase.cnt += 1
		if ProducerConsumerTestCase.cnt > 1000:
			raise StopIteration

		time.sleep(int(random.random()))
		print("produced: %d" % ProducerConsumerTestCase.cnt)
		return ProducerConsumerTestCase.cnt

	def consumer(data):
		time.sleep(int(random.random()*2))
		print("consumed: %d" % data)
		return data
#
# TBD
#

class ASN1TestCase(unittest.TestCase):
	def test_asn1(self):
		s = b"0\x82\x02Q\x02\x01\x0bc\x82\x02J\x04xcn=Douglas J Song 1, ou=Information Technology Division, ou=Faculty and Staff, ou=People, o=University of Michigan, c=US\n\x01\x00\n\x01\x03\x02\x01\x00\x02\x01\x00\x01\x01\x00\x87\x0bobjectclass0\x82\x01\xb0\x04\rmemberOfGroup\x04\x03acl\x04\x02cn\x04\x05title\x04\rpostalAddress\x04\x0ftelephoneNumber\x04\x04mail\x04\x06member\x04\thomePhone\x04\x11homePostalAddress\x04\x0bobjectClass\x04\x0bdescription\x04\x18facsimileTelephoneNumber\x04\x05pager\x04\x03uid\x04\x0cuserPassword\x04\x08joinable\x04\x10associatedDomain\x04\x05owner\x04\x0erfc822ErrorsTo\x04\x08ErrorsTo\x04\x10rfc822RequestsTo\x04\nRequestsTo\x04\tmoderator\x04\nlabeledURL\x04\nonVacation\x04\x0fvacationMessage\x04\x05drink\x04\x0elastModifiedBy\x04\x10lastModifiedTime\x04\rmodifiersname\x04\x0fmodifytimestamp\x04\x0ccreatorsname\x04\x0fcreatetimestamp"
		self.assertTrue(decode(s) == [(48, [(2, 11), (99, [(4, "cn=Douglas J Song 1, ou=Information Technology Division, ou=Faculty and Staff, ou=People, o=University of Michigan, c=US"), (10, "\x00"), (10, "\x03"), (2, 0), (2, 0), (1, "\x00"), (135, "objectclass"), (48, [(4, "memberOfGroup"), (4, "acl"), (4, "cn"), (4, "title"), (4, "postalAddress"), (4, "telephoneNumber"), (4, "mail"), (4, "member"), (4, "homePhone"), (4, "homePostalAddress"), (4, "objectClass"), (4, "description"), (4, "facsimileTelephoneNumber"), (4, "pager"), (4, "uid"), (4, "userPassword"), (4, "joinable"), (4, "associatedDomain"), (4, "owner"), (4, "rfc822ErrorsTo"), (4, "ErrorsTo"), (4, "rfc822RequestsTo"), (4, "RequestsTo"), (4, "moderator"), (4, "labeledURL"), (4, "onVacation"), (4, "vacationMessage"), (4, "drink"), (4, "lastModifiedBy"), (4, "lastModifiedTime"), (4, "modifiersname"), (4, "modifytimestamp"), (4, "creatorsname"), (4, "createtimestamp")])])])])


class LLCTestCase(unittest.TestCase):
	def test_llc(self):
		s = b"\xaa\xaa\x03\x00\x00\x00\x08\x00\x45\x00\x00\x28\x07\x27\x40\x00\x80\x06\x1d\x39\x8d\xd4\x37\x3d\x3f\xf5\xd1\x69\xc0\x5f\x01\xbb\xb2\xd6\xef\x23\x38\x2b\x4f\x08\x50\x10\x42\x04\xac\x17\x00\x00"

		llc_pkt = LLC(s)
		ip_pkt = ip.IP(llc_pkt.data)
		self.assertTrue(llc_pkt.type == ethernet.ETH_TYPE_IP)
		self.assertTrue(ip_pkt.dst == b"\x3f\xf5\xd1\x69")


class NetflowV1TestCase(unittest.TestCase):
	sample_v1 = "\x00\x01\x00\x18gza<B\x00\xfc\x1c$\x93\x08p\xac\x01 W\xc0\xa8c\xf7\n\x00\x02\x01\x00\x03\x00\n\x00\x00\x00\x01\x00\x00\x02(gz7,gz7,\\\x1b\x00P\xac\x01\x11,\x10\x00\x00\x00\x00\x04\x00\x1b\xac\x01\x18S\xac\x18\xd9\xaa\xc0\xa82\x02\x00\x03\x00\x19\x00\x00\x00\x01\x00\x00\x05\xdcgz7|gz7|\xd8\xe3\x00P\xac\x01\x06,\x10\x00\x00\x00\x00\x04\x00\x1b\xac\x01\x14\x18\xac\x18\x8d\xcd\xc0\xa82f\x00\x03\x00\x07\x00\x00\x00\x01\x00\x00\x05\xdcgz7\x90gz7\x90\x8a\x81\x17o\xac\x01\x066\x10\x00\x00\x00\x00\x04\x00\x03\xac\x0f'$\xac\x01\xe5\x1d\xc0\xa82\x06\x00\x04\x00\x1b\x00\x00\x00\x01\x00\x00\x02(gz:8gz:8\xa3Q\x126\xac)\x06\xfd\x18\x00\x00\x00\x00\x04\x00\x1b\xac\x01\x16E\xac#\x17\x8e\xc0\xa82\x06\x00\x03\x00\x1b\x00\x00\x00\x01\x00\x00\x02(gz:Lgz:L\xc9\xff\x00P\xac\x1f\x06\x86\x02\x00\x00\x00\x00\x03\x00\x1b\xac\r\t\xff\xac\x01\x99\x95\xc0\xa82\x06\x00\x04\x00\x1b\x00\x00\x00\x01\x00\x00\x05\xdcgz:Xgz:X\xee9\x00\x17\xac\x01\x06\xde\x10\x00\x00\x00\x00\x04\x00\x03\xac\x0eJ\xd8\xac\x01\xae/\xc0\xa82\x06\x00\x04\x00\x1b\x00\x00\x00\x01\x00\x00\x05\xdcgz:hgz:h\xb3n\x00\x15\xac\x01\x06\x81\x10\x00\x00\x00\x00\x04\x00\x1b\xac\x01#8\xac\x01\xd9*\xc0\xa82\x06\x00\x03\x00\x1b\x00\x00\x00\x01\x00\x00\x05\xdcgz:tgz:t\x00\x00\x83P\xac!\x01\xab\x10\x00\x00\x00\x00\x03\x00\x1b\xac\n`7\xac*\x93J\xc0\xa82\x06\x00\x04\x00\x1b\x00\x00\x00\x01\x00\x00\x05\xdcgz:tgz:t\x00\x00\x00\x00\xac\x012\xa9\x10\x00\x00\x00\x00\x04\x00\x07\xac\nG\x1f\xac\x01\xfdJ\xc0\xa82\x06\x00\x04\x00\x1b\x00\x00\x00\x01\x00\x00\x00(gz:\x88gz:\x88!\x99i\x87\xac\x1e\x06~\x02\x00\x00\x00\x00\x03\x00\x1b\xac\x01(\xc9\xac\x01B\xc4\xc0\xa82\x02\x00\x03\x00\x19\x00\x00\x00\x01\x00\x00\x00(gz:\x88gz:\x88}6\x00P\xac\x01\x06\xfe\x10\x00\x00\x00\x00\x04\x00\x1b\xac\x0b\x08\xe8\xac\x01F\xe2\xc0\xa82\x02\x00\x04\x00\x19\x00\x00\x00\x01\x00\x00\x05\xdcgz:\x9cgz:\x9c`ii\x87\xac\x01\x06;\x10\x00\x00\x00\x00\x04\x00\x1b\xac\x01\x1d$\xac<\xf0\xc3\xc0\xa82\x06\x00\x03\x00\x1b\x00\x00\x00\x01\x00\x00\x05\xdcgz:\x9cgz:\x9cF2\x00\x14\xac\x01\x06s\x18\x00\x00\x00\x00\x04\x00\x03\xac\x0b\x11Q\xac\x01\xde\x06\xc0\xa82\x06\x00\x04\x00\x1b\x00\x00\x00\x01\x00\x00\x05\xdcgz:\xb0gz:\xb0\xef#\x1a+\xac)\x06\xe9\x10\x00\x00\x00\x00\x04\x00\x1b\xac\x0cR\xd9\xac\x01o\xe8\xc0\xa82\x02\x00\x04\x00\x19\x00\x00\x00\x01\x00\x00\x05\xdcgz:\xc4gz:\xc4\x13n\x00n\xac\x19\x06\xa8\x10\x00\x00\x00\x00\x03\x00\x19\xac\x01=\xdd\xac\x01}\xee\xc0\xa82f\x00\x03\x00\x07\x00\x00\x00\x01\x00\x00\x00(gz:\xc4gz:\xc4\x00\x00\xdc\xbb\xac\x01\x01\xd3\x10\x00\x00\x00\x00\x04\x00\x1b\xac\x0f(\xd1\xac\x01\xcc\xa5\xc0\xa82\x06\x00\x04\x00\x1b\x00\x00\x00\x01\x00\x00\x05\xdcgz:\xd8gz:\xd8\xc5s\x17o\xac\x19\x06#\x18\x00\x00\x00\x00\x03\x00\x07\xac\n\x85[\xc0\xa8cn\n\x00\x02\x01\x00\x04\x00\n\x00\x00\x00\x01\x00\x00\x05\xdcgz:\xe4gz:\xe4\xbfl\x00P\xac\x01\x06\xcf\x10\x00\x00\x00\x00\x04\x00\x07\xac\x010\x1f\xac\x18!E\xc0\xa82f\x00\x03\x00\x07\x00\x00\x00\x01\x00\x00\x05\xdcgz;\x00gz;\x00\x11\x95\x04\xbe\xc0\xa8\x06\xea\x10\x00\x00\x00\x00\x03\x00\n\xac\x010\xb6\xac\x1e\xf4\xaa\xc0\xa82\x06\x00\x03\x00\x1b\x00\x00\x00\x01\x00\x00\x05\xdcgz;4gz;4\x88d\x00\x17\xac\x01\x06\x1f\x10\x00\x00\x00\x00\x04\x00\x1b\xac\x01#_\xac\x1e\xb0\t\xc0\xa82\x06\x00\x03\x00\x1b\x00\x00\x00\x01\x00\x00\x05\xdcgz;Hgz;H\x81S\x00P\xac \x06N\x10\x00\x00\x00\x00\x03\x00\x1b\xac\x01\x04\xd9\xac\x01\x94c\xc0\xa82\x06\x00\x03\x00\x1b\x00\x00\x00\x01\x00\x00\x02(gz;\\gz;\\U\x10\x00P\xac\x01\x06P\x18\x00\x00\x00\x00\x04\x00\x1b\xac\x01<\xae\xac*\xac!\xc0\xa82\x06\x00\x03\x00\x1b\x00\x00\x00\x01\x00\x00\x00\xfagz;\x84gz;\x84\x0c\xe7\x00P\xac\x01\x11\xfd\x10\x00\x00\x00\x00\x04\x00\x1b\xac\x01\x1f\x1f\xac\x17\xedi\xc0\xa82\x02\x00\x03\x00\x19\x00\x00\x00\x01\x00\x00\x05\xdcgz;\x98gz;\x98\xba\x17\x00\x16\xac\x01\x06|\x10\x00\x00\x00\x00\x03\x00\x07"

	def testPack(self):
		pass

	def testUnpack(self):
		nf = Netflow1(self.sample_v1)
		assert len(nf.data) == 24
		#print repr(nfv1)


class NetflowV5TestCase(unittest.TestCase):
	sample_v5 = b"\x00\x05\x00\x1d\xb5\xfa\xc9\xd0:\x0bAB&Vw\xde\x9bsv1\x00\x01\x00\x00\xac\n\x86\xa6\xac\x01\xaa\xf7\xc0\xa822\x02q\x00i\x00\x00\x00\x01\x00\x00\x02(\xb5\xfa\x81\x14\xb5\xfa\x81\x1452\x00P\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x01\x91D\xac\x14C\xe4\xc0\xa82\x16\x00i\x02q\x00\x00\x00\x01\x00\x00\x00(\xb5\xfa\x9b\xbd\xb5\xfa\x9b\xbd\x00P\x85\xd7\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x17\xe2\xd7\xac\x01\x8cV\xc0\xa822\x02q\x00i\x00\x00\x00\x01\x00\x00\x05\xdc\xb5\xfao\xb8\xb5\xfao\xb8v\xe8\x17o\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x0e\xf2\xe5\xac\x01\x91\xb2\xc0\xa822\x02q\x00i\x00\x00\x00\x01\x00\x00\x00\xfa\xb5\xfa\x81\xee\xb5\xfa\x81\xee\xd0\xeb\x00\x15\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\nCj\xac)\xa7\t\n\x00\x02\x01\x02q\x00\xdb\x00\x00\x00\x01\x00\x00\x02(\xb5\xfa\x85\x92\xb5\xfa\x85\x92\x8c\xb0\x005\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x01\x96=\xac\x15\x1a\xa8\xc0\xa82\x16\x00i\x02q\x00\x00\x00\x01\x00\x00\x05\xdc\xb5\xfa\x86\xe0\xb5\xfa\x86\xe0\xb4\xe7\x00\xc2\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x01V\xd1\xac\x01\x86\x15\xc0\xa822\x02q\x00i\x00\x00\x00\x01\x00\x00\x05\xdc\xb5\xfa}:\xb5\xfa}:[Q\x00P\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac2\xf1\xb1\xac)\x19\xca\n\x00\x02\x01\x02q\x00\xdb\x00\x00\x00\x01\x00\x00\x05\xdc\xb5\xfa\x83\xc3\xb5\xfa\x83\xc3\x16,\x00\x15\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x0cA4\xac\x01\x9az\xc0\xa822\x02q\x00i\x00\x00\x00\x01\x00\x00\x05\xdc\xb5\xfa\x8d\xa7\xb5\xfa\x8d\xa7\x173\x00\x15\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x1e\xd2\x84\xac)\xd8\xd2\n\x00\x02\x01\x02q\x00\xdb\x00\x00\x00\x01\x00\x00\x05\xdc\xb5\xfa\x8e\x97\xb5\xfa\x8e\x977*\x17o\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x01\x85J\xac \x11\xfc\xc0\xa82\x16\x00i\x02q\x00\x00\x00\x01\x00\x00\x02(\xb5\xfa\x884\xb5\xfa\x884\xf5\xdd\x00\x8f\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x01\x04\x80\xac<[n\n\x00\x02\x01\x02q\x00\xdb\x00\x00\x00\x01\x00\x00\x05\xdc\xb5\xfa\x9dr\xb5\xfa\x9drs$\x00\x16\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x01\xb9J\xac'\xc9\xd7\xc0\xa82\x16\x00i\x02q\x00\x00\x00\x01\x00\x00\x00(\xb5\xfa\x90r\xb5\xfa\x90r\x0f\x8d\x00\xc2\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac*\xa3\x10\xac\x01\xb4\x19\xc0\xa822\x02q\x00i\x00\x00\x00\x01\x00\x00\x00(\xb5\xfa\x92\x03\xb5\xfa\x92\x03pf\x00\x15\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x01\xabo\xac\x1e\x7fi\xc0\xa82\x16\x00i\x02q\x00\x00\x00\x01\x00\x00\x05\xdc\xb5\xfa\x93\x7f\xb5\xfa\x93\x7f\x00P\x0b\x98\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x0c\n\xea\xac\x01\xa1\x15\xc0\xa822\x02q\x00i\x00\x00\x00\x01\x00\x00\x05\xdc\xb5\xfay\xcf\xb5\xfay\xcf[3\x17\xe0\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x01\xbb\xb3\xac)u\x8c\n\x00\x02\x01\x00i\x00\xdb\x00\x00\x00\x01\x00\x00\x00\xfa\xb5\xfa\x943\xb5\xfa\x943\x00P\x1e\xca\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x0fJ`\xac\x01\xab\x94\xc0\xa822\x02q\x00i\x00\x00\x00\x01\x00\x00\x02(\xb5\xfa\x87[\xb5\xfa\x87[\x9a\xd6/\xab\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac*\x0f\x93\xac\x01\xb8\xa3\xc0\xa822\x02q\x00i\x00\x00\x00\x01\x00\x00\x00(\xb5\xfa\x89\xbb\xb5\xfa\x89\xbbn\xe1\x00P\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x01\x93\xa1\xac\x16\x80\x0c\xc0\xa82\x16\x00i\x02q\x00\x00\x00\x01\x00\x00\x00(\xb5\xfa\x87&\xb5\xfa\x87&\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x01\x83Z\xac\x1fR\xcd\xc0\xa82\x16\x00i\x02q\x00\x00\x00\x01\x00\x00\x05\xdc\xb5\xfa\x90\r\xb5\xfa\x90\r\xf7*\x00\x8a\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x0c\xe0\xad\xac\x01\xa8V\xc0\xa822\x02q\x00i\x00\x00\x00\x01\x00\x00\x05\xdc\xb5\xfa\x9c\xf6\xb5\xfa\x9c\xf6\xe5|\x1a+\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x1e\xccT\xac<x&\n\x00\x02\x01\x02q\x00\xdb\x00\x00\x00\x01\x00\x00\x05\xdc\xb5\xfa\x80\xea\xb5\xfa\x80\xea\x00\x00\x00\x00\x00\x00/\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x01\xbb\x18\xac\x01|z\xc0\xa82\x16\x00i\x02q\x00\x00\x00\x01\x00\x00\x00\xfa\xb5\xfa\x88p\xb5\xfa\x88p\x00P\x0b}\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x17\x0er\xac\x01\x8f\xdd\xc0\xa822\x02q\x00i\x00\x00\x00\x01\x00\x00\x02(\xb5\xfa\x89\xf7\xb5\xfa\x89\xf7\r\xf7\x00\x8a\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\n\xbb\x04\xac<\xb0\x15\n\x00\x02\x01\x02q\x00\xdb\x00\x00\x00\x01\x00\x00\x05\xdc\xb5\xfa\x90\xa9\xb5\xfa\x90\xa9\x9c\xd0\x00\x8f\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\nz?\xac)\x03\xc8\n\x00\x02\x01\x02q\x00\xdb\x00\x00\x00\x01\x00\x00\x05\xdc\xb5\xfaue\xb5\xfaue\xee\xa6\x00P\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x01\xb5\x05\xc0\xa8c\x9f\n\x00\x02\x01\x00i\x00\xdb\x00\x00\x00\x01\x00\x00\x05\xdc\xb5\xfa{\xc7\xb5\xfa{\xc7\x00P\x86\xa9\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac2\xa5\x1b\xac)0\xbf\n\x00\x02\x01\x02q\x00\xdb\x00\x00\x00\x01\x00\x00\x00\xfa\xb5\xfa\x9bZ\xb5\xfa\x9bZC\xf9\x17\xe0\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00"

	def testPack(self):
		pass

	def testUnpack(self):
		nf = Netflow5(self.sample_v5)
		assert len(nf.data) == 29
		#print repr(nfv5)



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
suite.addTests(loader.loadTestsFromTestCase(ICMPTestCase))
suite.addTests(loader.loadTestsFromTestCase(OSPFTestCase))
suite.addTests(loader.loadTestsFromTestCase(PPPTestCase))
suite.addTests(loader.loadTestsFromTestCase(STPTestCase))
suite.addTests(loader.loadTestsFromTestCase(VRRPTestCase))
suite.addTests(loader.loadTestsFromTestCase(AHTestCase))
suite.addTests(loader.loadTestsFromTestCase(IGMPTestCase))
suite.addTests(loader.loadTestsFromTestCase(IPXTestCase))
suite.addTests(loader.loadTestsFromTestCase(PIMTestCase))
suite.addTests(loader.loadTestsFromTestCase(HSRPTestCase))
suite.addTests(loader.loadTestsFromTestCase(NTPTestCase))
suite.addTests(loader.loadTestsFromTestCase(DHCPTestCase))
suite.addTests(loader.loadTestsFromTestCase(RIPTestCase))
suite.addTests(loader.loadTestsFromTestCase(SCTPTestCase))
suite.addTests(loader.loadTestsFromTestCase(ReaderTestCase))
suite.addTests(loader.loadTestsFromTestCase(ReaderNgTestCase))
suite.addTests(loader.loadTestsFromTestCase(RadiotapTestCase))
#suite.addTests(loader.loadTestsFromTestCase(IEEE80211TestCase))
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
suite.addTests(loader.loadTestsFromTestCase(PerfTestPpcapCase))
#suite.addTests(loader.loadTestsFromTestCase(SocketTestCase))
#suite.addTests(loader.loadTestsFromTestCase(ProducerConsumerTestCase))

unittest.TextTestRunner().run(suite)
