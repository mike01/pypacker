from pypacker import pypacker
import pypacker.ppcap as ppcap
from pypacker.layer12 import arp, dtp, ethernet, ieee80211, ospf, ppp, radiotap, stp, vrrp
from pypacker.layer3 import ah, ip, ip6, ipx, icmp, igmp, pim
from pypacker.layer4 import tcp, udp, sctp
from pypacker.layer567 import diameter, dhcp, dns, hsrp, http, ntp, rip, rtp, ssl, telnet, tftp

import unittest
import time
import sys

# Things to test on every protocol:
# - raw byte parsing
# - header changes
# - direction of packages
# - checksums
# - dynamic/optional headers
# General testcases:
# - Concatination via "+" (+parsing)
# - type finding via packet[type]
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
# 
# TBD:
# - CDP
# - LLC *

# - GRE
# - ICMP6

# - NetBios
# - SCCP

# - BGP *
# - Netflow *
# - PMAP
# - Radius
# - RFB
# - RPC
# - RX
# - SMB
# - STUN
# - TNS
# - TPKT
# - Yahoo

# - Snoop

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
#
## DHCP
# options=7: 53, 50, 57, 60, 12, 55, 255
BYTES_DHCP_REQ = b"\x01\x01\x06\x00\xf7\x24\x21\x68\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x12\x23\x03\x57\x25\x7c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x63\x82\x53\x63\x35\x01\x03\x32\x04\xc0\xa8\xb2\x15\x39\x02\x05\xdc\x3c\x31\x64\x68\x63\x70\x63\x64\x2d\x35\x2e\x36\x2e\x34\x3a\x4c\x69\x6e\x75\x78\x2d\x33\x2e\x35\x2e\x37\x2d\x67\x65\x6e\x74\x6f\x6f\x3a\x69\x36\x38\x36\x3a\x47\x65\x6e\x75\x69\x6e\x65\x49\x6e\x74\x65\x6c\x0c\x06\x6c\x6f\x72\x69\x6f\x74\x37\x0f\x01\x79\x21\x03\x06\x0c\x0f\x1a\x1c\x2a\x33\x36\x3a\x3b\x77\xff"
# options=12: 53, 54, 51, 58, 59, 1, 3, 6, 15, 28, 42, 255
BYTES_DHCP_RESP = b"\x02\x01\x06\x00\xf7\x24\x21\x68\x00\x00\x00\x00\x00\x00\x00\x00\xc0\xa8\xb2\x15\xc0\xa8\xb2\x01\x00\x00\x00\x00\x12\x23\x03\x57\x25\x7c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x63\x82\x53\x63\x35\x01\x05\x36\x04\xc0\xa8\xb2\x01\x33\x04\x00\x0d\x2f\x00\x3a\x04\x00\x06\x97\x80\x3b\x04\x00\x0b\x89\x20\x01\x04\xff\xff\xff\x00\x03\x04\xc0\xa8\xb2\x01\x06\x04\xc0\xa8\xb2\x01\x0f\x09\x66\x72\x69\x74\x7a\x2e\x62\x6f\x78\x1c\x04\xc0\xa8\xb2\xff\x2a\x04\xc0\xa8\xb2\x01\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
BYTES_UDP_DHCPREQ = b"\x00\x44\x00\x43" + BYTES_UDP[4:] + BYTES_DHCP_REQ
BYTES_UDP_DHCPRESP = b"\x00\x43\x00\x44" + BYTES_UDP[4:] + BYTES_DHCP_RESP
## ICMP
# type=8, checksum=0xEC66, id=2481
BYTES_ETH_IP_ICMPREQ	= b"\x52\x54\x00\x12\x35\x02\x08\x00\x27\xa9\x93\x9e\x08\x00\x45\x00\x00\x54\x00\x00\x40\x00\x40\x01\x54\xc1\x0a\x00\x02\x0f\xad\xc2\x2c\x17\x08\x00\xec" +\
			  b"\x66\x09\xb1\x00\x01\xd0\xd5\x18\x51\x28\xbd\x05\x00\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f" +\
			  b"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37"
## NTP, port=123 (0x7B)
BYTES_NTP = BYTES_UDP[:3] + b"\x7B" + BYTES_UDP[4:] + b"\x24\x02\x04\xef\x00\x00\x00\x84\x00\x00\x33\x27\xc1\x02\x04\x02\xc8\x90\xec\x11\x22\xae\x07\xe5\xc8\x90\xf9\xd9\xc0\x7e\x8c\xcd\xc8\x90\xf9\xd9\xda\xc5\xb0\x78\xc8\x90\xf9\xd9\xda\xc6\x8a\x93"
## RIP
BYTES_RIP = b"\x02\x02\x00\x00\x00\x02\x00\x00\x01\x02\x03\x00\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x02\x00\x00\xc0\xa8\x01\x08\xff\xff\xff\xfc\x00\x00\x00\x00\x00\x00\x00\x01"
## SCTP
BYTES_SCTP = b"\x80\x44\x00\x50\x00\x00\x00\x00\x30\xba\xef\x54\x01\x00\x00\x3c\x3b\xb9\x9c\x46\x00\x01\xa0\x00\x00\x0a\xff\xff\x2b\x2d\x7e\xb2\x00\x05\x00\x08\x9b\xe6\x18\x9b\x00\x05\x00\x08\x9b\xe6\x18\x9c\x00\x0c\x00\x06\x00\x05\x00\x00\x80\x00\x00\x04\xc0\x00\x00\x04\xc0\x06\x00\x08\x00\x00\x00\x00"


class CreateTestCase(unittest.TestCase):
	def test_create_eth(self):
		print(">>>>>>>>> CREATE TEST <<<<<<<<<")
		eth = ethernet.Ethernet()
		#print(str(eth))
		self.failUnless(eth.bin() == b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x08\x00")
		eth = ethernet.Ethernet(dst=b"\x00\x01\x02\x03\x04\x05", src=b"\x06\x07\x08\x09\x0A\x0B", type=2048)
		print(str(eth))
		print(eth.bin())
		self.failUnless(eth.bin() == b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x08\x00")
		

class EthTestCase(unittest.TestCase):
	def test_eth(self):
		print(">>>>>>>>> ETHERNET <<<<<<<<<")
		# Ethernet without body
		s = b"\x52\x54\x00\x12\x35\x02\x08\x00\x27\xa9\x93\x9e\x08\x00"
		eth1 = ethernet.Ethernet(s)
		# parsing
		self.failUnless(eth1.bin() == s)
		self.failUnless(eth1.dst_s == "52:54:00:12:35:02")
		self.failUnless(eth1.src_s == "08:00:27:a9:93:9e")
		# header field update
		mac1 = "aa:bb:cc:dd:ee:00"
		mac2 = "aa:bb:cc:dd:ee:01"
		eth1.dst_s = mac2
		eth1.src_s = mac1
		self.failUnless(eth1.dst_s == mac2)
		self.failUnless(eth1.src_s == mac1)
		# TODO: removed option "fieldvalue = None"
		#oldlen = len(eth1)
		#eth1.dst = None
		#self.failUnless(eth1.dst == None)
		# removed 6-byte ethernet address
		#self.failUnless(oldlen == len(eth1) + 6)
		# Ethernet + IP
		s= b"\x52\x54\x00\x12\x35\x02\x08\x00\x27\xa9\x93\x9e\x08\x00\x45\x00\x00\x37\xc5\x78\x40\x00\x40\x11\x9c\x81\x0a\x00\x02\x0f\x0a\x20\xc2\x8d"
		eth2 = ethernet.Ethernet(s)
		# parsing
		self.failUnless(eth2.bin() == s)
		self.failUnless(type(eth2.ip).__name__ == "IP")
		print("Ethernet with IP: %s -> %s" % (eth2.ip.src, eth2.ip.dst))
		# reconstruate macs
		eth1.src = b"\x52\x54\x00\x12\x35\x02"
		eth1.dst = b"\x08\x00\x27\xa9\x93\x9e"
		# direction
		print("direction of eth: %d" % eth1.direction(eth1))
		self.failUnless(eth1.direction(eth1) == pypacker.Packet.DIR_SAME)
		

class IPTestCase(unittest.TestCase):
	def test_IP(self):
		print(">>>>>>>>> IP <<<<<<<<<")
		packet_bytes = []
		f = open("tests/packets_dns.pcap", "rb")
		pcap = ppcap.Reader(f)

		for ts, buf in pcap:
			packet_bytes.append(buf)
			break

		# IP without body
		ip1_bytes = packet_bytes[0][14:34]
		ip1 = ip.IP(ip1_bytes)
		self.failUnless(ip1.bin() == ip1_bytes)
		self.failUnless(ip1.src_s == "192.168.178.22")
		self.failUnless(ip1.dst_s == "192.168.178.1")
		print("src: %s" % ip1.src_s)			
		# header field udpate
		src = "1.2.3.4"
		dst = "4.3.2.1"
		print(ip1)
		ip1.src_s = src
		ip1.dst_s = dst
		self.failUnless(ip1.src_s == src)
		self.failUnless(ip1.dst_s == dst)		
		self.failUnless(ip1.direction(ip1) == pypacker.Packet.DIR_SAME)

		print(">>> checksum")
		ip2 = ip.IP(ip1_bytes)
		print("IP sum 1: %s" % ip2.sum)
		self.failUnless(ip2.sum == 0x8e60)
		ip2.p = 6
		print("IP sum 2: %s" % ip2.sum)
		self.failUnless(ip2.sum == 36459)
		ip2.p = 17
		print("IP sum 3: %s" % ip2.sum)
		self.failUnless(ip2.sum == 0x8e60)

		# IP + options
		ip3_bytes = b"\x49"  + ip1_bytes[1:] + b"\x03\04\x00\x07" + b"\x09\03\x07" + b"\x01"
		ip3 = ip.IP(ip3_bytes)

		print("opts 1")

		for o in ip3.opts:
			print(o)

		self.failUnless(ip3.bin() == ip3_bytes)
		del ip3.opts[2]
		self.failUnless(len(ip3.opts) == 2)
		self.failUnless(ip3.opts[0].type == 3)
		self.failUnless(ip3.opts[0].len == 4)
		self.failUnless(ip3.opts[0].data == b"\x00\x07")

		print("opts 2")
		for o in ip3.opts:
			print(o)

		ip3.opts.append((ip.IP_OPT_TS, b"\x00\x01\x02\x03"))
		self.failUnless(len(ip3.opts) == 3)
		self.failUnless(ip3.opts[2].type == ip.IP_OPT_TS)
		self.failUnless(ip3.opts[2].data == b"\x00\x01\x02\x03")

		print("opts 3")
		ip3.opts.append((ip.IP_OPT_TS, b"\x00"))

		for o in ip3.opts:
			print(o)

		print("header offset: %d" % ip3.hl)
		self.failUnless(ip3.hl == 9)


class TCPTestCase(unittest.TestCase):
	def test_TCP(self):
		print(">>>>>>>>> TCP <<<<<<<<<")
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
		self.failUnless(tcp1.bin() == tcp1_bytes)
		self.failUnless(tcp1.sport == 37202)
		self.failUnless(tcp1.dport == 443)
		# direction
		tcp2 = tcp.TCP(tcp1_bytes)
		tcp1.sport = 443
		tcp1.dport = 37202
		print("dir: %d" % tcp1.direction(tcp2))
		self.failUnless(tcp1.direction(tcp2) == pypacker.Packet.DIR_REV)
		# checksum (no IP-layer means no checksum change)
		tcp1.win = 1234
		self.failUnless(tcp1.sum == 0x9c2d)
		# checksum (IP + TCP)
		ip_tcp_bytes = packet_bytes[0][14:]
		ip1 = ip.IP(ip_tcp_bytes)
		tcp2 = ip1[tcp.TCP]
		self.failUnless(ip1.bin() == ip_tcp_bytes)

		print("sum 1: %X" % tcp2.sum)
		self.failUnless(tcp2.sum == 0x9c2d)

		tcp2.win = 0x0073
		print("sum 2: %X" % tcp2.sum)
		self.failUnless(tcp2.sum == 0xea57)

		tcp2.win = 1234
		print("sum 3: %X" % tcp2.sum)
		self.failUnless(tcp2.sum == 0xe5f8)

		tcp2.win = 0x0073
		print("sum 4: %X" % tcp2.sum)
		self.failUnless(tcp2.sum == 0xea57)

		# options
		print("tcp options: %d" % len(tcp2.opts))
		self.failUnless(len(tcp2.opts) == 3)
		self.failUnless(tcp2.opts[2].type == tcp.TCP_OPT_TIMESTAMP)
		self.failUnless(tcp2.opts[2].len == 10)
		print(tcp2.opts[2].data)
		self.failUnless(tcp2.opts[2].data == b"\x01\x0b\x5d\xb3\x21\x3d\xc7\xd9")

		tcp2.opts.append((tcp.TCP_OPT_WSCALE, b"\x00\x01\x02\x03\x04\x05"))	# header length 20 + (12 + 8 options)
		for opt in tcp2.opts:
			print(opt)
		self.failUnless(len(tcp2.opts) == 4)
		self.failUnless(tcp2.opts[3].type == tcp.TCP_OPT_WSCALE)
		print("offset is: %s" % tcp2.off)
		self.failUnless(tcp2.off == 10)


class UDPTestCase(unittest.TestCase):
	def test_UDP(self):
		print(">>>>>>>>> UDP <<<<<<<<<")
		packet_bytes = []
		f = open("tests/packets_dns.pcap", "rb")
		pcap = ppcap.Reader(f)

		for ts, buf in pcap:
			packet_bytes.append(buf)
			break

		ip_udp_bytes = packet_bytes[0][14:]
		ip1 = ip.IP(ip_udp_bytes)
		self.failUnless(ip1.bin() == ip_udp_bytes)

		# UDP + DNS
		udp1 = ip1[udp.UDP]
		# parsing
		self.failUnless(udp1.sport == 42432)
		self.failUnless(udp1.dport == 53)
		# direction
		udp2 = ip.IP(ip_udp_bytes)[udp.UDP]
		self.failUnless(udp1.direction(udp2) == pypacker.Packet.DIR_SAME)
		# checksum
		self.failUnless(udp1.sum == 0xf6eb)

		#print("setting new port")
		udp1.dport = 1234
		print("sum 1: %X" % udp1.sum)
		self.failUnless(udp1.sum == 0xf24e)

		udp1.dport = 53
		print("sum 2: %X" % udp1.sum)
		self.failUnless(udp1.sum == 0xf6eb)


class HTTPTestCase(unittest.TestCase):
	def test_HTTP(self):
		print(">>>>>>>>> HTTP <<<<<<<<<")
		# HTTP header + body
		s1 = b"GET / HTTP/1.1\r\nHeader1: value1\r\nHeader2: value2\r\n\r\nThis is the body content\r\n"
		http1 = http.HTTP(s1)
		self.failUnless(http1.bin() == s1)
		# header changes
		s2 = b"POST / HTTP/1.1\r\nHeader1: value1\r\nHeader2: value2\r\n\r\nThis is the body content\r\n"
		print(">>> new startline POST")
		http1.header[0] = (b"POST / HTTP/1.1",)
		print("http bin: %s" % http1.bin())
		self.failUnless(http1.bin() == s2)
		self.failUnless(http1.header[b"hEaDeR1"][1] == b"value1")
		print(">>> new startline GET")
		http1.header[0] = (b"GET / HTTP/1.1",)
		self.failUnless(http1.bin() == s1)
		s3 = b"GET / HTTP/1.1\r\nHeader1: value1\r\nHeader2: value2\r\n\r\n"
		print(">>> resetting body")
		http1.data = b""
		self.failUnless(http1.bin() == s3)
		# TODO: set ether + ip + tcp + http
		#print("HTTP headers: %s" % http1.headers)


class AccessConcatTestCase(unittest.TestCase):
	def test_concat(self):
		print(">>>>>>>>> CONCAT <<<<<<<<<")
		packet_bytes = []
		f = open("tests/packets_telnet.pcap", "rb")
		pcap = ppcap.Reader(f)

		for ts, buf in pcap:
			packet_bytes.append(buf)

		# TCP without body
		bytes_eth_ip_tcp_tn =  packet_bytes[0]
		l_eth = bytes_eth_ip_tcp_tn[:14]
		l_ip = bytes_eth_ip_tcp_tn[14:34]
		l_tcp = bytes_eth_ip_tcp_tn[34:66]
		l_tn = bytes_eth_ip_tcp_tn[66:]

		p_all = ethernet.Ethernet(bytes_eth_ip_tcp_tn)
		self.failUnless(p_all.bin() == bytes_eth_ip_tcp_tn)

		eth1 = ethernet.Ethernet(l_eth)
		ip1 = ip.IP(l_ip)
		tcp1 = tcp.TCP(l_tcp)
		tn1 = telnet.Telnet(l_tn)

		self.failUnless(type(p_all[ethernet.Ethernet]) == type(eth1))
		self.failUnless(type(p_all[ip.IP]) == type(ip1))
		self.failUnless(type(p_all[tcp.TCP]) == type(tcp1))
		self.failUnless(type(p_all[telnet.Telnet]) == type(tn1))

		bytes_concat = [eth1.bin(), ip1.bin(), tcp1.bin(), tn1.bin()]
		self.failUnless(p_all.bin() == b"".join(bytes_concat))

		p_all_concat = eth1 + ip1 + tcp1 + tn1
		self.failUnless(p_all.bin() == p_all_concat.bin())


class ICMPTestCase(unittest.TestCase):
	def test_concat(self):
		print(">>>>>>>>> ICMP <<<<<<<<<")
		global BYTES_ETH_IP_ICMPREQ
		req = BYTES_ETH_IP_ICMPREQ

		eth = ethernet.Ethernet(req)
		print(eth)
		print(eth[ip.IP])
		self.failUnless(eth.bin() == req)
		icmp1 = eth[icmp.ICMP]
		print(str(icmp1))
		self.failUnless(icmp1.type == 8)
		# type=8, checksum=0xEC66, id=2481
		print("sum 1: %d" % icmp1.sum)		# 0xEC66 = 22213
		self.failUnless(icmp1.sum == 60518)
		self.failUnless(icmp1.seq == 1)
		print("data: %s -> %s" % (type(icmp1), icmp1.data))
		self.failUnless(icmp1.data == BYTES_ETH_IP_ICMPREQ[50:])
		icmp1.seq = 2
		print("sum 2: %d" % icmp1.sum)
		self.failUnless(icmp1.sum == 60517)
		icmp1.seq = 1
		print("sum 3: %d" % icmp1.sum)
		self.failUnless(icmp1.sum == 60518)


class OSPFTestCase(unittest.TestCase):
	def test(self):
		print(">>>>>>>>> OSPF <<<<<<<<<")
		s = b"ABCCDDDDEEEEFFFFGGGGGGGG"
		ospf1 = ospf.OSPF(s)
		self.failUnless(ospf1.bin() == s)


class PPPTestCase(unittest.TestCase):
	def test_ppp(self):
		print(">>>>>>>>> PPP <<<<<<<<<")
		s = b"\x21" + BYTES_IP
		ppp1 = ppp.PPP(s)
		self.failUnless(ppp1.bin() == s)
		self.failUnless(type(ppp1[ip.IP]).__name__ == "IP")


class STPTestCase(unittest.TestCase):
	def test_stp(self):
		print(">>>>>>>>> STP <<<<<<<<<")
		s = b"AABCDEEEEEEEEFFFFGGGGGGGGHHIIJJKKLL"
		stp1 = stp.STP(s)
		self.failUnless(stp1.bin() == s)


class VRRPTestCase(unittest.TestCase):
	def test_vrrp(self):
		print(">>>>>>>>> VRRP <<<<<<<<<")
		s = b"ABCDEFGG"
		vrrp1 = vrrp.VRRP(s)
		self.failUnless(vrrp1.bin() == s)


class AHTestCase(unittest.TestCase):
	def test_ah(self):
		print(">>>>>>>>> AH <<<<<<<<<")
		s = b"\x06\x0c\x00\x00\x11\x11\x11\x11\x22\x22\x22\x22" + BYTES_TCP
		ah1 = ah.AH(s)
		self.failUnless(ah1.bin() == s)


class IGMPTestCase(unittest.TestCase):
	def test_igmp(self):
		print(">>>>>>>>> IGMP <<<<<<<<<")
		s = b"ABCCDDDD"
		igmp1 = igmp.IGMP(s)
		self.failUnless(igmp1.bin() == s)


class IPXTestCase(unittest.TestCase):
	def test_ipx(self):
		print(">>>>>>>>> IPX <<<<<<<<<")
		s = b"AABBCDEEEEEEEEEEEEFFFFFFFFFFFF"
		ipx1 = ipx.IPX(s)
		self.failUnless(ipx1.bin() == s)


class PIMTestCase(unittest.TestCase):
	def test_ipx(self):
		print(">>>>>>>>> PIM <<<<<<<<<")
		s = b"ABCC"
		pim1 = pim.PIM(s)
		self.failUnless(pim1.bin() == s)


class HSRPTestCase(unittest.TestCase):
	def test_hsrp(self):
		print(">>>>>>>>> HSRP <<<<<<<<<")
		s = b"ABCDEFGHIIIIIIIIJJJJ"
		hsrp1 = hsrp.HSRP(s)
		self.failUnless(hsrp1.bin() == s)


class DHCPTestCase(unittest.TestCase):
	def test_dhcp(self):
		print(">>>>>>>>> DHCP <<<<<<<<<")
		s = BYTES_UDP_DHCPREQ
		dhcp1 = udp.UDP(s)
		self.failUnless(s == dhcp1.bin())
		print("DHCP type: %s" % type(dhcp1[dhcp.DHCP]).__name__)
		self.failUnless(type(dhcp1[dhcp.DHCP]).__name__ == "DHCP")
		dhcp2 = dhcp1[dhcp.DHCP]
		self.failUnless(len(dhcp2.opts) == 7)
		self.failUnless(dhcp2.opts[0].type == 53)
		self.failUnless(dhcp2.opts[6].type == 255)

		s = BYTES_UDP_DHCPRESP
		dhcp1 = udp.UDP(s)
		self.failUnless(s == dhcp1.bin())
		self.failUnless(type(dhcp1[dhcp.DHCP]).__name__ == "DHCP")
		dhcp2 = dhcp1[dhcp.DHCP]
		self.failUnless(len(dhcp2.opts) == 12)
		self.failUnless(dhcp2.opts[0].type == 53)
		self.failUnless(dhcp2.opts[11].type == 255)
		# TODO: use "append/extend"
		#dhcp2.opts += [(dhcp.DHCP_OPT_TCPTTL, b"\x00\x01\x02")]
		dhcp2.opts.append((dhcp.DHCP_OPT_TCPTTL, b"\x00\x01\x02"))
		print("new TLlen: %d" % len(dhcp2.opts))
		self.failUnless(len(dhcp2.opts) == 13)


class DNSTestCase(unittest.TestCase):
	def test_dns(self):
		print(">>>>>>>>> DNS <<<<<<<<<")
		packet_bytes = []
		f = open("tests/packets_dns.pcap", "rb")
		pcap = ppcap.Reader(f)

		for ts, buf in pcap:
			packet_bytes.append(buf)

		dns1 = ethernet.Ethernet(packet_bytes[0])[dns.DNS]
		print(dns1.bin())
		print(packet_bytes[0][42:])
		self.failUnless(dns1.bin() == packet_bytes[0][42:])
		self.failUnless(len(dns1.queries) == 1)
		self.failUnless(len(dns1.answers) == 0)
		self.failUnless(len(dns1.auths) == 0)
		self.failUnless(len(dns1.addrequests) == 1)

		dns2 = ethernet.Ethernet(packet_bytes[1])[dns.DNS]
		self.failUnless(dns2.bin() == packet_bytes[1][42:])
		print("%s" % dns2)
		self.failUnless(len(dns2.queries) == 1)
		self.failUnless(len(dns2.answers) == 3)
		self.failUnless(len(dns2.auths) == 0)
		self.failUnless(len(dns2.addrequests) == 1)

		dns3 = ethernet.Ethernet(packet_bytes[2])[dns.DNS]
		self.failUnless(dns3.bin() == packet_bytes[2][42:])
		print("%s" % dns3)
		self.failUnless(len(dns3.queries) == 1)
		self.failUnless(len(dns3.answers) == 0)
		self.failUnless(len(dns3.auths) == 1)
		self.failUnless(len(dns3.addrequests) == 0)


class NTPTestCase(unittest.TestCase):
	def test_ntp(self):
		print(">>>>>>>>> NTP <<<<<<<<<")
		global BYTES_NTP
		s = BYTES_NTP
		n = udp.UDP(s)
		self.failUnless(s == n.bin())
		n = n[ntp.NTP]
		print("NTP flags 1")
		print(n)
		self.failUnless(n.li == ntp.NO_WARNING)
		self.failUnless(n.v == 4)
		self.failUnless(n.mode == ntp.SERVER)
		self.failUnless(n.stratum == 2)
		self.failUnless(n.id == b"\xc1\x02\x04\x02")

		# test get/set functions
		print("NTP flags 2")
		n.li = ntp.ALARM_CONDITION
		n.v = 3
		n.mode = ntp.CLIENT
		self.failUnless(n.li == ntp.ALARM_CONDITION)
		self.failUnless(n.v == 3)
		self.failUnless(n.mode == ntp.CLIENT)


class RIPTestCase(unittest.TestCase):
	def test_rip(self):
		global BYTES_RIP
		s = BYTES_RIP
		print(">>>>>>>>> RIP <<<<<<<<<")
		r = rip.RIP(s)
		self.failUnless(s == r.bin())
		print("amount auth/rte: %d" % len(r.rte_auth))
		self.failUnless(len(r.rte_auth) == 2)

		rte = r.rte_auth[1]
		self.failUnless(rte.family == 2)
		self.failUnless(rte.route_tag == 0)
		self.failUnless(rte.metric == 1)


class SCTPTestCase(unittest.TestCase):
	def test_sctp(self):
		print(">>>>>>>>> SCTP <<<<<<<<<")
		packet_bytes = []
		f = open("tests/packets_sctp.pcap", "rb")
		pcap = ppcap.Reader(f)

		for ts, buf in pcap:
			packet_bytes.append(buf)

		# parsing
		sct1_bytes = packet_bytes[0]
		eth_ip_sct = ethernet.Ethernet(sct1_bytes)
		sct = eth_ip_sct[sctp.SCTP]
		print("sctp 1: %s" % sct.bin())
		self.failUnless(eth_ip_sct.bin() == sct1_bytes)
		# checksum (CRC32)
		#print("sctp sum1: %X" % sct.sum)
		#self.failUnless(sct.sum == 0x6db01882)

		#print(sct)
		#sct.vtag = sct.vtag
		#print("sctp sum3: %X" % sct.sum)
		#print(sct)
		#self.failUnless(sct.sum == 0x6db01882)

		self.failUnless(sct.sport == 16384)
		self.failUnless(sct.dport == 2944)
		self.failUnless(len(sct.chunks) == 1)

		chunk = sct.chunks[0]
		self.failUnless(chunk.type == sctp.DATA)
		self.failUnless(chunk.len == 91)
		# dynamic fields
		sct.chunks.append((sctp.DATA, 0xff, b"\x00\x01\x02"))
		self.failUnless(len(sct.chunks) == 2)
		self.failUnless(sct.chunks[1].data == b"\x00\x01\x02")
		# lazy init of chunks
		sct2 = sctp.SCTP()
		sct2.chunks.append((sctp.DATA, 0xff, b"\x00\x01\x02"))
		self.failUnless(len(sct2.chunks) == 1)


class ReaderTestCase(unittest.TestCase):
	def test_reader(self):
		print(">>>>>>>>> READER <<<<<<<<<")
		import os
		print(os.getcwd())
		f = open("tests/packets_ether.pcap", "rb")
		pcap = ppcap.Reader(f)

		cnt = 0
		proto_cnt = { arp.ARP:4,
				tcp.TCP:34,
				udp.UDP:4,
				icmp.ICMP:7,
				http.HTTP:12
				}
		for ts, buf in pcap:
			cnt += 1
			#print("%02d TS: %s LEN: %d" % (cnt, ts, len(buf)))
			eth = ethernet.Ethernet(buf)
			keys = proto_cnt.keys()

			for k in keys:
				if eth[k] is not None:
					proto_cnt[k] -= 1
					#if k == HTTP:
					#	print("found HTTP at: %d" % cnt)
					#break

			#try:
			## skip packets out of stream
			#	if not ether_old.direction(ether):
			#	continue
			#except:
			#continue
			#ether_old = ether
			#print("%s:%s -> %s:%s", (ether[IP].src, ether[TCP].src, ether[IP].dst, ether[IP].dst))

			#if http.method == "GET":
			#	print("got GET-request for: %s", % http.uri)

		self.failUnless(cnt == 49)

		print("proto summary:")
		for k,v in proto_cnt.items():
			print("%s: %s" % (k.__name__, v))
			self.failUnless(v == 0)


class RadiotapTestCase(unittest.TestCase):
	def test_radiotap(self):
		print(">>>>>>>>> Radiotap <<<<<<<<<")
		# radiotap: flags, rate channel, dBm Antenna, Antenna, RX Flags
		s = b"\x00\x00\x12\x00\x2e\x48\x00\x00\x00\x02\x6c\x09\xa0\x00\xc2\x07\x00\x00"
		rad = radiotap.Radiotap(s)
		self.failUnless(rad.bin() == s)

		self.failUnless(rad.version == 0)
		print("len: %d" % rad.len)
		self.failUnless(rad.len == 4608)	# 0x1200 = 18
		self.failUnless(rad.present_flags == 0x2e480000)
		print("channel: %X" % rad.channel)
		self.failUnless(rad.channel == 0x6c09)
		self.failUnless(rad.channel_flags == 0xa000)
		print("flags: %x" % rad.present_flags)
		print("flags mask: %x" % radiotap.FLAGS_MASK)
		print("flags & flags mask: %x" % (rad.present_flags & radiotap.FLAGS_MASK))

		self.failUnless(rad.present_flags & radiotap.TSFT_MASK == 0)
		self.failUnless(rad.present_flags & radiotap.FLAGS_MASK != 0)
		self.failUnless(rad.present_flags & radiotap.RATE_MASK != 0)
		#self.failUnless(len(rad.fields) == 7)


class PerfTestCase(unittest.TestCase):
	def test_perf(self):
		# IP + ICMP
		s = b"E\x00\x00T\xc2\xf3\x00\x00\xff\x01\xe2\x18\n\x00\x01\x92\n\x00\x01\x0b\x08\x00\xfc\x11:g\x00\x00A,\xc66\x00\x0e\xcf\x12\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f!"#$%&\'()*+,-./01234567"
		cnt = 10000
		print(">>>>>>>>> Performance Tests <<<<<<<<<")
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
		print("or = 13150 pps")

		print(">>> creating/direct assigning (IP + data)")
		start = time.time()
		for i in range(cnt):
			#ip = IP(src="1.2.3.4", dst="1.2.3.5").bin()
			ip.IP(src=b"\x01\x02\x03\x04", dst=b"\x05\x06\x07\x08", p=17, len=1234, data=b"abcd")
			#ip = IP(src=b"\x01\x02\x03\x04", dst=b"\x05\x06\x07\x08", p=17, len=1234, data=b"abcd")
		print("time diff: %ss" % (time.time() - start))
		print("nr = %d pps" % (cnt / (time.time() - start)) )
		print("or = 71326 pps")

		print(">>> output without change (IP)")
		ip2 = ip.IP(src=b"\x01\x02\x03\x04", dst=b"\x05\x06\x07\x08", p=17, len=1234, data=b"abcd")
		start = time.time()
		for i in range(cnt):
			ip2.bin()
		print("time diff: %ss" % (time.time() - start))
		print("nr = %d pps" % (cnt / (time.time() - start)) )
		print("or = 345161 pps")

		print(">>> output with change/checksum recalculation (IP)")
		ip3 = ip.IP(src=b"\x01\x02\x03\x04", dst=b"\x05\x06\x07\x08", p=17, len=1234, data=b"abcd")
		start = time.time()
		for i in range(cnt):
			ip3.sum = 0
			ip3.bin()
		print("time diff: %ss" % (time.time() - start))
		print("nr = %d pps" % (cnt / (time.time() - start)) )
		print("or = 30974 pps")

		print(">>> parsing (Ethernet + IP + TCP + HTTP)")
		global BYTES_ETH_IP_TCP_HTTP
		start = time.time()
		for i in range(cnt):
			eth = ethernet.Ethernet(BYTES_ETH_IP_TCP_HTTP)
		print("time diff: %ss" % (time.time() - start))
		print("nr = %d pps" % (cnt / (time.time() - start)) )
		print("or = 4361 pps")

		print(">>> changing Triggerlist/binary proto (Ethernet + IP + TCP + HTTP)")
		start = time.time()
		eth1 = ethernet.Ethernet(BYTES_ETH_IP_TCP_HTTP)
		tcp1 = eth1[tcp.TCP]
		for i in range(cnt):
			tcp1.opts[0].type = tcp.TCP_OPT_WSCALE
		print("time diff: %ss" % (time.time() - start))
		print("nr = %d pps" % (cnt / (time.time() - start)) )
		print("or = 89524 pps")

		print(">>> changing Triggerlist/text based proto (Ethernet + IP + TCP + HTTP)")
		start = time.time()
		eth1 = ethernet.Ethernet(BYTES_ETH_IP_TCP_HTTP)
		http1 = eth1[http.HTTP]
		for i in range(cnt):
			http1.header[0] = (b"GET / HTTP/1.1",)
		print("time diff: %ss" % (time.time() - start))
		print("nr = %d pps" % (cnt / (time.time() - start)) )
		print("or = 48371 pps")

		print(">>> concatination (Ethernet + IP + TCP + HTTP)")
		start = time.time()
		for i in range(cnt):
			concat = ethernet.Ethernet(dst_s="ff:ff:ff:ff:ff:ff", src_s="ff:ff:ff:ff:ff:ff") +\
				ip.IP(src_s="127.0.0.1", dst_s="192.168.0.1") +\
				tcp.TCP(sport=1234, dport=123) +\
				http.HTTP()
		#print("=======================")
		#print(concat)
		print("time diff: %ss" % (time.time() - start))
		print("nr = %d pps" % (cnt / (time.time() - start)) )
		print("or = 11083 pps")


class TriggerListHTTPTestCase(unittest.TestCase):
	def test_triggerlist(self):
		print(">>>>>>>>> Triggerlist (via HTTP) <<<<<<<<<")
		hdr = b"GET / HTTP/1.1\r\nkey1: value1\r\nkey2: value2\r\n\r\n"
		tl = http.HTTPTriggerList(hdr)
		self.failUnless(len(tl) == 3)
		#tl += [("key3", "value3")]
		tl.append(("key3", "value3"))
		self.failUnless(tl[3][0] == "key3")
		self.failUnless(tl[3][1] == "value3")


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
		self.failUnless(ieee.bin() == self.packet_bytes[2][rlen:])
		self.failUnless(ieee.version == 0)
		self.failUnless(ieee.type == ieee80211.CTL_TYPE)
		self.failUnless(ieee.subtype == ieee80211.C_ACK)
		self.failUnless(ieee.to_ds == 0)
		self.failUnless(ieee.from_ds == 0)
		self.failUnless(ieee.pwr_mgt == 0)
		self.failUnless(ieee.more_data == 0)
		self.failUnless(ieee.wep == 0)
		self.failUnless(ieee.order == 0)
		self.failUnless(ieee.ack.dst == b"\x00\xa0\x0b\x21\x37\x84")

	def test_beacon(self):
		print(">>>>>>>>> Beacon <<<<<<<<<")
		rlen = self.packet_bytes[0][2]
		ieee = ieee80211.IEEE80211(self.packet_bytes[0][rlen:])
		self.failUnless(ieee.bin() == self.packet_bytes[0][rlen:])
		self.failUnless(ieee.version == 0)
		self.failUnless(ieee.type == ieee80211.MGMT_TYPE)
		self.failUnless(ieee.subtype == ieee80211.M_BEACON)
		self.failUnless(ieee.to_ds == 0)
		self.failUnless(ieee.from_ds == 0)
		self.failUnless(ieee.pwr_mgt == 0)
		self.failUnless(ieee.more_data == 0)
		self.failUnless(ieee.wep == 0)
		self.failUnless(ieee.order == 0)
		self.failUnless(ieee.mgmtframe.dst == b"\xff\xff\xff\xff\xff\xff")
		self.failUnless(ieee.mgmtframe.src == b"\x24\x65\x11\x85\xe9\xae")
		self.failUnless(ieee.mgmtframe.beacon.capability == 0x3104)
		# TODO: test IEs
		#self.failUnless(ieee.capability.privacy == 1)
		#self.failUnless(ieee.mgmtframe.beacon.data == "CAEN")
		#self.failUnless(ieee.rate.data == b"\x82\x84\x8b\x0c\x12\x96\x18\x24")
		#self.failUnless(ieee.ds.data == b"\x01")
		#self.failUnless(ieee.tim.data == b"\x00\x01\x00\x00")

	def test_data(self):
		print(">>>>>>>>> Data <<<<<<<<<")
		rlen = self.packet_bytes[5][2]
		ieee = ieee80211.IEEE80211(self.packet_bytes[5][rlen:])
		self.failUnless(ieee.bin() == self.packet_bytes[5][rlen:])
		self.failUnless(ieee.type == ieee80211.DATA_TYPE)
		self.failUnless(ieee.subtype == ieee80211.D_DATA)
		print("type is: %s" % type(ieee.data))
		self.failUnless(ieee.datafromds.dst == b"\x01\x00\x5e\x7f\xff\xfa")
		self.failUnless(ieee.datafromds.src == b"\x00\x1e\xe5\xe0\x8c\x06")
		self.failUnless(ieee.datafromds.frag_seq == 0x501e)
		self.failUnless(ieee.datafromds.data == b"\x62\x22\x39\x61\x98\xd1\xff\x34\x65\xab\xc1\x3c\x8e\xcb\xec\xef\xef\xf6\x25\xab\xe5\x89\x86\xdf\x74\x19\xb0\xa4\x86\xc2\xdb\x38\x20\x59\x08\x1f\x04\x1b\x96\x6b\x01\xd7\x6a\x85\x73\xf5\x4a\xf1\xa1\x2f\xf3\xfb\x49\xb7\x6b\x6a\x38\xef\xa8\x39\x33\xa1\xc8\x29\xc7\x0a\x88\x39\x7c\x31\xbf\x55\x96\x24\xd5\xe1\xbf\x62\x85\x2c\xe3\xdf\xb6\x80\x3e\x92\x1c\xbf\x13\xcd\x47\x00\x8e\x9f\xc6\xa7\x81\x91\x71\x9c\x0c\xad\x08\xe2\xe8\x5f\xac\xd3\x1c\x90\x16\x15\xa0\x71\x30\xee\xac\xdd\xe5\x8d\x1f\x5b\xbc\xb6\x03\x51\xf1\xee\xff\xaa\xc9\xf5\x16\x1d\x2c\x5e\x52\x49\x3c\xaf\x7f\x13\x12\x1a\x24\xfb\xb8\xc1\x4e\xb7\xd8\x53\xfb\x76\xc0\x6e\xc8\x30\x8d\x2a\x65\xfd\x5d\x1c\xee\x97\x0d\xa3\x5c\x0f\x6c\x08\x5b\x2c\x0b\xbf\x64\xdb\x52\x2d\x8e\x92\x4f\x12\xbe\x6c\x87\x78\xb7\x7d\xc8\x42\xd8\x68\x83\x29\x04\xb5\x20\x91\xb2\xc9\xb9\x65\x45\xf4\xf6\xf4\xb7\xbd\x9d\x86\xc4\xab\xbe\x95\x9e\xe3\x82\x39\xcf\x95\xf4\x68\x7c\xb7\x00\xbb\x5d\xab\x35\x86\xa0\x11\x49\x50\x6c\x28\xc4\x18\xb5\x2f\x3f\xfc\x23\x90\x1c\x9f\x81\x5a\x14\xcf\xbf\xc4\xf4\x38\x0b\x61\x6d\xd1\x57\x49\xba\x31\x2d\xa5\x0f\x3d\x76\x24\xb4\xf9\xa3\xe1\x33\xae\x9f\x69\x67\x23")

		#llc_pkt = LLC(ieee.data_frame.data)
		#ip_pkt = ip.IP(llc_pkt.data)
		#self.failUnless(ip_pkt.dst == b"\x3f\xf5\xd1\x69")

	def test_data_qos(self):
		print(">>>>>>>>> Data QoS <<<<<<<<<")
		rlen = self.packet_bytes[3][2]
		ieee = ieee80211.IEEE80211(self.packet_bytes[3][rlen:])
		self.failUnless(ieee.bin() == self.packet_bytes[3][rlen:])
		self.failUnless(ieee.type == ieee80211.DATA_TYPE)
		self.failUnless(ieee.subtype == ieee80211.D_QOS_DATA)
		self.failUnless(ieee.datatods.dst == b"\x24\x65\x11\x85\xe9\xac")
		self.failUnless(ieee.datatods.src == b"\x00\xa0\x0b\x21\x37\x84")
		self.failUnless(ieee.datatods.frag_seq == 0xd008)
		self.failUnless(ieee.datatods.data == b"\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x00\xa0\x0b\x21\x37\x84\xc0\xa8\xb2\x16\x00\x00\x00\x00\x00\x00\xc0\xa8\xb2\x01")
		#self.failUnless(ieee.qos_data.control == 0x0)


	def test_rtap_ieee(self):
		print(">>>>>>>>> Radiotap IEEE 80211 <<<<<<<<<")
		rtap_ieee = radiotap.Radiotap(self.packet_bytes[0])
		self.failUnless(rtap_ieee.bin() == self.packet_bytes[0])
		self.failUnless(rtap_ieee.version == 0)
		print("len: %d" % rtap_ieee.len)
		self.failUnless(rtap_ieee.len == 4608)	# 0x1200 = 18
		self.failUnless(rtap_ieee.present_flags == 0x2e480000)
		
	def _test_bug(self):
		s= b"\x88\x41\x2c\x00\x00\x26\xcb\x17\x44\xf0\x00\x1e\x52\x97\x14\x11\x00\x1f\x6d\xe8\x18\x00\xd0\x07\x00\x00\x6f\x00\x00\x20\x00\x00\x00\x00"
		ieee = ieee80211.IEEE80211(s)
		self.failUnless(ieee.wep == 1)


class IP6TestCase(unittest.TestCase):
	def test_IP6(self):
		print(">>>>>>>>> IPv6 <<<<<<<<<")
		s = b"\x60\x00\x00\x00\x00\x24\x00\x01\xfe\x80\x00\x00\x00\x00\x00\x00\x9c\x09\xb4\x16\x07\x68\xff\x42\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x16\x3a\x00\x05\x02\x00\x00\x01\x00"
		ip = ip6.IP6(s)
		print(ip)
		self.failUnless(ip.bin() == s)
		self.failUnless(len(ip.opts) == 1)
		self.failUnless(len(ip.opts[0].opts) == 2)
		self.failUnless(ip.opts[0].opts[0].type == 5)
		self.failUnless(ip.opts[0].opts[1].type == 1)


class DTPTestCase(unittest.TestCase):
	def test_DTP(self):
		print(">>>>>>>>> DTP <<<<<<<<<")
		s = b"\x01\x00\x01\x00\x08\x4c\x61\x62\x00\x00\x02\x00\x05\x04\x00\x03\x00\x05\x40\x00\x04\x00\x0a\x00\x19\x06\xea\xb8\x85"
		dtp1 = dtp.DTP(s)
		self.failUnless(dtp1.bin() == s)
		for tv in dtp1.tvs:
			print("%s" % tv)
		self.failUnless(len(dtp1.tvs) == 4)


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
		self.failUnless(telnet1.bin() == packet_bytes[0][66:])


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
		self.failUnless(ssl1.bin() == packet_bytes[0][66:])
		#print(packet_bytes[0][66:])

		ssl2 = ssl.SSL(packet_bytes[1][66:])
		self.failUnless(ssl2.bin() == packet_bytes[1][66:])
		#print(packet_bytes[1][66:])

		ssl3 = ssl.SSL(packet_bytes[2][66:])
		self.failUnless(ssl3.bin() == packet_bytes[2][66:])
		#print(packet_bytes[2][66:])

		ssl4 = ssl.SSL(packet_bytes[3][66:])
		self.failUnless(ssl4.bin() == packet_bytes[3][66:])
		#print(packet_bytes[3][66:])

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

		self.failUnless(dia1.bin() == dia_bytes)
		self.failUnless(dia1 is not None)
		self.failUnless(dia1.v == 1)
		self.failUnless(dia1.len == b"\x00\x00\xe8")
		# dynamic fields
		print("AVPs: %d" % len(dia1.avps))
		self.failUnless(len(dia1.avps) == 13)
		avp1 = dia1.avps[0]
		avp2 = dia1.avps[12]
		self.failUnless(avp1.code == 268)
		self.failUnless(avp2.code == 258)

		avp3 = diameter.AVP(code=1, flags=2, len=b"\x00\x00\x03", data=b"\xff\xff\xff")
		dia1.avps.append(avp3)
		self.failUnless(len(dia1.avps) == 14)

#
# TBD
#


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

		self.failUnless(bgp1.bin() == bgp1_bytes)
		self.failUnless(bgp2.bin() == bgp2_bytes)
		self.failUnless(bgp3.bin() == bgp3_bytes)
		

class ASN1TestCase(unittest.TestCase):
	def test_asn1(self):
		s = b"0\x82\x02Q\x02\x01\x0bc\x82\x02J\x04xcn=Douglas J Song 1, ou=Information Technology Division, ou=Faculty and Staff, ou=People, o=University of Michigan, c=US\n\x01\x00\n\x01\x03\x02\x01\x00\x02\x01\x00\x01\x01\x00\x87\x0bobjectclass0\x82\x01\xb0\x04\rmemberOfGroup\x04\x03acl\x04\x02cn\x04\x05title\x04\rpostalAddress\x04\x0ftelephoneNumber\x04\x04mail\x04\x06member\x04\thomePhone\x04\x11homePostalAddress\x04\x0bobjectClass\x04\x0bdescription\x04\x18facsimileTelephoneNumber\x04\x05pager\x04\x03uid\x04\x0cuserPassword\x04\x08joinable\x04\x10associatedDomain\x04\x05owner\x04\x0erfc822ErrorsTo\x04\x08ErrorsTo\x04\x10rfc822RequestsTo\x04\nRequestsTo\x04\tmoderator\x04\nlabeledURL\x04\nonVacation\x04\x0fvacationMessage\x04\x05drink\x04\x0elastModifiedBy\x04\x10lastModifiedTime\x04\rmodifiersname\x04\x0fmodifytimestamp\x04\x0ccreatorsname\x04\x0fcreatetimestamp"
		self.failUnless(decode(s) == [(48, [(2, 11), (99, [(4, "cn=Douglas J Song 1, ou=Information Technology Division, ou=Faculty and Staff, ou=People, o=University of Michigan, c=US"), (10, "\x00"), (10, "\x03"), (2, 0), (2, 0), (1, "\x00"), (135, "objectclass"), (48, [(4, "memberOfGroup"), (4, "acl"), (4, "cn"), (4, "title"), (4, "postalAddress"), (4, "telephoneNumber"), (4, "mail"), (4, "member"), (4, "homePhone"), (4, "homePostalAddress"), (4, "objectClass"), (4, "description"), (4, "facsimileTelephoneNumber"), (4, "pager"), (4, "uid"), (4, "userPassword"), (4, "joinable"), (4, "associatedDomain"), (4, "owner"), (4, "rfc822ErrorsTo"), (4, "ErrorsTo"), (4, "rfc822RequestsTo"), (4, "RequestsTo"), (4, "moderator"), (4, "labeledURL"), (4, "onVacation"), (4, "vacationMessage"), (4, "drink"), (4, "lastModifiedBy"), (4, "lastModifiedTime"), (4, "modifiersname"), (4, "modifytimestamp"), (4, "creatorsname"), (4, "createtimestamp")])])])])


class LLCTestCase(unittest.TestCase):
	def test_llc(self):
		s = b"\xaa\xaa\x03\x00\x00\x00\x08\x00\x45\x00\x00\x28\x07\x27\x40\x00\x80\x06\x1d\x39\x8d\xd4\x37\x3d\x3f\xf5\xd1\x69\xc0\x5f\x01\xbb\xb2\xd6\xef\x23\x38\x2b\x4f\x08\x50\x10\x42\x04\xac\x17\x00\x00"

		llc_pkt = LLC(s)
		ip_pkt = ip.IP(llc_pkt.data)
		self.failUnless(llc_pkt.type == ethernet.ETH_TYPE_IP)
		self.failUnless(ip_pkt.dst == b"\x3f\xf5\xd1\x69")


class H225TestCase(unittest.TestCase):
	def testPack(self):
		h = H225(self.s)
		self.failUnless(self.s == str(h))

	def testUnpack(self):
		h = H225(self.s)
		self.failUnless(h.tpkt.v == 3)
		self.failUnless(h.tpkt.rsvd == 0)
		self.failUnless(h.tpkt.len == 1041)
		self.failUnless(h.proto == 8)
		self.failUnless(h.type == h225.SETUP)
		self.failUnless(len(h.data) == 3)

		ie = h.data[0]
		self.failUnless(ie.type == h225.BEARER_CAPABILITY)
		self.failUnless(ie.len == 3)
		ie = h.data[1]
		self.failUnless(ie.type == h225.DISPLAY)
		self.failUnless(ie.len == 14)
		ie = h.data[2]
		self.failUnless(ie.type == h225.USER_TO_USER)
		self.failUnless(ie.len == 1008)

	s = b"\x03\x00\x04\x11\x08\x02\x54\x2b\x05\x04\x03\x88\x93\xa5\x28\x0e\x4a\x6f\x6e\x20\x4f\x62\x65\x72\x68\x65\x69\x64\x65\x00\x7e\x03\xf0\x05\x20\xb8\x06\x00\x08\x91\x4a\x00\x04\x01\x40\x0c\x00\x4a\x00\x6f\x00\x6e\x00\x20\x00\x4f\x00\x62\x00\x65\x00\x72\x00\x68\x00\x65\x00\x69\x00\x64\x00\x65\x22\xc0\x09\x00\x00\x3d\x06\x65\x6b\x69\x67\x61\x00\x00\x14\x32\x2e\x30\x2e\x32\x20\x28\x4f\x50\x41\x4c\x20\x76\x32\x2e\x32\x2e\x32\x29\x00\x00\x00\x01\x40\x15\x00\x74\x00\x63\x00\x70\x00\x24\x00\x68\x00\x33\x00\x32\x00\x33\x00\x2e\x00\x76\x00\x6f\x00\x78\x00\x67\x00\x72\x00\x61\x00\x74\x00\x69\x00\x61\x00\x2e\x00\x6f\x00\x72\x00\x67\x00\x42\x87\x23\x2c\x06\xb8\x00\x6a\x8b\x1d\x0c\xb7\x06\xdb\x11\x9e\xca\x00\x10\xa4\x89\x6d\x6a\x00\xc5\x1d\x80\x04\x07\x00\x0a\x00\x01\x7a\x75\x30\x11\x00\x5e\x88\x1d\x0c\xb7\x06\xdb\x11\x9e\xca\x00\x10\xa4\x89\x6d\x6a\x82\x2b\x0e\x30\x40\x00\x00\x06\x04\x01\x00\x4c\x10\x09\x00\x00\x3d\x0f\x53\x70\x65\x65\x78\x20\x62\x73\x34\x20\x57\x69\x64\x65\x36\x80\x11\x1c\x00\x01\x00\x98\xa0\x26\x41\x13\x8a\x00\x98\xa0\x26\x41\x13\x8b\x26\x00\x00\x64\x0c\x10\x09\x00\x00\x3d\x0f\x53\x70\x65\x65\x78\x20\x62\x73\x34\x20\x57\x69\x64\x65\x36\x80\x0b\x0d\x00\x01\x00\x98\xa0\x26\x41\x13\x8b\x00\x2a\x40\x00\x00\x06\x04\x01\x00\x4c\x10\x09\x00\x00\x3d\x09\x69\x4c\x42\x43\x2d\x31\x33\x6b\x33\x80\x11\x1c\x00\x01\x00\x98\xa0\x26\x41\x13\x8a\x00\x98\xa0\x26\x41\x13\x8b\x20\x00\x00\x65\x0c\x10\x09\x00\x00\x3d\x09\x69\x4c\x42\x43\x2d\x31\x33\x6b\x33\x80\x0b\x0d\x00\x01\x00\x98\xa0\x26\x41\x13\x8b\x00\x20\x40\x00\x00\x06\x04\x01\x00\x4e\x0c\x03\x00\x83\x00\x80\x11\x1c\x00\x01\x00\x98\xa0\x26\x41\x13\x8a\x00\x98\xa0\x26\x41\x13\x8b\x16\x00\x00\x66\x0e\x0c\x03\x00\x83\x00\x80\x0b\x0d\x00\x01\x00\x98\xa0\x26\x41\x13\x8b\x00\x4b\x40\x00\x00\x06\x04\x01\x00\x4c\x10\xb5\x00\x53\x4c\x2a\x02\x00\x00\x00\x00\x00\x40\x01\x00\x00\x40\x01\x02\x00\x08\x00\x00\x00\x00\x00\x31\x00\x01\x00\x40\x1f\x00\x00\x59\x06\x00\x00\x41\x00\x00\x00\x02\x00\x40\x01\x00\x00\x80\x11\x1c\x00\x01\x00\x98\xa0\x26\x41\x13\x8a\x00\x98\xa0\x26\x41\x13\x8b\x41\x00\x00\x67\x0c\x10\xb5\x00\x53\x4c\x2a\x02\x00\x00\x00\x00\x00\x40\x01\x00\x00\x40\x01\x02\x00\x08\x00\x00\x00\x00\x00\x31\x00\x01\x00\x40\x1f\x00\x00\x59\x06\x00\x00\x41\x00\x00\x00\x02\x00\x40\x01\x00\x00\x80\x0b\x0d\x00\x01\x00\x98\xa0\x26\x41\x13\x8b\x00\x32\x40\x00\x00\x06\x04\x01\x00\x4c\x10\x09\x00\x00\x3d\x11\x53\x70\x65\x65\x78\x20\x62\x73\x34\x20\x4e\x61\x72\x72\x6f\x77\x33\x80\x11\x1c\x00\x01\x00\x98\xa0\x26\x41\x13\x8a\x00\x98\xa0\x26\x41\x13\x8b\x28\x00\x00\x68\x0c\x10\x09\x00\x00\x3d\x11\x53\x70\x65\x65\x78\x20\x62\x73\x34\x20\x4e\x61\x72\x72\x6f\x77\x33\x80\x0b\x0d\x00\x01\x00\x98\xa0\x26\x41\x13\x8b\x00\x1d\x40\x00\x00\x06\x04\x01\x00\x4c\x60\x1d\x80\x11\x1c\x00\x01\x00\x98\xa0\x26\x41\x13\x8a\x00\x98\xa0\x26\x41\x13\x8b\x13\x00\x00\x69\x0c\x60\x1d\x80\x0b\x0d\x00\x01\x00\x98\xa0\x26\x41\x13\x8b\x00\x1d\x40\x00\x00\x06\x04\x01\x00\x4c\x20\x1d\x80\x11\x1c\x00\x01\x00\x98\xa0\x26\x41\x13\x8a\x00\x98\xa0\x26\x41\x13\x8b\x13\x00\x00\x6a\x0c\x20\x1d\x80\x0b\x0d\x00\x01\x00\x98\xa0\x26\x41\x13\x8b\x00\x01\x00\x01\x00\x01\x00\x01\x00\x81\x03\x02\x80\xf8\x02\x70\x01\x06\x00\x08\x81\x75\x00\x0b\x80\x13\x80\x01\xf4\x00\x01\x00\x00\x01\x00\x00\x01\x00\x00\x0c\xc0\x01\x00\x01\x80\x0b\x80\x00\x00\x20\x20\x09\x00\x00\x3d\x0f\x53\x70\x65\x65\x78\x20\x62\x73\x34\x20\x57\x69\x64\x65\x36\x80\x00\x01\x20\x20\x09\x00\x00\x3d\x09\x69\x4c\x42\x43\x2d\x31\x33\x6b\x33\x80\x00\x02\x24\x18\x03\x00\xe6\x00\x80\x00\x03\x20\x20\xb5\x00\x53\x4c\x2a\x02\x00\x00\x00\x00\x00\x40\x01\x00\x00\x40\x01\x02\x00\x08\x00\x00\x00\x00\x00\x31\x00\x01\x00\x40\x1f\x00\x00\x59\x06\x00\x00\x41\x00\x00\x00\x02\x00\x40\x01\x00\x00\x80\x00\x04\x20\x20\x09\x00\x00\x3d\x11\x53\x70\x65\x65\x78\x20\x62\x73\x34\x20\x4e\x61\x72\x72\x6f\x77\x33\x80\x00\x05\x20\xc0\xef\x80\x00\x06\x20\x40\xef\x80\x00\x07\x08\xe0\x03\x51\x00\x80\x01\x00\x80\x00\x08\x08\xd0\x03\x51\x00\x80\x01\x00\x80\x00\x09\x83\x01\x50\x80\x00\x0a\x83\x01\x10\x80\x00\x0b\x83\x01\x40\x00\x80\x01\x03\x06\x00\x00\x00\x01\x00\x02\x00\x03\x00\x04\x00\x05\x00\x06\x01\x00\x07\x00\x08\x00\x00\x09\x01\x00\x0a\x00\x0b\x07\x01\x00\x32\x80\xa6\xff\x4c\x02\x80\x01\x80"


class LLDPTestCase():
# TODO: not yet implemented
#class LLDPTestCase(unittest.TestCase):
	# TODO:XXX more test cases

	def test_lldp(self):
		data = b"\x02\x11\x07" + b"deadbeefcafecafe" \
			   b"\x04\x05\x07" + b"0008" \
			   b"\x06\x02\x00\x3c" \
			   b"\x00\x00"
		lldp = LLDP(data)
		if (data != lldp.pack()):
			raise pypacker.PackError

	def test_eth_lldp(self):
		data = b"\x80\x48\x00\x00\x00\x00" \
			  b"\x80\x48\x00\x00\x00\x00" \
			  b"\x88\xcc" \
			  b"\x02\x11\x07" + b"deadbeefcafecafe" \
			  b"\x04\x05\x07" + b"0008" \
			  b"\x06\x02\x00\x3c" \
			  b"\x00\x00"
		ethlldp = ethernet.Ethernet(data)
		if (data != ethlldp.pack()):
			raise pypacker.PackError


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

suite.addTests(loader.loadTestsFromTestCase(CreateTestCase))
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
suite.addTests(loader.loadTestsFromTestCase(RadiotapTestCase))
suite.addTests(loader.loadTestsFromTestCase(IEEE80211TestCase))
suite.addTests(loader.loadTestsFromTestCase(TriggerListHTTPTestCase))
suite.addTests(loader.loadTestsFromTestCase(DTPTestCase))
suite.addTests(loader.loadTestsFromTestCase(DNSTestCase))
suite.addTests(loader.loadTestsFromTestCase(TelnetTestCase))
suite.addTests(loader.loadTestsFromTestCase(SSLTestCase))
suite.addTests(loader.loadTestsFromTestCase(DiameterTestCase))
#suite.addTests(loader.loadTestsFromTestCase(BGPTestCase))
suite.addTests(loader.loadTestsFromTestCase(PerfTestCase))

unittest.TextTestRunner().run(suite)
