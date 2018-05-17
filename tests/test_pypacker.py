import copy
import unittest
import time
import random
import struct
import sys
import pprint

from pypacker import pypacker, checksum
from pypacker.psocket import SocketHndl
import pypacker.ppcap as ppcap
import pypacker.pcapng as pcapng
from pypacker import statemachine
from pypacker.layer12 import aoe, arp, btle, can, dtp, ethernet, ieee80211, linuxcc, ppp, radiotap, stp, vrrp,\
	flow_control, lldp
from pypacker.layer3 import ip, ip6, ipx, icmp, igmp, ospf, pim
from pypacker.layer4 import tcp, udp, ssl, sctp
from pypacker.layer567 import diameter, dhcp, dns, der, hsrp, http, ntp, pmap, radius, rip, rtp, telnet, tpkt


# General testcases:
# - Length comparing before/after parsing
# - Concatination via "+" (+parsing)
# - type finding via packet[type]
# - dynamic field modification
#
# Things to test on every protocol:
# - raw byte parsing
# - header changes (dynamic/optional headers)
# - checksums (optional)
# - direction of packages (optional)
#
# Successfully tested:
# - Ethernet
# - Linux cooked capture format
# - Radiotap
# - IEEE80211
# - BTLE
# - ARP
# - DNS
# - STP
# - PPP
# - OSPF
# - VRRP
# - DTP
# - AOE
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
# - STUN
# - TFTP
# - TPKT
# - Pmap
# - Radius
# - BGP
#
# TBD:
# - PPPoE


def print_header(msg):
	print()
	print(">>>>>>>>> " + msg + " <<<<<<<<<")


def get_pcap(fname, cnt=1000):
	"""
	Read cnt packets from a pcap file, default: 1000
	"""
	packet_bytes = []
	pcap = ppcap.Reader(fname)

	for ts, buf in pcap:
		packet_bytes.append(buf)
		cnt -= 1

		if cnt <= 0:
			break
	pcap.close()
	return packet_bytes


class MyPacket(pypacker.Packet):
	pass


class GeneralTestCase(unittest.TestCase):
	def Xtest_onlybody(self):
		bts = b"abcd"
		p = MyPacket(bts)
		self.assertEqual(p.bin(), bts)

	def test_create_eth(self):
		print_header("Keyword creation")
		eth = ethernet.Ethernet()
		# print(str(eth))
		self.assertEqual(eth.bin(), b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x08\x00")
		eth = ethernet.Ethernet(dst=b"\x00\x01\x02\x03\x04\x05", src=b"\x06\x07\x08\x09\x0A\x0B", type=2048)
		print(str(eth))
		print(eth.bin())
		self.assertEqual(eth.bin(), b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x08\x00")

		# test packet creation (default, keyword, bytes + keyword)
		bts = get_pcap("tests/packets_ether.pcap")[0]
		eth = ethernet.Ethernet()
		self.assertEqual(eth.src_s, "FF:FF:FF:FF:FF:FF")
		eth = ethernet.Ethernet(src=b"\xAA\xAA\xAA\xAA\xAA\xAA")
		self.assertEqual(eth.src_s, "AA:AA:AA:AA:AA:AA")
		eth = ethernet.Ethernet(dst=b"\xAA\xAA\xAA\xAA\xAA\xAA")
		self.assertEqual(eth.dst_s, "AA:AA:AA:AA:AA:AA")

	def test_reverse(self):
		print_header("Reverse layer")
		# test packet reversing
		bts = get_pcap("tests/packets_ether.pcap")[13]
		eth = ethernet.Ethernet(bts)
		eth_src, eth_dst = eth.src_s, eth.dst_s
		ip_src, ip_dst = eth.ip.src_s, eth.ip.dst_s
		tcp_src, tcp_dst = eth.ip.tcp.sport, eth.ip.tcp.dport
		eth.reverse_all_address()

		self.assertEqual(eth.src_s, eth_dst)
		self.assertEqual(eth.dst_s, eth_src)
		self.assertEqual(eth.ip.src_s, ip_dst)
		self.assertEqual(eth.ip.dst_s, ip_src)
		self.assertEqual(eth.ip.tcp.sport, tcp_dst)
		self.assertEqual(eth.ip.tcp.dport, tcp_src)

	def test_lowest_layer(self):
		print_header("Lowest layer")
		bts = get_pcap("tests/packets_ether.pcap")[13]
		eth = ethernet.Ethernet(bts)
		tcp1 = eth[tcp.TCP]
		lowest_layer = tcp1.lowest_layer
		self.assertEqual(eth, lowest_layer)

	def test_highest_layer(self):
		print_header("Highest layer")
		bts = get_pcap("tests/packets_ether.pcap")[13]
		eth = ethernet.Ethernet(bts)
		highest_layer = eth.highest_layer
		self.assertEqual(highest_layer.__class__.__name__, "TCP")

	def test_add(self):
		print_header("pkt1 + pkt2 + pkt3")
		eth1 = ethernet.Ethernet()
		ip1 = ip.IP()
		tcp1 = tcp.TCP()
		pkt = eth1 + ip1 + tcp1

		self.assertEqual(pkt.highest_layer.__class__.__name__, "TCP")

	def test_iadd(self):
		print_header("pkt1 += pkt2")
		eth1 = ethernet.Ethernet()
		ip1 = ip.IP()
		tcp1 = tcp.TCP()

		eth1 += ip1
		eth1 += tcp1

		self.assertEqual(eth1.highest_layer.__class__.__name__, "TCP")

	def test_len(self):
		print_header("Length")
		bts_list = get_pcap("tests/packets_ssl.pcap")

		for bts in bts_list:
			eth = ethernet.Ethernet(bts)
			print("%d = %d" % (len(bts), len(eth)))
			self.assertEqual(len(bts), len(eth))

	def test_repr(self):
		# TODO: activate
		print_header("__repr__")
		bts_list = get_pcap("tests/packets_ssl.pcap")

		for bts in bts_list:
			eth = ethernet.Ethernet(bts)
			print("%r" % eth)

		eth1 = ethernet.Ethernet(bts)
		eth1[tcp.TCP].body_bytes = b"qwertz"
		eth1.bin()
		tcp_sum_original = eth1[tcp.TCP].sum
		eth1[tcp.TCP].body_bytes = b"asdfgh"
		# ip checksum should be recalculated
		tmp = "%r" % eth1
		self.assertNotEqual(tcp_sum_original, eth1[tcp.TCP].sum)
		# original checksum value should be calculated
		eth1[tcp.TCP].body_bytes = b"qwertz"
		tmp = "%r" % eth1
		self.assertEqual(tcp_sum_original, eth1[tcp.TCP].sum)

	def test_headerupate(self):
		print_header("Header update (most common protos)")
		pkt1 = ethernet.Ethernet() + ip.IP() + tcp.TCP() + dns.DNS()
		layers = [layer for layer in pkt1]
		layers.reverse()
		# make sure every header in stack A.B.C... is uptodate starting from highest
		# Must be same as A.bin() but we are testing...
		for layer in layers:
			layer.bin()
		sum_ip = pkt1.ip.sum
		sum_tcp = pkt1.ip.tcp.sum
		dns1 = pkt1.ip.tcp.dns
		dns_amounts = dns1.questions_amount + dns1.answers_amount + dns1.authrr_amount + dns1.addrr_amount
		self.assertEqual(dns_amounts, 0)
		# change highest layer and check checksums
		dns1.queries.append(dns.DNS.Query())
		dns1.answers.append(dns.DNS.Answer())
		dns1.auths.append(dns.DNS.Auth())
		dns1.addrecords.append(dns.DNS.AddRecord())

		# writer = ppcap.Writer(filename="headerupdate.pcap")
		bts1 = pkt1.bin()
		# writer.write(bts1)
		self.assertEqual(pkt1.ip.sum, 0x7A79)
		self.assertEqual(pkt1.ip.tcp.sum, 0xA41E)
		self.assertEqual(dns1.questions_amount, 1)
		self.assertEqual(dns1.answers_amount, 1)
		self.assertEqual(dns1.authrr_amount, 1)
		self.assertEqual(dns1.addrr_amount, 1)
		dns1.queries.clear()
		dns1.answers.clear()
		dns1.auths.clear()
		dns1.addrecords.clear()
		bts1 = pkt1.bin()
		# writer.write(bts1)
		# original state restored -> same checksum and auto-update values as before
		self.assertEqual(pkt1.ip.sum, sum_ip)
		self.assertEqual(pkt1.ip.tcp.sum, sum_tcp)
		self.assertEqual(dns1.questions_amount, 0)
		self.assertEqual(dns1.answers_amount, 0)
		self.assertEqual(dns1.authrr_amount, 0)
		self.assertEqual(dns1.addrr_amount, 0)

	# writer.close()

	def test_find(self):
		print_header("Find value")
		bts_list = get_pcap("tests/packets_rtap_sel.pcap")

		# TODO: remove
		rtap = radiotap.Radiotap(bts_list[0])
		# print("%r" % bts_list[0])
		print("type: %d subtype: %d" % (rtap.upper_layer.type, rtap.upper_layer.subtype))

		beacon = radiotap.Radiotap(bts_list[0])[ieee80211.IEEE80211.Beacon]
		essid = beacon.params.find_value(lambda v: v.id == 0).body_bytes
		print(essid)
		self.assertEqual(essid, b"system1")

	def test_lazyinit(self):
		print_header("Lazy init")
		bts = get_pcap("tests/packets_ether.pcap")[14]
		print(">>> creating ethernet packet")
		eth = ethernet.Ethernet(bts)

		self.assertIsNone(eth._body_bytes)
		self.assertIsNotNone(eth._lazy_handler_data)
		self.assertFalse(eth._header_changed)

		print(">>> checking Exceptions")

		def getattr_ip():
			object.__getattribute__(eth, "ip")
			print("end: access IP")

		# ip not present until accessing
		self.assertRaises(AttributeError, getattr_ip)

		ip1 = eth.ip

		print(">>> checking status")
		self.assertIsNone(eth._body_bytes)
		self.assertIsNone(eth._lazy_handler_data)
		self.assertFalse(ip1._header_changed)
		self.assertIsNone(ip1._body_bytes)
		self.assertIsNotNone(ip1._lazy_handler_data)

		print(">>> getting tcp")
		tcp1 = eth.ip.tcp

		print("getting opts")
		opts = tcp1.opts
		print("asserting..")
		# no writing access to packet: format changed by init of triggerlist
		self.assertTrue(tcp1._header_format_changed)
		# callback is not removed anymore
		# self.assertIsNone(tcp1.opts._dissect_callback)
		self.assertIsNotNone(tcp1.opts._cached_result)
		print("triggering lazy init")
		opt_val = tcp1.opts[0]
		self.assertIsNone(tcp1.opts._dissect_callback)
		self.assertIsNotNone(tcp1.opts._cached_result)
		print("--------------- deleting first option")
		del tcp1.opts[0]
		print("start: opts uncached")
		# TCP Triggerlist is updating header length which leads to cache update
		self.assertIsNone(tcp1.opts._cached_result)

		self.assertIsNotNone(tcp1._body_bytes)
		self.assertIsNone(tcp1._lazy_handler_data)

		print(">>> Iter over TriggerList")
		ipopts = [
			ip.IPOptMulti(type=0x02, len=0x04, body_bytes=b"AB"),
			ip.IPOptMulti(type=0x02, len=0x04, body_bytes=b"AB"),
			ip.IPOptMulti(type=0x02, len=0x04, body_bytes=b"AB")
		]
		pkt = ethernet.Ethernet() + ip.IP(opts=ipopts)
		#print(pkt)
		pkt_bts = pkt.bin()
		pkt_re = ethernet.Ethernet(pkt_bts)
		ipopts_re = pkt_re.ip.opts

		for idx, ipopt_new in enumerate(ipopts_re):
			print(ipopt_new)
			self.assertEqual(ipopt_new.bin(), ipopts[idx].bin())

	def test_dissectfail(self):
		print_header("Dissectfail")
		tcp_bytes_fail = b"\x00" * 16
		pkt1 = ethernet.Ethernet() + ip.IP() + tcp_bytes_fail
		pkt1_bts = pkt1.bin()
		self.assertTrue(pkt1_bts.endswith(tcp_bytes_fail))
		pkt1 = ethernet.Ethernet(pkt1_bts)
		pkt_tcp = pkt1.upper_layer.upper_layer
		print("TCP for dissectfail #1: %r" % pkt_tcp)
		self.assertIsNone(pkt_tcp)

		pkt1 = ethernet.Ethernet(pkt1_bts)
		pkt_tcp = pkt1.ip.tcp
		print("TCP for dissectfail #2: %r" % pkt_tcp)
		self.assertIsNone(pkt_tcp)

		# retrieving body type on failed dissect only works 1st time (returns None)
		# 2nd time raises Exception
		# pkt_tcp = pkt1.ip.tcp
		self.assertRaises(Exception, lambda: pkt1.ip.tcp)

		ip_bytes_orig = pkt1_bts[-len(tcp_bytes_fail):]
		ip_bytes = pkt1.ip.body_bytes
		self.assertEqual(ip_bytes, ip_bytes_orig)

	def test_handlerid_update(self):
		print_header("Auto update of handler id")
		# auto type-id setting for Ethernet
		print("Ethernet...")
		eth_1 = ethernet.Ethernet(type=0)
		ip_1 = ip.IP()
		pkt = eth_1 + ip_1
		self.assertEqual(pkt.type, 0)
		pkt.bin()
		self.assertEqual(pkt.type, ethernet.ETH_TYPE_IP)

		# auto type-id setting for IP
		print("IP...")
		ip_2 = ip.IP(p=0)
		tcp_2 = tcp.TCP()
		pkt = ip_2 + tcp_2
		self.assertEqual(pkt.p, 0)
		pkt.bin()
		self.assertEqual(pkt.p, ip.IP_PROTO_TCP)

		# auto type-id setting for TCP
		"""
		print("TCP...")
		ip_3 = ip.IP(p=0)
		tcp_3 = tcp.TCP(dport=0)
		http_3 = http.HTTP()
		pkt = ip_3 + tcp_3 + http_3
		self.assertEqual(pkt.tcp.dport, 0)
		pkt.bin()
		self.assertEqual(pkt.tcp.dport, 80)
		"""

		# auto type-id setting for UDP
		"""
		print("UDP...")
		ip_4 = ip.IP(p=0)
		udp_4 = udp.UDP(dport=0)
		dns_4 = dns.DNS()
		pkt = ip_4 + udp_4 + dns_4
		self.assertEqual(pkt.udp.dport, 0)
		pkt.bin()
		self.assertEqual(pkt.udp.dport, 53)
		"""

	def test_multivalue_getitem(self):
		print_header("Multi type __getitem__")
		pkt1 = ethernet.Ethernet() + ip.IP() + tcp.TCP() + http.HTTP()
		# match on end
		pkt1_http = pkt1[ethernet.Ethernet, ip.IP, tcp.TCP, http.HTTP]
		self.assertEqual(pkt1_http.__class__, http.HTTP)
		# match before end
		pkt1_tcp = pkt1[ethernet.Ethernet, ip.IP, tcp.TCP]
		self.assertEqual(pkt1_tcp.__class__, tcp.TCP)
		# no match on start
		pkt1_none = pkt1[ethernet.Ethernet, ethernet.Ethernet]
		self.assertEqual(pkt1_none, None)
		# no match on end
		pkt1_none = pkt1[ethernet.Ethernet, ip.IP, tcp.TCP, telnet.Telnet]
		self.assertEqual(pkt1_none, None)


class PacketDumpTestCase(unittest.TestCase):
	def test_exdump(self):
		bts = get_pcap("tests/packets_ether.pcap")[7]
		eth = ethernet.Ethernet(bts)
		eth.hexdump()


class EthTestCase(unittest.TestCase):
	def test_eth(self):
		print_header("ETHERNET")
		# Ethernet without body
		s = b"\x52\x54\x00\x12\x35\x02\x08\x00\x27\xa9\x93\x9e\x08\x00"
		eth1 = ethernet.Ethernet(s)
		# parsing
		self.assertEqual(eth1.bin(), s)
		self.assertEqual(eth1.dst_s, "52:54:00:12:35:02")
		self.assertEqual(eth1.src_s, "08:00:27:A9:93:9E")
		self.assertEqual(type(eth1.vlan).__name__, "TriggerList")
		self.assertEqual(len(eth1.vlan), 0)

		# Ethernet + IP
		s = b"\x52\x54\x00\x12\x35\x02\x08\x00\x27\xa9\x93\x9e\x08\x00\x45\x00\x00\x37\xc5\x78" +\
			b"\x40\x00\x40\x11\x9c\x81\x0a\x00\x02\x0f\x0a\x20\xc2\x8d"
		eth2 = ethernet.Ethernet(s)
		# parsing
		self.assertEqual(eth2.bin(), s)
		self.assertEqual(type(eth2.ip).__name__, "IP")
		print("Ethernet with IP: %s -> %s" % (eth2.ip.src, eth2.ip.dst))
		# reconstruate macs
		eth1.src = b"\x52\x54\x00\x12\x35\x02"
		eth1.dst = b"\x08\x00\x27\xa9\x93\x9e"
		# direction
		print("direction of eth: %d" % eth1.direction(eth1))
		self.assertTrue(eth1.is_direction(eth1, pypacker.Packet.DIR_SAME))

	def test_incomplete(self):
		eth = ethernet.Ethernet(b"\x01\x80\xc2\x00\x00\x00,03\xa3\x9b\xc8\x00'")
		print("%r" % eth)

	def test_eth_vlan_tags(self):
		print_header("ETHERNET + VLAN Tags")

		# Ethernet + VLAN tag, type 0x8100 ) + ARP
		# VALN tag: type=0x8100, prio=0, cfi=0, vid=5
		s1 = b"\x00\x00\x00333\x00\x00 \x00\x10\x02\x81\x00\x00\x05\x08\x06\x00\x01"\
			b"\x08\x00\x06\x04\x00\x01\x00\x00 \x00\x10\x02\x01\x01\x01\x01\x00\x00"\
			b"\x00\x00\x00\x00\x01\x01\x01\x02"
		eth1 = ethernet.Ethernet(s1)
		# parsing
		self.assertEqual(eth1.bin(), s1)
		self.assertEqual(eth1.dst_s, "00:00:00:33:33:33")
		self.assertEqual(eth1.src_s, "00:00:20:00:10:02")
		self.assertEqual(eth1.type, ethernet.ETH_TYPE_ARP)
		self.assertEqual(len(eth1.vlan), 1)
		self.assertEqual(eth1.vlan[0].type, ethernet.ETH_TYPE_8021Q)
		self.assertEqual(eth1.vlan[0].prio, 0)
		self.assertEqual(eth1.vlan[0].cfi, 0)
		self.assertEqual(eth1.vlan[0].vid, 5)
		self.assertEqual(type(eth1.arp).__name__, "ARP")

		# Ethernet + QinQ(double tags, type 0x8100 ) + IP
		# Outer tag: type=0x81A8, prio=1, cfi=1, vid=5
		# Inner tag: type=0x8100, prio=2, cfi=0, vid=99
		s = b"\x00\x00\x00\x00\x00\xaa\x00\x00\x00\x00\x00\xbb\x88\xA80\x05\x81\x00@c"\
			b"\x08\x00E\x00\x00&\x00\x01\x00\x00@\x00|\xd5\x7f\x00\x00\x01\x7f\x00\x00"\
			b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		eth1 = ethernet.Ethernet(s)
		# parsing
		self.assertEqual(eth1.bin(), s)
		self.assertEqual(eth1.dst_s, "00:00:00:00:00:AA")
		self.assertEqual(eth1.src_s, "00:00:00:00:00:BB")
		self.assertEqual(eth1.type, ethernet.ETH_TYPE_IP)
		self.assertEqual(len(eth1.vlan), 2)
		self.assertEqual(eth1.vlan[0].type, ethernet.ETH_TYPE_PBRIDGE)
		self.assertEqual(eth1.vlan[0].prio, 1)
		self.assertEqual(eth1.vlan[0].cfi, 1)
		self.assertEqual(eth1.vlan[0].vid, 5)
		self.assertEqual(eth1.vlan[1].type, ethernet.ETH_TYPE_8021Q)
		self.assertEqual(eth1.vlan[1].prio, 2)
		self.assertEqual(eth1.vlan[1].cfi, 0)
		self.assertEqual(eth1.vlan[1].vid, 99)
		self.assertEqual(type(eth1.ip).__name__, "IP")

		# Ethernet + QinQ(double tags, type 0x9100 ) + IP
		# Outer tag: type=0x8100, prio=7, cfi=1, vid=4000
		# Inner tag: type=0x8100, prio=0, cfi=0, vid=1
		s = b"\x00\x00\x00\x00\x00\xaa\x00\x00\x00\x00\x00\xbb\x91\x00\xff\xa0\x81\x00\x00"\
			b"\x01\x08\x00E\x00\x00&\x00\x01\x00\x00@\x00|\xd5\x7f\x00\x00\x01\x7f\x00\x00"\
			b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		eth1 = ethernet.Ethernet(s)
		# parsing
		self.assertEqual(eth1.bin(), s)
		self.assertEqual(eth1.dst_s, "00:00:00:00:00:AA")
		self.assertEqual(eth1.src_s, "00:00:00:00:00:BB")
		self.assertEqual(eth1.type, ethernet.ETH_TYPE_IP)
		self.assertEqual(len(eth1.vlan), 2)
		self.assertEqual(eth1.vlan[0].type, ethernet.ETH_TYPE_TUNNELING)
		self.assertEqual(eth1.vlan[0].prio, 7)
		self.assertEqual(eth1.vlan[0].cfi, 1)
		self.assertEqual(eth1.vlan[0].vid, 4000)
		self.assertEqual(eth1.vlan[1].type, ethernet.ETH_TYPE_8021Q)
		self.assertEqual(eth1.vlan[1].prio, 0)
		self.assertEqual(eth1.vlan[1].cfi, 0)
		self.assertEqual(eth1.vlan[1].vid, 1)
		self.assertEqual(type(eth1.ip).__name__, "IP")


class AOETestCase(unittest.TestCase):
	def test_aoe(self):
		s = b"\x01\x02\x03\x04\x05\x06\x11\x12\x13\x14\x15\x16\x88\xa2\x10\x00\x00\x01\x02\x01\x80\x00\x00"\
			b"\x00\x12\x34\x00\x00\x00\x00\x04\x00" + b"\0xed" * 1024
		aoecfg = aoe.AOECFG(s[14 + 10:])
		self.assertEqual(aoecfg.bufcnt, 0x1234)

		s = b"\x03\x0a\x6b\x19\x00\x00\x00\x00\x45\x00\x00\x28\x94\x1f\x00\x00\xe3\x06\x99\xb4\x23\x2b\x24"\
			b"\x00\xde\x8e\x84\x42\xab\xd1\x00\x50\x00\x35\xe1\x29\x20\xd9\x00\x00\x00\x22\x9b\xf0\xe2"\
			b"\x04\x65\x6b"
		aoeata = aoe.AOEATA(s)
		self.assertEqual(aoeata.bin(), s)


class LinuxCookedCapture(unittest.TestCase):
	def test_lcc(self):
		print_header("Linux cooked capture")
		bts = get_pcap("tests/packets_linuxcc.pcap")

		lcc1 = linuxcc.LinuxCC(bts[0])
		self.assertEqual(lcc1.dir, linuxcc.PACKET_DIR_FROM_US)
		self.assertEqual(lcc1.ip.src_s, "10.50.247.1")
		self.assertEqual(lcc1.ip.dst_s, "91.240.77.140")
		self.assertEqual(lcc1.ip.tcp.sport, 56060)
		self.assertEqual(lcc1.ip.tcp.dport, 80)
		lcc2 = linuxcc.LinuxCC(bts[2])
		self.assertEqual(lcc2.dir, linuxcc.PACKET_DIR_TO_US)


class CANTestCase(unittest.TestCase):
	def test_can(self):
		print_header("CAN")
		bts_list = get_pcap("tests/packets_can.pcap")
		can_pkts = []

		for bts in bts_list:
			can_pkt = can.CAN(bts)
			can_pkt.bin()
			self.assertEqual(len(can_pkt.body_bytes), 8)
			can_pkts.append(can_pkt)

		self.assertEqual(can_pkts[0].id, 0x12070000)
		self.assertEqual(can_pkts[1].id, 0x04000020)
		self.assertEqual(can_pkts[2].id, 0x1000009B)

		self.assertEqual(can_pkts[0].extended, 1)
		self.assertEqual(can_pkts[0].rtr, 1)
		self.assertEqual(can_pkts[0].err, 1)

		for idx in range(1, 3):
			self.assertEqual(can_pkts[idx].extended, 1)
			self.assertEqual(can_pkts[idx].rtr, 0)
			self.assertEqual(can_pkts[idx].err, 0)

		# UDS packet
		print("1: %r" % can_pkts[0])
		self.assertEqual(can_pkts[0].isotpsingleframe.dl, 2)
		self.assertEqual(can_pkts[0].isotpsingleframe.uds.bin()[: 2], b"\x10\x01")

		# UDS packet
		print("2: %r" % can_pkts[1])
		self.assertEqual(can_pkts[1].isotpsingleframe.dl, 0)

		# OBD2 packet
		print("3: %r" % can_pkts[2])
		self.assertEqual(can_pkts[2].isotpfirstframe.dl, 0x40)
		self.assertEqual(can_pkts[2].isotpfirstframe.obd2.mode, 0x01)
		self.assertEqual(can_pkts[2].isotpfirstframe.obd2.pid, 0x04)
		self.assertEqual(can_pkts[2].isotpfirstframe.obd2.bin(), b"\x01\x04\x00\x00\x00\x00")

		can_pkts[0].id = 0x123
		can_pkts[0].bin()
		self.assertEqual(can_pkts[0].extended, 0)
		can_pkts[0].id = 0x800
		can_pkts[0].bin()
		self.assertEqual(can_pkts[0].extended, 1)

		can1 = can.CAN(id=0x7ff)
		self.assertEqual(can1.extended, 0)
		# set extended althouth it isn't
		can1.extended = 1
		can1.bin(update_auto_fields=False)
		self.assertEqual(can1.extended, 1)
		can1.id = 0x7ff
		can1.bin()
		self.assertEqual(can1.extended, 0)
		can1.id = 0x800
		can1.bin()
		self.assertEqual(can1.extended, 1)

		for x in range(0x1FFF):
			can2 = can.CAN(id=x, extended=1, rtr=1, err=1)
			self.assertEqual(can2.id, x)
			self.assertEqual(can2.extended, 1)
			self.assertEqual(can2.rtr, 1)
			self.assertEqual(can2.err, 1)


class IPTestCase(unittest.TestCase):
	def test_IP(self):
		print_header("IP")
		packet_bytes = get_pcap("tests/packets_dns.pcap")

		# IP without body
		ip1_bytes = packet_bytes[0][14:]
		ip1 = ip.IP(ip1_bytes)
		self.assertEqual(ip1.bin(), ip1_bytes)
		self.assertEqual(ip1.src_s, "192.168.178.22")
		self.assertEqual(ip1.dst_s, "192.168.178.1")
		print("src: %s" % ip1.src_s)
		# header field udpate
		src = "1.2.3.4"
		dst = "4.3.2.1"
		print(ip1)
		ip1.src_s = src
		ip1.dst_s = dst
		self.assertEqual(ip1.src_s, src)
		self.assertEqual(ip1.dst_s, dst)
		self.assertEqual(ip1.direction(ip1), pypacker.Packet.DIR_SAME)

		print(">>> checksum")
		ip2 = ip.IP(ip1_bytes)
		ip2.bin()
		print("IP sum 1 (original): %s" % ip2.sum)
		print("IP len 1 (original): %d" % ip2.len)
		print("IP hl 1 (original): %d" % ip2.hl)
		self.assertEqual(ip2.sum, 0x8e60)
		print("setting protocol")
		ip2.p = 6
		ip2.bin()
		print("IP sum 2: %s" % ip2.sum)
		print("IP len 2: %d" % ip2.len)
		print("IP hl 2: %d" % ip2.hl)

		self.assertEqual(ip2.sum, 36459)
		ip2.p = 17
		ip2.bin()
		print("IP sum 3: %s" % ip2.sum)
		self.assertEqual(ip2.sum, 0x8e60)

		print("IP options..")
		# IP + options
		ip3_bytes = b"\x49" + packet_bytes[0][15:34]
		ip3_opt_bytes = b"\x03\04\x00\x07" + b"\x09\03\x07" + b"\x01"
		ip3_bytes_opts = ip3_bytes + ip3_opt_bytes
		# print(ip3_bytes)
		# print(ip3_opt_bytes)
		ip3 = ip.IP(ip3_bytes_opts)
		# print(ip3)

		print("opts 1")

		for o in ip3.opts:
			print(o)

		# print(ip3.bin(update_auto_fields=False))
		# print(ip3_bytes_opts)

		self.assertEqual(ip3.bin(update_auto_fields=False), ip3_bytes_opts)
		del ip3.opts[2]
		self.assertEqual(len(ip3.opts), 2)
		self.assertEqual(ip3.opts[0].type, 3)
		self.assertEqual(ip3.opts[0].len, 4)
		print("body bytes: %s" % ip3.opts[0].bin())
		self.assertEqual(ip3.opts[0].bin(), b"\x03\04\x00\x07")

		print("opts 2")
		for o in ip3.opts:
			print(o)

		# ip3.opts.append((ip.IP_OPT_TS, b"\x00\x01\x02\x03"))
		ip3.opts.append(ip.IPOptMulti(type=ip.IP_OPT_TS, len=6, body_bytes=b"\x00\x01\x02\x03"))
		self.assertEqual(len(ip3.opts), 3)
		self.assertEqual(ip3.opts[2].type, ip.IP_OPT_TS)
		self.assertEqual(ip3.opts[2].len, 6)
		print(ip3.opts[2].body_bytes)
		self.assertEqual(ip3.opts[2].body_bytes, b"\x00\x01\x02\x03")

		print("opts 3")
		# ip3.opts.append((ip.IP_OPT_TS, b"\x00"))
		ip3.opts.append(ip.IPOptMulti(type=ip.IP_OPT_TS, len=4, body_bytes=b"\x00\x11"))
		self.assertEqual(len(ip3.opts), 4)

		totallen = 0
		for o in ip3.opts:
			totallen += len(o)
			print(o)

		print("ip len: 20+%d, in header: %d" % (totallen, (20 + totallen) / 4))
		print("header offset: %d" % ip3.hl)
		self.assertEqual(ip3.hl, 9)

	def test_ipoptmultichange(self):
		print_header("IP / OptMultiChange")
		ip1 = ip.IP()
		ip1.opts.append(ip.IPOptMulti(type=ip.IP_OPT_TS, len=6, body_bytes=b"\x00\x01\x02\x03"))
		self.assertEqual(ip1.opts[0].len, 6)
		ip1.opts[0].body_bytes = b"\x00\x00\x00"
		ip1.opts[0].bin()
		self.assertEqual(ip1.opts[0].len, 5)

	def test_fragmentation(self):
		print_header("IP / fragmentation")
		# fragmentation of 1000 gives 5 IP fragments
		ip1 = ip.IP() + tcp.TCP(body_bytes=b"A" * (4000 - 20))

		fragments = ip1.create_fragments(fragment_len=1000)
		self.assertEqual(len(fragments), 4)
		tcp_fragments = []

		for fragment in fragments:
			self.assertEqual(len(fragment.body_bytes), 1000)
			self.assertEqual(fragment.id, ip1.id)
			self.assertEqual(fragment.p, ip1.p)
			self.assertEqual(fragment.src, ip1.src)
			self.assertEqual(fragment.dst, ip1.dst)

			tcp_fragments.append(fragment.body_bytes)

		tcp_reassembled = b"".join(tcp_fragments)
		self.assertEqual(tcp_reassembled, ip1.upper_layer.bin())


class TCPTestCase(unittest.TestCase):
	def test_TCP(self):
		print_header("TCP")
		packet_bytes = get_pcap("tests/packets_ssl.pcap")

		# TCP without body
		tcp1_bytes = packet_bytes[0][34:66]
		tcp1 = tcp.TCP(tcp1_bytes)

		# parsing
		self.assertEqual(tcp1.bin(), tcp1_bytes)
		self.assertEqual(tcp1.sport, 37202)
		self.assertEqual(tcp1.dport, 443)
		# direction
		tcp2 = tcp.TCP(tcp1_bytes)
		tcp1.sport = 443
		tcp1.dport = 37202
		print("dir: %d" % tcp1.direction(tcp2))
		self.assertTrue(tcp1.is_direction(tcp2, pypacker.Packet.DIR_REV))
		# checksum (no IP-layer means no checksum change)
		tcp1.win = 1234
		self.assertEqual(tcp1.sum, 0x9c2d)
		# checksum (IP + TCP)
		ip_tcp_bytes = packet_bytes[0][14:]
		ip1 = ip.IP(ip_tcp_bytes)
		tcp2 = ip1[tcp.TCP]
		print(ip1.bin())
		print(ip_tcp_bytes)
		self.assertEqual(ip1.bin(), ip_tcp_bytes)

		print("sum 1: %X" % tcp2.sum)
		self.assertEqual(tcp2.sum, 0x9c2d)
		print("tcp: %r" % tcp2)
		print("tcp off: %r" % tcp2.off)
		win_original = tcp2.win
		tcp2.win = win_original
		tcp2.bin()
		self.assertEqual(tcp2.sum, 0xea57)

		tcp2.win = 0x0073
		tcp2.bin()

		print("sum 2: %X" % tcp2.sum)
		self.assertEqual(tcp2.sum, 0xea57)

		tcp2.win = win_original
		tcp2.bin()
		print("sum 3: %X" % tcp2.sum)
		self.assertEqual(tcp2.sum, 0xea57)

		# options
		print("tcp options: %d" % len(tcp2.opts))
		self.assertEqual(len(tcp2.opts), 3)
		self.assertEqual(tcp2.opts[2].type, tcp.TCP_OPT_TIMESTAMP)
		self.assertEqual(tcp2.opts[2].len, 10)
		print(tcp2.opts[2].header_bytes)
		print(tcp2.opts[2].bin())
		print(tcp2.opts[2].body_bytes)
		self.assertEqual(tcp2.opts[2].header_bytes, b"\x08\x0a")
		self.assertEqual(tcp2.opts[2].body_bytes, b"\x01\x0b\x5d\xb3\x21\x3d\xc7\xd9")

		print("adding option")
		# header length 20 + (12 + 8 options)
		tcp2.opts.append(
			tcp.TCPOptMulti(type=tcp.TCP_OPT_WSCALE, len=8, body_bytes=b"\x00\x01\x02\x03\x04\x05"))
		tcp2.bin()
		totallen = 0

		print("found the following options")
		for opt in tcp2.opts:
			totallen += len(opt)
			print(opt)
		self.assertEqual(len(tcp2.opts), 4)
		self.assertEqual(tcp2.opts[3].type, tcp.TCP_OPT_WSCALE)
		print("len is: 20+%d, hlen: %d" % (totallen, (20 + totallen) / 4))
		print("offset is: %s" % tcp2.off)
		self.assertEqual(tcp2.off, 10)


class UDPTestCase(unittest.TestCase):
	def test_UDP(self):
		print_header("UDP")
		packet_bytes = get_pcap("tests/packets_dns.pcap")

		ip_udp_bytes = packet_bytes[0][14:]
		ip1 = ip.IP(ip_udp_bytes)
		self.assertEqual(ip1.bin(), ip_udp_bytes)

		# UDP + DNS
		udp1 = ip1[udp.UDP]
		# parsing
		self.assertEqual(udp1.sport, 42432)
		self.assertEqual(udp1.dport, 53)
		# direction
		udp2 = ip.IP(ip_udp_bytes)[udp.UDP]
		print("direction: %d" % udp1.direction(udp2))
		self.assertTrue(udp1.is_direction(udp2, pypacker.Packet.DIR_SAME))
		# checksum
		self.assertEqual(udp1.sum, 0xf6eb)

		udp_bin = udp1.bin()
		print(udp1.ulen)
		udp1.dport = 53
		print(udp1)
		udp_bin = udp1.bin()
		print(udp1)
		print(udp1.ulen)
		print(udp_bin)
		print(udp1.sum)
		print("sum 1: %X" % udp1.sum)
		self.assertEqual(udp1.sum, 0xf6eb)

		# print("setting new port")
		udp1.dport = 1234
		udp1.bin()
		print("sum 2: %X" % udp1.sum)
		self.assertEqual(udp1.sum, 0xf24e)

		udp2 = ethernet.Ethernet() + ip.IP() + udp.UDP()
		udp2[udp.UDP].body_bytes = b"A" * 10
		udp2.bin()
		self.assertEqual(udp2[udp.UDP].sum, 0xDAD6)
		udp2[udp.UDP].body_bytes = b"A" * 11
		udp2.bin()
		self.assertEqual(udp2[udp.UDP].sum, 0x99D4)


class IP6TestCase(unittest.TestCase):
	def test_IP6(self):
		print_header("IPv6")
		packet_bytes = get_pcap("tests/packets_ip6.pcap")
		s = packet_bytes[0]
		print(s)

		eth = ethernet.Ethernet(s)
		print("> searching ip6 in ether")
		ip_6 = eth[ip6.IP6]
		print("> calling bin on eth")
		self.assertEqual(eth.bin(), s)
		print("> counting options")
		self.assertEqual(len(ip_6.opts), 1)
		self.assertEqual(len(ip_6.opts[0].opts), 2)
		self.assertEqual(ip_6.opts[0].opts[0].type, 5)
		self.assertEqual(ip_6.opts[0].opts[1].type, 1)

		pkt_eth_ip_tcp = ethernet.Ethernet() + ip6.IP6() + tcp.TCP()
		pkt_eth_ip_tcp.bin()
		ip6len_real = len(pkt_eth_ip_tcp.ip6.opts.bin()) + len(pkt_eth_ip_tcp.ip6.tcp.bin())
		# length should be updated
		self.assertEqual(pkt_eth_ip_tcp.ip6.dlen, ip6len_real)
		# header type should be updated
		self.assertEqual(pkt_eth_ip_tcp.ip6.nxt,
			pypacker.Packet.get_id_for_handlerclass(pkt_eth_ip_tcp.ip6.__class__,
				pkt_eth_ip_tcp.ip6.tcp.__class__))


class ChecksumTestCase(unittest.TestCase):
	def test_in_checksum(self):
		print_header("Internet checksum")
		# see packets_dns.py, packet 2
		udp = b"\x00\x35\xa5\xc0\x00\x62\x00\x00\x48\x5b\x81\x80\x00\x01\x00\x03\x00\x00\x00\x01" +\
			b"\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x02\x64\x65\x00\x00\x01\x00\x01\xc0" +\
			b"\x0c\x00\x01\x00\x01\x00\x00\x00\x55\x00\x04\xad\xc2\x23\x97\xc0\x0c\x00\x01\x00" +\
			b"\x01\x00\x00\x00\x55\x00\x04\xad\xc2\x23\x98\xc0\x0c\x00\x01\x00\x01\x00\x00\x00" +\
			b"\x55\x00\x04\xad\xc2\x23\x9f\x00\x00\x29\x05\xb4\x00\x00\x00\x00\x00\x00"
		pseudoheader = b"\xc0\xa8\xb2\x01\xc0\xa8\xb2\x16\x00\x11" + struct.pack(">H", len(udp))
		print(len(udp))
		csum = checksum.in_cksum(pseudoheader + udp)
		self.assertEqual(csum, 0x32bf)

	def test_fletcher_checksum(self):
		print_header("fletcher checksum")

		bts = b"\xff\xff\xff\xff"
		csum = checksum.fletcher32(bts, 2)
		self.assertEqual(csum, 4294967295)

		bts = b"\x00\x00\x00\x00"
		csum = checksum.fletcher32(bts, 2)
		self.assertEqual(csum, 4294967295)

		# C: 0x00010000 (uint32_t)
		bts = b"\x00\x00\x00\x01"
		csum = checksum.fletcher32(bts, 2)
		self.assertEqual(csum, 65537)

		# C: 0x00ff0000 (uint32_t)
		bts = b"\x00\x00\x00\xff"
		csum = checksum.fletcher32(bts, 2)
		self.assertEqual(csum, 16711935)


class HTTPTestCase(unittest.TestCase):
	def test_HTTP(self):
		print_header("HTTP")
		# HTTP header + body
		s1 = b"GET / HTTP/1.1\r\nHeader1: value1\r\nHeader2: value2\r\n\r\nThis is the body content\r\n"
		http1 = http.HTTP(s1)
		self.assertEqual(http1.bin(), s1)
		# header changes
		s2 = b"POST / HTTP/1.1\r\nHeader1: value1\r\nHeader2: value2\r\n\r\nThis is the body content\r\n"
		# print(">>> new startline POST")
		# print(">>> sep: %s" % http1.sep)
		# print(">>> http bin 1: %s" % http1.bin())
		# print(">>> sep: %s" % http1.sep)
		http1.startline = b"POST / HTTP/1.1\r\n"
		print(">>> sep: %s" % http1.sep)
		print(">>> New startline = %r" % http1.startline)
		print(">>> Now calling bin()")
		print(">>> http bin 2: %s" % http1.bin())
		print(">>> http bin 2: %r" % http1)
		self.assertEqual(http1.bin(), s2)
		self.assertEqual(http1.hdr[0][1], b"value1")
		print(">>> new startline GET")
		http1.startline = b"GET / HTTP/1.1\r\n"
		self.assertEqual(http1.bin(), s1)
		print(">>> resetting body")
		s3 = b"GET / HTTP/1.1\r\nHeader1: value1\r\nHeader2: value2\r\n\r\n"
		http1.body_bytes = b""
		print("http bin: %s" % http1.bin())
		self.assertEqual(http1.bin(), s3)
		# TODO: set ether + ip + tcp + http
		# print("HTTP headers: %s" % http1.headers)

		print("Parsing raw bytes: HTTP without header")
		raw = b'\xf4\xec8\xa8\xa0\xf2\x1coeN7\r\x08\x00E\x00\x05\x8cQk@\x00\x80\x06\xd7&\xc0\xa8\x01d\n\x00'\
			b'\x00\xce\xc5\xb9\x00PU\x06\xeaF\xf6g\xe5DP\x18\x01\x00\x03j\x00\x006\x007\x004\x00C\x001'\
			b'\x008\x00C\x007\x005\x009\x005\x00A\x00D\x003\x006\x00C\x00B\x005\x004\x00<\x00/\x00P\x00r'\
			b'\x00o\x00p\x00e\x00r\x00t\x00y\x00>\x00<\x00/\x00H\x00o\x00o\x00k\x002\x00>\x00<\x00/\x00H'\
			b'\x00o\x00o\x00k\x00s\x00>\x00<\x00P\x00a\x00y\x00l\x00o\x00a\x00d\x00 \x00T\x00y\x00p\x00e'\
			b'\x00=\x00"\x00i\x00n\x00l\x00i\x00n\x00e\x00"\x00/\x00>\x00<\x00T\x00a\x00r\x00g\x00e\x00t'\
			b'\x00H\x00o\x00s\x00t\x00>\x00S\x00R\x00V\x00-\x00S\x00C\x00C\x00M\x00.\x00d\x00c\x00k\x00a'\
			b'\x00i\x00.\x00r\x00u\x00<\x00/\x00T\x00a\x00r\x00g\x00e\x00t\x00H\x00o\x00s\x00t\x00>\x00<'\
			b'\x00T\x00a\x00r\x00g\x00e\x00t\x00E\x00n\x00d\x00p\x00o\x00i\x00n\x00t\x00>\x00M\x00P\x00_'\
			b'\x00R\x00e\x00l\x00a\x00y\x00E\x00n\x00d\x00p\x00o\x00i\x00n\x00t\x00<\x00/\x00T\x00a\x00r'\
			b'\x00g\x00e\x00t\x00E\x00n\x00d\x00p\x00o\x00i\x00n\x00t\x00>\x00<\x00R\x00e\x00p\x00l\x00y'\
			b'\x00M\x00o\x00d\x00e\x00>\x00A\x00s\x00y\x00n\x00c\x00<\x00/\x00R\x00e\x00p\x00l\x00y\x00M'\
			b'\x00o\x00d\x00e\x00>\x00<\x00P\x00r\x00o\x00t\x00o\x00c\x00o\x00l\x00>\x00h\x00t\x00t\x00p'\
			b'\x00<\x00/\x00P\x00r\x00o\x00t\x00o\x00c\x00o\x00l\x00>\x00<\x00/\x00M\x00s\x00g\x00>\x00'\
			b'\r\n--aAbBcCdDv1234567890VxXyYzZ\r\ncontent-type: application/octet-stream\r\n\r\nx\x9c\xed'\
			b'\x96[O\x1aQ\x10\xc7\xe7\xa3\x18^|h\x80\xdde+\xb4A\x1b\xb9l%\xd5\xd6Hm_\xfaB\x04\xd1\x14\xc4'\
			b'\x08^\xe8\x87o\xfb\x9b9\x0b\xec\xc5\x8a\xe9\xed\x89\x90\xb3;g.\xff3\xb73K]Nd \xd72\x91\x1b'\
			b'\x99\xc9\x9e\xd4S\xfb\x03\xe8\x9e\xf4y\xde\x98\xacc\xf4\x15\x92K9g\x9d!Uz\x02O\xe5G\xec\xcf'\
			b'\xe4\x02\xce\x15z\xcai\xca\x88\x9d\xb3\xe9\xf0\x9c\xf2\xee\xc1\x1b\xc1\xeb\xa3\xe1\xa3S^\xab'\
			b'\x95\xc6\xf9(s<\x1c<j\xbd\x92e\xcfn\xc1{+\xa7F\xbd\x96\x90g\x1b\x8d\x80g[<)JE\x1aP>T(\x91'\
			b'\xd4x\x16\xe1\xa8\x9eoT\x15\xed\x1a;\x8f_SvX\x11+\xef}+w\xf6\'\xcb\xdft\x99\xa7\x97R2\x94'\
			b'\x12x\x01\xe7\xbe\x82\xf2\x8d\xe3\xe5\xf0\xb2\xb6uy\x0fg\x86?\x1d\xf9 ]v=\x19[\xbc\'\xc4'\
			b'\xde\xc5S\x0f\xfc"\xcb\x03Yw.G\xbf\xb2RO\'V\xd5cxC\xe3\xd5\x88n\'\xf6$+\xabc=\xb7\xfa\x0c@'\
			b'h\xf1<Gv\x8b\xc739D\xdf\xc5\xaf\xd1\x84\xc4\xa5\x18\xcf\xd1W\xbd|\xef\x94\xd7\xf6[\xb2W['\
			b'\x16a\x0f\xe9\x88\xf3\xb2\xd2\xa6\xd9\xccb\xb4=\xbc\x9a\x808\x93{,n\xe0~\x91\x07\xcb\x7f'\
			b'\xc0:2$\xcd\xbb\xfa2L\xc9Z\xe6A\xcf\xbc{\n?}\xfa\xaa+#\x8b}\x94\xb3O\xf6\xad;C\xe9\xc0\xeaW'\
			b'\xb3Z\x06t\xa0\xcf/\xe4]\xa1>%\xa3+q\xdf\xbc\x88\xf5\x14we_\xcf\xf5\x8fo\xbd\xa7Z\xf9\xce'\
			b'\x8a\xcc\x97\xb1Y\'5\xd3\xfc\xac\xe7\xf9\xbc\x97\x9f\x9c!\xe5\xcc\xc4\x11\xf9\xf1\xbd.o\xc8'\
			b'\xf1\x18\x84-\xb9K\xf9\xb5+\xdb\xb1\'\xdb\xc84\xbbg\xd6\x93\xae2*=%w\x11\x9d\xee\x93\x93mp'\
			b'\xb2\xb9\xdf\xcc\xb4\xcdL\xdb\xcc\xb4\xcdL\xfb\x973-)kX\x7f\xcd\x8d\x7f\x0cGw\xb7T\xd9M\x81s'\
			b'\xf6[\x96\xd91\x16=8\xf3e\xe7\xeeJ\x81\x93;\xe4\xadHf\x02z\xad\x80n\x1a#\xa9\xfb9u\xab\xf2'\
			b'\xba\xe9l\xa8\x85\x8b\x7f\xb1\xf2\x16\x87\xe6\xd1\x90\x9d\xbb\x1b\xce\xc6\xf5}!\xbe)\xe9'\
			b'\x1e\x8b,G\x83Dl\x0b\x8e\xe6p\n\xaav\xdc\xf5\xb2\xc3\x15\xf1\x10jh}XDS\xe9\t\'\xce\xb0\x1d'\
			b'\x9b\xce%\xb4\xe6\xb2\x90@{N,\x0b\xddd\x8e\xee\xf1`\x95\xa3\x12\xef\x07VR\xbb\xcb\xfb['\
			b'\xac\xad]\xa8\xbd\x18\x18\xa2\xc6{\x80t\x1a\xfb\xe3\xee\xea(q\x97\x167g+\xc1\xd3\xe9\xbe'\
			b'\xe0\xeb$p\xb8:\x7f\xab\xfc\xda\x96O\x9d\xbd\x81\xf1t27\x98l\xb5\x98\xd76\x9ez\xa13/\x92}'\
			b'\x10\xaa\xbc}*\xd00\xbfO\xf1G\xcfIwMS\xde\xa1\xdb\xe1^\x9f\xa0\xdd\xc0\xd7\xafHoy^\xc4z}b'\
			b'\xb83\x84\xae\xf9\xe6n\xe8\xe5\x12\xe3\xb1{\xe9\xd97\xa3\x1a\xcfv/s/\x15\xabM^\xfbkqV\xf7;'\
			b'\xb09\x9c\xc7q>\xcd\xf0xj(\x958\xff\xe5gV\xe0\xef\xd5j\x9f\xfc\x85\xf1W\xb4j\xb5\xf2-\x8a'\
			b'\x96\xd5\xaa\x82\xc7\x91\xd5J\xe7f`_\xa5\x00N\xdb\xbe\xbd!R\xfd5\xcd\xff\xffU\xab\x1d\xeb'\
			b'\x0e\xcffF\xf8\x07\xb5r8\x15Cy\n\'[\xab\xe07jU^;I\x9c\xd6\xe3\x134?\x91\x93S7\xfb\x0f\xf3'\
			b'\'\x1e\xa4j\x16\r\n--aAbBcCdDv1234567890VxXyYzZ--'
		eth = ethernet.Ethernet(raw)
		pkt_ip = eth.ip
		pkt_tcp = pkt_ip.tcp
		pkt_http = pkt_tcp.http


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
		self.assertEqual(p_all.bin(), bytes_eth_ip_tcp_tn)
		print()
		print(">>> Ascending layers from full bytes:")
		print(p_all)
		print(p_all.upper_layer)
		print(p_all.upper_layer.upper_layer)
		print(p_all.upper_layer.upper_layer.upper_layer)

		print()
		print(">>> Creating layers from bytes")
		print(">> eth")
		eth1 = ethernet.Ethernet(l_eth)
		self.assertEqual(l_eth, eth1.bin())
		print(">> ip")
		ip1 = ip.IP(l_ip)
		self.assertEqual(l_ip, ip1.bin())
		print(">> tcp")
		tcp1 = tcp.TCP(l_tcp)
		self.assertEqual(l_tcp, tcp1.bin())
		print("tcp bytes: %s" % l_tcp)
		print(tcp1.opts)
		print(">> telnet")
		tn1 = telnet.Telnet(l_tn)
		self.assertEqual(l_tn, tn1.bin())

		print()
		print(">>> Comparing types")
		self.assertEqual(type(p_all[ethernet.Ethernet]), type(eth1))
		self.assertEqual(type(p_all[ip.IP]), type(ip1))
		self.assertEqual(type(p_all[tcp.TCP]), type(tcp1))
		self.assertEqual(type(p_all[telnet.Telnet]), type(tn1))

		print()
		print(">>> Comparing assembled bytes")
		# clean parsed = reassembled
		bytes_concat = [eth1.bin(), ip1.bin(), tcp1.bin(), tn1.bin()]
		self.assertEqual(p_all.bin(), b"".join(bytes_concat))

		p_all_concat = eth1 + ip1 + tcp1 + tn1
		# p_all.bin()
		# p_all_concat.bin()
		print(p_all[ethernet.Ethernet])
		print(p_all_concat[ethernet.Ethernet])
		print("--------------")
		print(p_all[ip.IP])
		print(p_all_concat[ip.IP])
		print("--------------")
		print(p_all[tcp.TCP])
		print(p_all_concat[tcp.TCP])
		print("--------------")
		print(p_all[telnet.Telnet])
		print(p_all_concat[telnet.Telnet])
		print("--------------")

		self.assertEqual(p_all.bin(), bytes_eth_ip_tcp_tn)
		self.assertEqual(p_all.bin(), p_all_concat.bin())

		print()
		print(">>> Testing keyword construction")
		# create layers using keyword-constructor
		eth2 = ethernet.Ethernet(dst=eth1.dst, src=eth1.src, type=eth1.type)
		ip2 = ip.IP(v_hl=ip1.v_hl, tos=ip1.tos, len=ip1.len, id=ip1.id, off=ip1.off, ttl=ip1.ttl, p=ip1.p,
			sum=ip1.sum, src=ip1.src, dst=ip1.dst)
		tcp2 = tcp.TCP(sport=tcp1.sport, dport=tcp1.dport, seq=tcp1.seq, ack=tcp1.ack, off_x2=tcp1.off_x2,
			flags=tcp1.flags, win=tcp1.win, sum=tcp1.sum, urp=tcp1.urp)
		self.assertEqual(tcp1.off_x2, tcp2.off_x2)

		for opt in ip1.opts:
			print("adding ip option: %s" % opt)
		totallen = 0
		for opt in tcp1.opts:
			print("adding tcp option: %s" % opt)
			tcp2.opts.append(opt.bin())  # use raw bytes instead packets, must work
			totallen += len(opt)
		print("total length: 20+%d" % totallen)

		self.assertEqual(tcp1.off_x2, tcp2.off_x2)

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
		self.assertEqual(p_all2.bin(), p_all.bin())


class IterateTestCase(unittest.TestCase):
	def test_iter(self):
		print_header("ITERATE")
		bts_list = get_pcap("tests/packets_ssl.pcap")

		for bts in bts_list:
			eth1 = ethernet.Ethernet(bts)
			# TODO: tcp not parsed/shown using %r?
			# print("%r" % eth1.ip.tcp)

			for layer in eth1:
				print("Iterated Layer: %r" % layer)
			print()


class SimpleFieldActivateDeactivateTestCase(unittest.TestCase):
	def test_static(self):
		print_header("static fields active/inactive")
		eth1 = ethernet.Ethernet(dst_s="00:11:22:33:44:55", src_s="11:22:33:44:55:66",
			vlan=b"\x22\x22\x22\x22",
			type=0)
		self.assertEqual(eth1.vlan[0], b"\x22\x22\x22\x22")
		del eth1.vlan[:]
		print(eth1.bin())
		self.assertEqual(eth1.bin(), b"\x00\x11\x22\x33\x44\x55\x11\x22\x33\x44\x55\x66\x00\x00")
		eth1 = ethernet.Ethernet(dst_s="00:11:22:33:44:55", src_s="11:22:33:44:55:66", type=0)
		eth1.vlan = b"\x22\x22\x22\x23"
		eth1.src = None
		eth1.dst = None
		eth1.type = None
		print(eth1.bin())
		self.assertEqual(eth1.bin(), b"\x22\x22\x22\x23")


class TriggerListTestCase(unittest.TestCase):
	def test_dynamicfield(self):
		print_header("dynamic fields")
		eth1 = ethernet.Ethernet() + ip.IP() + tcp.TCP()
		tcp1 = eth1[tcp.TCP]
		# find packets
		del tcp1.opts[:]
		tcp1.opts.extend([tcp.TCPOptMulti(type=0, len=3, body_bytes=b"\x00\x11\x22"), tcp.TCPOptSingle(type=1),
			tcp.TCPOptSingle(type=2)])
		self.assertEqual(tcp1.opts.find_pos(lambda v: v.type == 2), 2)

		tcp1.opts.extend([(b"key1", b"value1"), (b"key2", b"value2")])
		idx, res = tcp1.opts.get_by_key(b"key1")
		self.assertEqual(res, b"value1")
		idx, res = tcp1.opts.get_by_key(b"key2")
		self.assertEqual(res, b"value2")
		tcp1.opts.set_by_key(b"key1", b"value1b")
		tcp1.opts.set_by_key(b"key2", b"value2b")
		idx, res = tcp1.opts.get_by_key(b"key1")
		self.assertEqual(res, b"value1b")
		idx, res = tcp1.opts.get_by_key(b"key2")
		self.assertEqual(res, b"value2b")


class ICMPTestCase(unittest.TestCase):
	def test_icmp(self):
		print_header("ICMP")
		bts = get_pcap("tests/packets_icmp.pcap", 1)[0]
		print(bts)
		eth = ethernet.Ethernet(bts)
		print(eth)
		print(eth[ip.IP])
		self.assertEqual(eth.bin(), bts)
		icmp1 = eth[icmp.ICMP]
		print(str(icmp1))
		self.assertEqual(icmp1.type, 8)
		# checksum handling
		print("sum 1: %d" % icmp1.sum)  # 0xEC66 = 22213
		self.assertEqual(icmp1.sum, 0x425c)
		self.assertEqual(icmp1.echo.seq, 2304)
		print("code 1: %d" % icmp1.code)
		icmp1.code = 123
		print("code 2: %d" % icmp1.code)
		eth.bin()
		print("code 3: %d" % icmp1.code)
		self.assertNotEqual(icmp1.sum, 0x425c)
		icmp1.code = 0
		icmp1 = eth[icmp.ICMP]
		eth.bin()
		self.assertEqual(icmp1.sum, 0x425c)


class ICMP6TestCase(unittest.TestCase):
	def test_icmp6(self):
		print_header("ICMP6")
		bts_list = get_pcap("tests/packets_icmp6.pcap")

		for cnt, bts in enumerate(bts_list):
			# remove shitty VSS trailer
			if cnt > 0:
				bts = bts[:-2]

			eth1 = ethernet.Ethernet(bts)
			eth1.dissect_full()
			self.assertEqual(bts, eth1.bin())

			eth1.ip6.src = eth1.ip6.src
			if cnt > 0:
				self.assertEqual(eth1.ip6.src, eth1.ip6.dst)

			self.assertEqual(bts, eth1.bin())


class OSPFTestCase(unittest.TestCase):
	def test(self):
		print_header("OSPF")
		bts = get_pcap("tests/packets_ospf.pcap", 1)[0]

		eth = ethernet.Ethernet(bts)
		self.assertEqual(eth.bin(), bts)
		self.assertIsNotNone(eth[ethernet.Ethernet])
		self.assertIsNotNone(eth[ip.IP])
		self.assertIsNotNone(eth[ospf.OSPF])


class PPPTestCase(unittest.TestCase):
	def test_ppp(self):
		print_header("PPP")
		# src="10.0.2.15", dst="10.32.194.141", type=6 (TCP)
		BYTES_IP = b"\x45\x00\x00\xff\xc5\x78\x40\x00\x40\x06\x9c\x81\x0a\x00\x02\x0f\x0a\x20\xc2\x8d"

		s = b"\x21" + BYTES_IP
		ppp1 = ppp.PPP(s)
		self.assertEqual(ppp1.bin(), s)
		self.assertEqual(type(ppp1[ip.IP]).__name__, "IP")


class STPTestCase(unittest.TestCase):
	def test_stp(self):
		print_header("STP")
		s = b"AABCDEEEEEEEEFFFFGGGGGGGGHHIIJJKKLL"
		stp1 = stp.STP(s)
		self.assertEqual(stp1.bin(), s)


class VRRPTestCase(unittest.TestCase):
	def test_vrrp(self):
		print_header("VRRP")
		s = b"ABCDEFGG"
		vrrp1 = vrrp.VRRP(s)
		self.assertEqual(vrrp1.bin(), s)


class IGMPTestCase(unittest.TestCase):
	def test_igmp(self):
		print_header("IGMP")
		s = b"ABCCDDDD"
		igmp1 = igmp.IGMP(s)
		self.assertEqual(igmp1.bin(), s)


class IPXTestCase(unittest.TestCase):
	def test_ipx(self):
		print_header("IPX")
		s = b"AABBCDEEEEEEEEEEEEFFFFFFFFFFFF"
		ipx1 = ipx.IPX(s)
		self.assertEqual(ipx1.bin(), s)


class PIMTestCase(unittest.TestCase):
	def test_ipx(self):
		print_header("PIM")
		s = b"ABCC"
		pim1 = pim.PIM(s)
		self.assertEqual(pim1.bin(), s)


class HSRPTestCase(unittest.TestCase):
	def test_hsrp(self):
		print_header("HSRP")
		s = b"ABCDEFGHIIIIIIIIJJJJ"
		hsrp1 = hsrp.HSRP(s)
		self.assertEqual(hsrp1.bin(), s)


class DHCPTestCase(unittest.TestCase):
	def test_dhcp(self):
		print_header("DHCP")
		# this is a DHCP-Discover
		s = get_pcap("tests/packets_dhcp.pcap", 1)[0]
		eth = ethernet.Ethernet(s)
		self.assertEqual(s, eth.bin())
		print("DHCP type: %s" % type(eth[dhcp.DHCP]).__name__)
		self.assertEqual(type(eth[dhcp.DHCP]).__name__, "DHCP")
		dhcp2 = eth[dhcp.DHCP]
		print("%r" % dhcp2)
		self.assertEqual(len(dhcp2.opts), 6)
		self.assertEqual(dhcp2.opts[0].type, 0x35)
		self.assertEqual(dhcp2.opts[1].type, 0x3d)

		eth = ethernet.Ethernet(s)
		dhcp2 = eth[dhcp.DHCP]
		# TODO: use "append/extend"
		# dhcp2.opts += [(dhcp.DHCP_OPT_TCPTTL, b"\x00\x01\x02")]
		# dhcp2.opts.insert(4, (dhcp.DHCP_OPT_TCPTTL, b"\x00\x01\x02"))
		dhcp2.opts.insert(4, dhcp.DHCPOpt(type=dhcp.DHCP_OPT_TCPTTL, len=5, body_bytes=b"\x00\x01\x02"))
		print("new TLlen: %d" % len(dhcp2.opts))
		self.assertEqual(len(dhcp2.opts), 7)
		self.assertEqual(dhcp2.opts[4].type, dhcp.DHCP_OPT_TCPTTL)


class StunTestCase(unittest.TestCase):
	def test_stun(self):
		print_header("STUN")
		packet_bytes = get_pcap("tests/packets_stun.pcap")

		eth1 = ethernet.Ethernet(packet_bytes[0])
		stun1 = eth1.highest_layer
		print("%r" % stun1)
		self.assertEqual(stun1.type, 1)
		self.assertEqual(stun1.len, 92)
		self.assertEqual(len(stun1.attrs), 5)


class TFTPTestCase(unittest.TestCase):
	def test_tftp(self):
		print_header("TFTP")
		packet_bytes = get_pcap("tests/packets_tftp.pcap")

		for bts in packet_bytes:
			eth1 = ethernet.Ethernet(bts)
			tftp = eth1.highest_layer


# print("%r" % tftp)


class DNSTestCase(unittest.TestCase):
	def test_dns(self):
		print_header("DNS")
		packet_bytes = get_pcap("tests/packets_dns.pcap")

		print()
		print(">>> DNS 1")
		dns1 = ethernet.Ethernet(packet_bytes[0])[dns.DNS]
		print(dns1.bin())
		print(packet_bytes[0][42:])
		self.assertEqual(dns1.bin(), packet_bytes[0][42:])
		self.assertEqual(len(dns1.queries), 1)
		self.assertEqual(len(dns1.answers), 0)
		self.assertEqual(len(dns1.auths), 0)
		self.assertEqual(len(dns1.addrecords), 1)
		print()
		print(">>> DNS 2")
		dns2 = ethernet.Ethernet(packet_bytes[1])[dns.DNS]
		print("---> checking bin")
		print(dns2.queries[0]._name_format)
		self.assertEqual(dns2.bin(), packet_bytes[1][42:])
		print("---> checking repr")
		print(dns2.queries[0]._name_format)
		print("%s" % dns2)
		self.assertEqual(len(dns2.queries), 1)
		self.assertEqual(len(dns2.answers), 3)
		self.assertEqual(len(dns2.auths), 0)
		self.assertEqual(len(dns2.addrecords), 1)
		print()
		print(">>> DNS 3")
		print("---> checking bin")
		dns3 = ethernet.Ethernet(packet_bytes[2])[dns.DNS]
		self.assertEqual(dns3.bin(), packet_bytes[2][42:])
		print("---> checking str")
		print("%s" % dns3)
		self.assertEqual(len(dns3.queries), 1)
		self.assertEqual(len(dns3.answers), 0)
		self.assertEqual(len(dns3.auths), 1)
		self.assertEqual(len(dns3.addrecords), 0)

		dns_string = "www.test1.test2.de."
		dns_bytes = b"\x03www\x05test1\x05test2\x02de\x00"
		dns3.queries[0].name_s = dns_string
		self.assertEqual(dns_bytes, dns3.queries[0].name)
		dns3.queries[0].name = dns_bytes
		self.assertEqual(dns_string, dns3.queries[0].name_s)

		print()
		print(">>> DNS 4")
		packet_bytes = get_pcap("tests/packets_dns3.pcap")

		for bts in packet_bytes:
			dns2 = ethernet.Ethernet(bts)[dns.DNS]


class NTPTestCase(unittest.TestCase):
	def test_ntp(self):
		print_header("NTP")
		# NTP, port=123 (0x7B)
		# sport=38259, dport=53
		BYTES_UDP = b"\x95\x73\x00\x35\x00\x23\x81\x49"
		BYTES_NTP = BYTES_UDP[:3] + b"\x7B" + BYTES_UDP[4:] +\
			b"\x24\x02\x04\xef\x00\x00\x00\x84\x00\x00\x33\x27" +\
			b"\xc1\x02\x04\x02\xc8\x90\xec\x11\x22\xae\x07\xe5\xc8\x90\xf9\xd9\xc0\x7e\x8c\xcd\xc8" +\
			b"\x90" +\
			b"\xf9\xd9\xda\xc5" +\
			b"\xb0\x78\xc8\x90\xf9\xd9\xda\xc6\x8a\x93"
		s = BYTES_NTP
		n = udp.UDP(s)
		self.assertEqual(s, n.bin())
		n = n[ntp.NTP]
		print("NTP flags 1")
		print(n)
		self.assertEqual(n.li, ntp.NO_WARNING)
		self.assertEqual(n.v, 4)
		self.assertEqual(n.mode, ntp.SERVER)
		self.assertEqual(n.stratum, 2)
		self.assertEqual(n.id, b"\xc1\x02\x04\x02")

		# test get/set functions
		print("NTP flags 2")
		n.li = ntp.ALARM_CONDITION
		n.v = 3
		n.mode = ntp.CLIENT
		self.assertEqual(n.li, ntp.ALARM_CONDITION)
		self.assertEqual(n.v, 3)
		self.assertEqual(n.mode, ntp.CLIENT)


class RIPTestCase(unittest.TestCase):
	def test_rip(self):
		# RIP
		BYTES_RIP = b"\x02\x02\x00\x00\x00\x02\x00\x00\x01\x02\x03\x00\xff\xff\xff\x00\x00\x00\x00\x00\x00"\
			b"\x00" +\
			b"\x00\x01\x00\x02\x00\x00\xc0\xa8\x01\x08\xff\xff\xff\xfc\x00\x00\x00\x00\x00\x00" +\
			b"\x00\x01"
		s = BYTES_RIP
		print_header("RIP")
		r = rip.RIP(s)
		self.assertEqual(s, r.bin())
		print("amount auth/rte: %d" % len(r.rte_auth))
		self.assertEqual(len(r.rte_auth), 2)

		rte = r.rte_auth[1]
		self.assertEqual(rte.family, 2)
		self.assertEqual(rte.route_tag, 0)
		self.assertEqual(rte.metric, 1)


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
		self.assertEqual(eth_ip_sct.bin(), sct1_bytes)
		# checksum (CRC32)
		# print("sctp sum1: %X" % sct.sum)
		# self.assertTrue(sct.sum == 0x6db01882)

		# print(sct)
		# sct.vtag = sct.vtag
		# print("sctp sum3: %X" % sct.sum)
		# print(sct)
		# self.assertTrue(sct.sum == 0x6db01882)

		self.assertEqual(sct.sport, 16384)
		self.assertEqual(sct.dport, 2944)
		self.assertEqual(len(sct.chunks), 1)

		chunk = sct.chunks[0]
		self.assertEqual(chunk.type, sctp.DATA)
		self.assertEqual(chunk.len, 91)
		# dynamic fields
		# sct.chunks.append((sctp.DATA, 0xff, b"\x00\x01\x02"))
		sct.chunks.append(sctp.Chunk(type=sctp.DATA, flags=0xff, len=8, body_bytes=b"\x00\x01\x02\x03"))
		self.assertEqual(len(sct.chunks), 2)
		self.assertEqual(sct.chunks[1].body_bytes, b"\x00\x01\x02\x03")
		# lazy init of chunks
		sct2 = sctp.SCTP()
		sct2.chunks.append((sctp.DATA, 0xff, b"\x00\x01\x02\x03"))
		self.assertEqual(len(sct2.chunks), 1)


class ReaderTestCase(unittest.TestCase):
	def test_reader(self):
		print_header("pcap reader")
		reader = ppcap.Reader("tests/packets_ether.pcap")

		cnt = 0
		# HTTP found = TCP having payload!
		proto_cnt = {arp.ARP: 4, tcp.TCP: 34, udp.UDP: 4, icmp.ICMP: 7, http.HTTP: 12}

		for ts, buf in reader:
			if cnt == 0:
				# check timestamp (big endian)
				self.assertEqual(ts, (0x5118d5d0 * 10 ** 9) + 335929000)

			cnt += 1
			# print("%02d TS: %.40f LEN: %d" % (cnt, ts, len(buf)))
			eth = ethernet.Ethernet(buf)
			keys = proto_cnt.keys()

			for k in keys:
				if eth[k] is not None:
					proto_cnt[k] -= 1

		self.assertEqual(cnt, 49)

		print("proto summary:")
		for k, v in proto_cnt.items():
			print("%s: %s" % (k.__name__, v))
			self.assertEqual(v, 0)

		reader.close()
		reader = ppcap.Reader("tests/packets_ether.pcap")
		# test resetting and reading by indices
		cnt = 0

		for ts, pkt in reader:
			cnt += 1
		self.assertEqual(cnt, 49)

		"""
		pkts = reader.get_by_indices([0, 1, 2, 3])
		self.assertEqual(len(pkts), 4)

		pkts = reader.get_by_indices([4, 5, 6, 7, 10, 17, 23, 42])
		self.assertEqual(len(pkts), 8)

		pkts = reader.get_by_indices([4, 5, 6, 7, 10, 17, 23, 42, 100, 9999])
		self.assertEqual(len(pkts), 8)
		"""
		cnt = 0

		for ts, pkt in reader:
			cnt += 1
		reader.close()
		self.assertRaises(StopIteration, reader.__iter__().__next__)


# TODO: broken
"""
class ReaderNgTestCase(unittest.TestCase):
	def test_reader(self):
		print_header("pcapng reader")
		png_reader = pcapng.Reader(filename="tests/packets_ether.pcapng")

		cnt = 0
		proto_cnt = {
			arp.ARP: 4,
			tcp.TCP: 34,
			udp.UDP: 4,
			icmp.ICMP: 7,
			http.HTTP: 12		# HTTP found = TCP having payload!
		}

		for ts, buf in png_reader:
			cnt += 1
			# print("%02d TS: %.40f LEN: %d" % (cnt, ts, len(buf)))
			eth = ethernet.Ethernet(buf)
			keys = proto_cnt.keys()

			for k in keys:
				if eth[k] is not None:
					proto_cnt[k] -= 1

		png_reader.close()
		self.assertEqual(cnt, 49)

		print("proto summary:")
		for k, v in proto_cnt.items():
			print("%s: %s" % (k.__name__, v))
			self.assertEqual(v, 0)


class ReaderPcapNgTestCase(unittest.TestCase):
	def test_reader(self):
		print_header("READER PCAP-NG File format")
		import os
		print(os.getcwd())
		f = open("tests/packets_ether2.pcapng", "r+b")
		pcap = pcapng.Reader(f)

		print("Section Header Block Start")
		print("  Block Type:", hex(pcap.shb.type))
		print("  Block Total Length:", pcap.shb.block_length)
		print("  Byte-Order Magic:", hex(pcap.shb.magic))
		print("  Major Version:", hex(pcap.shb.v_major))
		print("  Minor Version:", hex(pcap.shb.v_minor))
		print("  Section Length:", hex(pcap.shb.section_length))
		print("  Option header")

		for opt in pcap.shb.opts:
			print("    {}({}): {}".format(pcapng.SHB_OPTIONS.get(opt.code), opt.code, opt.data))
		print("Section Header Block End")

		for idb in pcap.idbs:
			print("Interface Description Block Start")
			print("  Block Type:", hex(idb.type))
			print("  Block Total Length:", idb.block_length)
			print("  LinkType:", hex(idb.linktype))
			print("  Reserved:", hex(idb.reserved))
			print("  SnapLen:", idb.snaplen)
			print("  Option header")
			for opt in idb.opts:
				print("    {}({}): {}".format(pcapng.IDB_OPTIONS.get(opt.code), opt.code, opt.data))
			print("Interface Description Block End")

		for isb in pcap.isbs:
			print("Interface Statistics Block Start")
			print("  Block Type:", hex(isb.type))
			print("  Block Total Length:", isb.block_length)
			print("  Interface ID:", hex(isb.interface_id))
			print("  Timestamp(high):", hex(isb.ts_high))
			print("  Timestamp(Low):", hex(isb.ts_low))
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
			# print("  Hexdump:")
			# pypacker.hexdump(epb.data)
		print("Enhanced Packet Block End")

		self.assertEqual(count, 2)
"""


class ReadWriteReadTestCase(unittest.TestCase):
	def test_read_write(self):
		print_header("pcap READ -> WRITE -> READ")
		filename_read = "tests/packets_ether.pcapng"
		filename_write = "tests/packets_ether.pcapng_tmp"

		reader = ppcap.Reader(filename=filename_read, lowest_layer=ethernet.Ethernet)
		writer = ppcap.Writer(filename=filename_write)
		pkts_read = []

		for ts, pkt in reader.read_packet_iter():
			# should allready be fully dissected but we want to be sure..
			pkts_read.append(tuple([ts, pkt.bin()]))
			writer.write(pkt.bin(), ts=ts)

		writer.close()
		reader.close()

		reader = ppcap.Reader(filename=filename_write, lowest_layer=ethernet.Ethernet)

		for pos, ts_pkt in enumerate(reader.read_packet_iter()):
			# timestamp and bytes should not have been changed: input = output
			ts = ts_pkt[0]
			bts = ts_pkt[1].bin()

			self.assertEqual(ts, pkts_read[pos][0])
			self.assertEqual(bts, pkts_read[pos][1])
		reader.close()


class RadiotapTestCase(unittest.TestCase):
	def test_radiotap(self):
		print_header("Radiotap")
		# radiotap: flags, rate channel, dBm Antenna, Antenna, RX Flags
		s = b"\x00\x00\x12\x00\x2e\x48\x00\x00\x00\x02\x6c\x09\xa0\x00\xc2\x07\x00\x00\xff\xff"
		rad = radiotap.Radiotap(s)
		self.assertEqual(rad.bin(), s)
		print(rad)

		self.assertEqual(rad.version, 0)
		print("len: %d" % rad.len)
		self.assertEqual(rad.len, 4608)  # 0x1200 = 18
		self.assertEqual(rad.present_flags, 0x2e480000)
		# channel_bytes = rad.flags[bytes([radiotap.CHANNEL_MASK])][0][1]
		channel_bytes = rad.flags.find_value(lambda v: v[0] == radiotap.CHANNEL_MASK)[1]
		channel = radiotap.get_channelinfo(channel_bytes)

		print("channel: %d" % channel[0])
		print(type(channel[0]))
		self.assertEqual(channel[0], 2412)
		print("channel type: %s" % channel[1])
		self.assertEqual(channel[1], 160)
		print("flags: %x" % rad.present_flags)
		print("flags mask: %x" % radiotap.FLAGS_MASK)
		print("flags & flags mask: %x" % (rad.present_flags & radiotap.FLAGS_MASK))

		self.assertEqual(rad.present_flags & radiotap.TSFT_MASK, 0)
		self.assertNotEqual(rad.present_flags & radiotap.FLAGS_MASK, 0)
		self.assertNotEqual(rad.present_flags & radiotap.RATE_MASK, 0)


# self.assertTrue(len(rad.fields) == 7)


class BTLETestcase(unittest.TestCase):
	def test_crc(self):
		print_header("BTLE CRC")
		crc_reordered = checksum.crc_btle_init_reorder(0x555555)
		self.assertEqual(crc_reordered, 0xAAAAAA)

		# ADV data
		data = b"\xAA\xd6\xbe\x89\x8e\x04\x16\x3e\xab\xcf\xbc\xbd\x78\x0f\x08\x5b\x54\x56\x5d\x20" +\
			b"\x55\x45\x34\x38\x4a\x36\x32\x35\x30\xd0\x3e\xbf"
		crc_correct = checksum.crc_btle_check(data[1:], 0xAAAAAA)
		self.assertTrue(crc_correct)

	def test_btle_header(self):
		print_header("BTLE header")
		packet_bytes = get_pcap("tests/packets_btle.pcap")

		bts = packet_bytes[0]
		# print(">>> %d" % idx)
		btle_packet = btle.BTLEHdr(bts)
		repr = "%r" % btle_packet
		self.assertEqual(btle_packet.whitening, 1)
		self.assertEqual(btle_packet.sigvalid, 1)
		self.assertEqual(btle_packet.noisevalid, 1)
		self.assertEqual(btle_packet.decrypted, 0)
		self.assertEqual(btle_packet.refaavalid, 1)
		self.assertEqual(btle_packet.aaoffensesvalid, 1)
		self.assertEqual(btle_packet.chanalias, 0)
		self.assertEqual(btle_packet.crcchecked, 0)
		self.assertEqual(btle_packet.crcvalid, 0)
		self.assertEqual(btle_packet.micchecked, 0)
		self.assertEqual(btle_packet.micvalid, 0)

		btle_packet.whitening = 0
		btle_packet.sigvalid = 0
		btle_packet.noisevalid = 0
		btle_packet.decrypted = 1
		btle_packet.refaavalid = 0
		btle_packet.aaoffensesvalid = 0
		btle_packet.chanalias = 1
		btle_packet.crcchecked = 1
		btle_packet.crcvalid = 1
		btle_packet.micchecked = 1
		btle_packet.micvalid = 1

		self.assertEqual(btle_packet.whitening, 0)
		self.assertEqual(btle_packet.sigvalid, 0)
		self.assertEqual(btle_packet.noisevalid, 0)
		self.assertEqual(btle_packet.decrypted, 1)
		self.assertEqual(btle_packet.refaavalid, 0)
		self.assertEqual(btle_packet.aaoffensesvalid, 0)
		self.assertEqual(btle_packet.chanalias, 1)
		self.assertEqual(btle_packet.crcchecked, 1)
		self.assertEqual(btle_packet.crcvalid, 1)
		self.assertEqual(btle_packet.micchecked, 1)
		self.assertEqual(btle_packet.micvalid, 1)

	def test_chanmap(self):
		print_header("BTLE header")
		packet_bytes = get_pcap("tests/packets_btle_cm.pcap")
		bts = packet_bytes[0]
		# print(">>> %d" % idx)
		btle_packet = btle.BTLEHdr(bts)

		channels = btle_packet[btle.ConnRequest].get_active_channels()
		print(channels)
		channels_expected = [x for x in range(10, 20)] + [x for x in range(10, 37)]
		print(channels_expected)
		self.assertEqual(channels, channels_expected)

	def test_btle_packet(self):
		print_header("BTLE packets")
		packet_bytes = get_pcap("tests/packets_btle.pcap")

		for idx, bts in enumerate(packet_bytes):
			# print(">>> %d" % idx)
			btle_packet = btle.BTLEHdr(bts)
			repr = "%r" % btle_packet

	def test_btle_packet2(self):
		print_header("BTLE packets 2")
		packet_bytes = get_pcap("tests/packets_btle2.pcap")

		for idx, bts in enumerate(packet_bytes):
			# print(">>> %d" % idx)
			btle_packet = btle.BTLEHdr(bts)
			repr = "%r" % btle_packet

			if btle_packet.highest_layer.errors != 0:
				print("errors on Nr. %d" % idx)


class PerfTestCase(unittest.TestCase):
	def test_perf(self):
		# dst="52:54:00:12:35:02" src="08:00:27:a9:93:9e" type="0x08x00", type=2048
		BYTES_ETH = b"\x52\x54\x00\x12\x35\x02\x08\x00\x27\xa9\x93\x9e\x08\x00"
		# src="10.0.2.15", dst="10.32.194.141", type=6 (TCP)
		BYTES_IP = b"\x45\x00\x00\xff\xc5\x78\x40\x00\x40\x06\x9c\x81\x0a\x00\x02\x0f\x0a\x20\xc2\x8d"
		# sport=6667, dport=55211, win=46
		BYTES_TCP = b"\x1a\x0b\x00\x50\xb9\xb7\x74\xa9\xbc\x5b\x83\xa9\x80\x10\x00\x2e\xc0\x09\x00\x00" +\
			b"\x01\x01\x08\x0a\x28\x2b\x0f\x9e\x05\x77\x1b\xe3"
		# sport=38259, dport=53
		BYTES_UDP = b"\x95\x73\x00\x35\x00\x23\x81\x49"
		BYTES_HTTP = b"GET / HTTP/1.1\r\nHeader1: value1\r\nHeader2: value2\r\n\r\nThis is the body "\
			b"content\r\n"
		BYTES_ETH_IP_TCP_HTTP = BYTES_ETH + BYTES_IP + BYTES_TCP + BYTES_HTTP

		# IP + ICMP
		s = b"E\x00\x00T\xc2\xf3\x00\x00\xff\x01\xe2\x18\n\x00\x01\x92\n\x00\x01\x0b\x08\x00\xfc" +\
			b"\x11:g\x00\x00A,\xc66\x00\x0e\xcf\x12\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15" +\
			b"\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f!__$%&\'()*+,-./01234567"
		cnt = 10000
		print_header("Performance Tests")
		print("nr = new results on this machine")
		print("orC = old results (Intel Core2 Duo CPU @ 1,866 GHz, 2GB RAM, CPython v3.6)")
		print("orP = old results (Intel Core2 Duo CPU @ 1,866 GHz, 2GB RAM, Pypy 5.10.1)")
		print("rounds per test: %d" % cnt)
		print("=====================================")

		print(">>> parsing (IP + ICMP)")
		start = time.time()
		for i in range(cnt):
			ip1 = ip.IP(s)
		print("time diff: %ss" % (time.time() - start))
		print("nr = %d p/s" % (cnt / (time.time() - start)))
		print("orC = 86064 p/s")
		print("orP = 208346 p/s")

		print(">>> creating/direct assigning (IP only header)")
		start = time.time()
		for i in range(cnt):
			# ip = IP(src="1.2.3.4", dst="1.2.3.5").bin()
			# ip.IP(src=b"\x01\x02\x03\x04", dst=b"\x05\x06\x07\x08", p=17, len=1234, body_bytes=b"abcd")
			ip.IP(src=b"\x01\x02\x03\x04", dst=b"\x05\x06\x07\x08", p=17, len=1234)
		# ip = IP(src=b"\x01\x02\x03\x04", dst=b"\x05\x06\x07\x08", p=17, len=1234, body_bytes=b"abcd")
		print("time diff: %ss" % (time.time() - start))
		print("nr = %d p/s" % (cnt / (time.time() - start)))
		print("orC = 41623 p/s")
		print("orP = 59370 p/s")

		print(">>> bin() without change (IP)")
		ip2 = ip.IP(src=b"\x01\x02\x03\x04", dst=b"\x05\x06\x07\x08", p=17, len=1234, body_bytes=b"abcd")
		ip2.bin()
		start = time.time()

		for i in range(cnt):
			ip2.bin()
		print("time diff: %ss" % (time.time() - start))
		print("nr = %d p/s" % (cnt / (time.time() - start)))
		print("orC = 170356 p/s")
		print("orP = 292133 p/s")

		print(">>> output with change/checksum recalculation (IP)")
		ip3 = ip.IP(src=b"\x01\x02\x03\x04", dst=b"\x05\x06\x07\x08", p=17, len=1234, body_bytes=b"abcd")
		start = time.time()

		for i in range(cnt):
			ip3.src = b"\x01\x02\x03\x04"
			ip3.bin()
		print("time diff: %ss" % (time.time() - start))
		print("nr = %d p/s" % (cnt / (time.time() - start)))
		print("orC = 10104 p/s")
		print("orP = 23851 p/s")

		print(">>> basic/first layer parsing (Ethernet + IP + TCP + HTTP)")
		start = time.time()

		for i in range(cnt):
			eth = ethernet.Ethernet(BYTES_ETH_IP_TCP_HTTP)
		print("time diff: %ss" % (time.time() - start))
		print("nr = %d p/s" % (cnt / (time.time() - start)))
		print("orC = 62748 p/s")
		print("orP = 241047 p/s")

		print(">>> changing Triggerlist element value (Ethernet + IP + TCP + HTTP)")
		start = time.time()
		eth1 = ethernet.Ethernet(BYTES_ETH_IP_TCP_HTTP)
		tcp1 = eth1[tcp.TCP]
		# initiate TriggerList before performance test
		tmp = tcp1.opts[0].type

		for i in range(cnt):
			tcp1.opts[0].type = tcp.TCP_OPT_WSCALE
		print("time diff: %ss" % (time.time() - start))
		print("nr = %d p/s" % (cnt / (time.time() - start)))
		print("orC = 101552 p/s")
		print("orP = 201994 p/s")

		print(">>> changing Triggerlist/text based proto (Ethernet + IP + TCP + HTTP)")
		start = time.time()
		eth1 = ethernet.Ethernet(BYTES_ETH_IP_TCP_HTTP)
		http1 = eth1[http.HTTP]

		for i in range(cnt):
			http1.startline = b"GET / HTTP/1.1"
		print("time diff: %ss" % (time.time() - start))
		print("nr = %d p/s" % (cnt / (time.time() - start)))
		print("orC = 37249 p/s")
		print("orP = 272972 p/s")

		print(">>> direct assigning and concatination (Ethernet + IP + TCP + HTTP)")
		start = time.time()
		for i in range(cnt):
			concat = ethernet.Ethernet(dst_s="ff:ff:ff:ff:ff:ff", src_s="ff:ff:ff:ff:ff:ff") + ip.IP(
				src_s="127.0.0.1", dst_s="192.168.0.1") + tcp.TCP(sport=1234, dport=123) + http.HTTP()
		print("time diff: %ss" % (time.time() - start))
		print("nr = %d p/s" % (cnt / (time.time() - start)))
		print("orC = 7428 p/s")
		print("orP = 14315 p/s")

		print(">>> full packet parsing (Ethernet + IP + TCP + HTTP)")

		start = time.time()
		for i in range(cnt):
			p = ethernet.Ethernet(BYTES_ETH_IP_TCP_HTTP)
			p.dissect_full()

		print("time diff: %ss" % (time.time() - start))
		print("nr = %d p/s" % (cnt / (time.time() - start)))
		print("orC = 6886 p/s")
		print("orP = 17040 p/s")

		print(">>> Scapy and dpkt comparison: see dedicated performance scripts (Scapy needs Python 2)")


class IEEE80211TestCase(unittest.TestCase):
	def setUp(self):
		if hasattr(self, "packet_bytes"):
			return
		# print(">>>>>>>>> IEEE 802.11 <<<<<<<<<")
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

	def test_ack(self):
		print_header("ACK")
		# cut away RadioTap header
		rlen = self.packet_bytes[2][2]
		ieee = ieee80211.IEEE80211(self.packet_bytes[2][rlen:])
		self.assertEqual(ieee.bin(), self.packet_bytes[2][rlen:])
		self.assertEqual(ieee.version, 0)
		self.assertEqual(ieee.type, ieee80211.CTL_TYPE)
		self.assertEqual(ieee.subtype, ieee80211.C_ACK)
		self.assertEqual(ieee.to_ds, 0)
		self.assertEqual(ieee.from_ds, 0)
		self.assertEqual(ieee.pwr_mgt, 0)
		self.assertEqual(ieee.more_data, 0)
		self.assertEqual(ieee.protected, 0)
		self.assertEqual(ieee.order, 0)
		# print(ieee)
		self.assertEqual(ieee.ack.dst, b"\x00\xa0\x0b\x21\x37\x84")

	def test_beacon(self):
		print_header("Beacon")
		# cut away RadioTap header
		rlen = self.packet_bytes[0][2]
		ieee = ieee80211.IEEE80211(self.packet_bytes[0][rlen:])
		self.assertEqual(ieee.bin(), self.packet_bytes[0][rlen:])
		self.assertEqual(ieee.version, 0)
		self.assertEqual(ieee.type, ieee80211.MGMT_TYPE)
		self.assertEqual(ieee.subtype, ieee80211.M_BEACON)
		self.assertEqual(ieee.to_ds, 0)
		self.assertEqual(ieee.from_ds, 0)
		self.assertEqual(ieee.pwr_mgt, 0)
		self.assertEqual(ieee.more_data, 0)
		self.assertEqual(ieee.protected, 0)
		self.assertEqual(ieee.order, 0)
		beacon = ieee[ieee80211.IEEE80211.Beacon]
		self.assertEqual(beacon.dst, b"\xff\xff\xff\xff\xff\xff")
		self.assertEqual(beacon.src, b"\x24\x65\x11\x85\xe9\xae")
		self.assertEqual(beacon.bssid, b"\x24\x65\x11\x85\xe9\xae")
		print("%04x" % beacon.capa)
		self.assertEqual(beacon.seq_frag, 0x702D)
		self.assertEqual(beacon.capa, 0x3104)

	# self.assertTrue(beacon.capa == 0x0431)
	# TODO: test IEs
	# self.assertTrue(ieee.capability.privacy == 1)
	# self.assertTrue(ieee.mgmtframe.beacon.body_bytes == "CAEN")
	# self.assertTrue(ieee.rate.body_bytes == b"\x82\x84\x8b\x0c\x12\x96\x18\x24")
	# self.assertTrue(ieee.ds.body_bytes == b"\x01")
	# self.assertTrue(ieee.tim.body_bytes == b"\x00\x01\x00\x00")

	def test_data(self):
		print_header("Data")
		# cut away RadioTap header
		rlen = self.packet_bytes[5][2]
		ieee = ieee80211.IEEE80211(self.packet_bytes[5][rlen:])
		self.assertEqual(ieee.bin(), self.packet_bytes[5][rlen:])
		self.assertEqual(ieee.type, ieee80211.DATA_TYPE)
		self.assertEqual(ieee.subtype, ieee80211.D_NORMAL)
		self.assertEqual(ieee.protected, 1)
		self.assertEqual(ieee.dataframe.dst, b"\x01\x00\x5e\x7f\xff\xfa")
		self.assertEqual(ieee.dataframe.src, b"\x00\x1e\xe5\xe0\x8c\x06")
		self.assertEqual(ieee.dataframe.bssid, b"\x00\x22\x3f\x89\x0d\xd4")
		self.assertEqual(ieee.dataframe.seq_frag, 0x501e)
		print(ieee.dataframe.body_bytes)
		self.assertEqual(ieee.dataframe.body_bytes,
			b"\x62\x22\x39\x61\x98\xd1\xff\x34" +
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

	# llc_pkt = LLC(ieee.data_frame.body_bytes)
	# ip_pkt = ip.IP(llc_pkt.body_bytes)
	# self.assertTrue(ip_pkt.dst == b"\x3f\xf5\xd1\x69")

	def test_data_qos(self):
		print_header("Data QoS")
		# cut away RadioTap header
		rlen = self.packet_bytes[3][2]
		ieee = ieee80211.IEEE80211(self.packet_bytes[3][rlen:])
		self.assertEqual(ieee.bin(), self.packet_bytes[3][rlen:])
		self.assertEqual(ieee.type, ieee80211.DATA_TYPE)
		self.assertEqual(ieee.subtype, ieee80211.D_QOS_DATA)
		self.assertEqual(ieee.dataframe.bssid, b"\x24\x65\x11\x85\xe9\xae")
		self.assertEqual(ieee.dataframe.src, b"\x00\xa0\x0b\x21\x37\x84")
		self.assertEqual(ieee.dataframe.dst, b"\x24\x65\x11\x85\xe9\xac")
		self.assertEqual(ieee.dataframe.seq_frag, 0xd008)
		print(ieee.dataframe.body_bytes)
		self.assertEqual(ieee.dataframe.body_bytes,
			b"\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01" +
			b"\x08\x00\x06\x04\x00\x01\x00\xa0\x0b\x21\x37\x84\xc0\xa8\xb2\x16\x00\x00\x00\x00" +
			b"\x00\x00\xc0\xa8\xb2\x01")

	# self.assertTrue(ieee.qos_data.control == 0x0)

	def test_rtap_ieee(self):
		print_header("Radiotap IEEE 80211")
		rtap_ieee = radiotap.Radiotap(self.packet_bytes[0])
		self.assertEqual(rtap_ieee.bin(), self.packet_bytes[0])
		self.assertEqual(rtap_ieee.version, 0)
		print("len: %d" % rtap_ieee.len)
		self.assertEqual(rtap_ieee.len, 0x1200)  # 0x1200 = 18
		self.assertEqual(rtap_ieee.present_flags, 0x2e480000)

	def test_assoc_ieee(self):
		print_header("Assoc/Reassoc")
		packet_bytes = get_pcap("tests/packets_rtap_sel2.pcap")
		packets = []

		for bts in packet_bytes:
			rtap_ieee = radiotap.Radiotap(bts)
			self.assertEqual(rtap_ieee.bin(), bts)
			packets.append(rtap_ieee)

		for pkt in packets:
			ieeepkt = pkt.upper_layer.upper_layer
			self.assertEqual(ieeepkt.src, b"\x00" * 6)
			self.assertEqual(ieeepkt.dst, b"\x01" * 6)
			self.assertEqual(ieeepkt.bssid, b"\x02" * 6)


class DTPTestCase(unittest.TestCase):
	def test_DTP(self):
		print_header("DTP")
		s = b"\x01\x00\x01\x00\x08\x4c\x61\x62\x00\x00\x02\x00\x05\x04\x00\x03\x00\x05\x40\x00" +\
			b"\x04\x00\x0a\x00\x19\x06\xea\xb8\x85"
		dtp1 = dtp.DTP(s)
		self.assertEqual(dtp1.bin(), s)
		for tv in dtp1.tvs:
			print("%s" % tv)
		self.assertEqual(len(dtp1.tvs), 4)


class TelnetTestCase(unittest.TestCase):
	def test_telnet(self):
		print_header("Telnet")
		packet_bytes = get_pcap("tests/packets_telnet.pcap")

		eth = ethernet.Ethernet(packet_bytes[0])
		self.assertEqual(eth.bin(), packet_bytes[0])
		telnet1 = eth[telnet.Telnet]

		print(telnet1.bin())
		print(packet_bytes[0][66:])
		self.assertEqual(telnet1.bin(), packet_bytes[0][66:])


class PTPv2TestCase(unittest.TestCase):
	def test_ptpv2(self):
		print_header("PTPv2")
		packet_bytes = get_pcap("tests/packets_ptpv2_ether.pcap")

		for bts in packet_bytes:
			print("=====================")
			print("read %d bytes" % len(bts))
			eth1 = ethernet.Ethernet(bts)
			self.assertEqual(eth1.bin(), bts)

			# extract PTP layer: eth | PTP or eth | IP | UDP | PTP
			if eth1.type != 0x88F7:
				continue

			ptpv2_1 = eth1.upper_layer

			print("%r" % ptpv2_1)
			self.assertTrue(ptpv2_1.version, 2)


class SSLTestCase(unittest.TestCase):
	def test_ssl(self):
		print_header("SSL")
		packet_bytes = get_pcap("tests/packets_ssl.pcap")

		ssl1 = ssl.SSL(packet_bytes[0][66:])
		self.assertEqual(ssl1.bin(), packet_bytes[0][66:])
		# print(packet_bytes[0][66:])

		ssl2 = ssl.SSL(packet_bytes[1][66:])
		self.assertEqual(ssl2.bin(), packet_bytes[1][66:])
		# print(packet_bytes[1][66:])

		ssl3 = ssl.SSL(packet_bytes[2][66:])
		self.assertEqual(ssl3.bin(), packet_bytes[2][66:])
		# print(packet_bytes[2][66:])

		ssl4 = ssl.SSL(packet_bytes[3][66:])
		self.assertEqual(ssl4.bin(), packet_bytes[3][66:])

	# print(packet_bytes[3][66:])

	def test_cert_extract(self):
		print("SSL cert extract")
		packet_bytes = get_pcap("tests/packets_ssl2_certs.pcap")
		print("amount packets: %d" % len(packet_bytes))
		packet_bytes_iter = packet_bytes.__iter__()
		first_segment = None
		cert_length = 0

		# search first segment of SSL Hello containing certs
		for bts in packet_bytes_iter:
			print("=" * 100)
			eth1 = ethernet.Ethernet(bts)
			ssl1 = eth1[ssl.SSL]
			print("checking for cert: %r" % ssl1)
			cert_length = ssl1.get_cert_length()

			if ssl1 is not None and cert_length > 0:
				first_segment = eth1.ip.tcp
				print("certificate length: %d" % ssl1.get_cert_length())
				break

		self.assertNotEqual(first_segment, None)
		assembled_cnt = len(first_segment.body_bytes)

		for bts in packet_bytes_iter:
			eth1 = ethernet.Ethernet(bts)

			if eth1[tcp.TCP] is None:
				continue
			assembled, final = first_segment.ra_collect(eth1.ip.tcp)
			assembled_cnt += assembled

			if assembled_cnt >= cert_length:
				print("assembled all bytes, %d >= %d (cert length)" % (assembled_cnt, cert_length))
				break

		ssl_bts = first_segment.ra_bin()
		# print("ssl bytes: %r" % ssl_bts)
		self.assertGreaterEqual(len(ssl_bts), cert_length)
		ssl_certs = ssl.SSL(ssl_bts)
		# print("certs: %r" % ssl_certs.bin())
		# for rec in ssl_certs.records:
		#	print("%r" % rec)

		self.assertEqual(ssl_certs.records[1].handshake.type, ssl.HNDS_CERTIFICATE)
		certs = ssl_certs.records[1].handshake.extract_certificates()
		self.assertEqual(len(certs), 3)
		self.assertEqual(len(certs[0]), 1934)
		self.assertEqual(len(certs[1]), 1068)
		self.assertEqual(len(certs[2]), 897)


class TPKTTestCase(unittest.TestCase):
	def test_tpkt(self):
		print_header("TPKT")
		tpkt1 = tpkt.TPKT()
		tpkt1.bin()


# bts = get_pcap("tests/packets_tpkt.pcap", 1)[0]
# ether = ethernet.Ethernet(bts)
# self.assertTrue(ether.bin() == bts)
# self.assertTrue(ether[tpkt.TPKT] != None)


class PMAPTestCase(unittest.TestCase):
	def test_pmap(self):
		print_header("Pmap")
		pmap1 = pmap.Pmap()
		pmap1.bin()


# bts = get_pcap("tests/packets_pmap.pcap", 1)[0]
# ether = ethernet.Ethernet(bts)
# self.assertTrue(ether.bin() == bts)
# self.assertTrue(ether[pmap.Pmap] != None)


class RadiusTestCase(unittest.TestCase):
	def test_radius(self):
		print_header("Radius")
		radius1 = radius.Radius()
		radius1.bin()


# bts = get_pcap("tests/packets_radius.pcap", 1)[0]
# ether = ethernet.Ethernet(bts)
# self.assertTrue(ether.bin() == bts)
# self.assertTrue(ether[radius.Radius] != None)


class DiameterTestCase(unittest.TestCase):
	def test_diameter(self):
		print_header("Diameter")
		packet_bytes = get_pcap("tests/packets_diameter.pcap")

		# parsing
		dia_bytes = packet_bytes[0][62:]
		dia1 = diameter.Diameter(dia_bytes)

		self.assertEqual(dia1.bin(), dia_bytes)
		self.assertNotEqual(dia1, None)
		self.assertEqual(dia1.v, 1)
		self.assertEqual(dia1.len, b"\x00\x00\xe8")
		# dynamic fields
		print("AVPs: %d" % len(dia1.avps))
		self.assertEqual(len(dia1.avps), 13)
		avp1 = dia1.avps[0]
		avp2 = dia1.avps[12]
		self.assertEqual(avp1.code, 268)
		self.assertEqual(avp2.code, 258)

		avp3 = diameter.AVP(code=1, flags=2, len=b"\x00\x00\x03", body_bytes=b"\xff\xff\xff")
		dia1.avps.append(avp3)
		self.assertEqual(len(dia1.avps), 14)


class SocketTestCase(unittest.TestCase):
	def test_socket(self):
		print_header("Sockets")
		packet_eth = ethernet.Ethernet() + ip.IP(src_s="192.168.178.27", dst_s="173.194.113.183") + tcp.TCP(
			dport=80)
		packet_ip = ip.IP(src_s="192.168.178.27", dst_s="173.194.113.183") + tcp.TCP(dport=80)

		# Layer 2 Socket
		socket = SocketHndl(iface_name="eth1", mode=SocketHndl.MODE_LAYER_2)
		# socket.send(packet_eth.bin())
		packets = socket.sr(packet_eth)
		for p in packets:
			print(">>> %s" % p)
		socket.close()

		# Layer 3 Socket
		socket = SocketHndl(iface_name="eth1", mode=SocketHndl.MODE_LAYER_3)
		# socket.send(packet_ip.bin())
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

		self.assertEqual(bgp1.bin(), bgp1_bytes)
		self.assertEqual(bgp2.bin(), bgp2_bytes)
		self.assertEqual(bgp3.bin(), bgp3_bytes)

	def test_bgp2(self):
		print_header("BGP2")
		packet_bytes = get_pcap("tests/packets_bgp2.pcap")

		for bts in packet_bytes:
			eth = ethernet.Ethernet(bts)
			bgp_check = eth.highest_layer
			self.assertFalse(bgp_check.dissect_error)

			if not isinstance(bgp_check, tcp.TCP):
				print("%r" % bgp_check)


class StaticsTestCase(unittest.TestCase):
	def test_dns(self):
		dns_string = "www.test1.test2.de."
		dns_bytes = b"\x03www\x05test1\x05test2\x02de\x00"
		self.assertEqual(dns_string, pypacker.dns_name_decode(dns_bytes))
		self.assertEqual(dns_bytes, pypacker.dns_name_encode(dns_string))


class DNS2TestCase(unittest.TestCase):
	def test_smb(self):
		print_header("SMB")
		cnt = 0

		reader = ppcap.Reader(filename="tests/packets_dns2.pcap")
		pkts = [ethernet.Ethernet(bts) for ts, bts in reader]
		reader.close()

		for pkt in pkts:
			cnt += 1
			dnsP = pkt.highest_layer

			if isinstance(dnsP, dns.DNS):
				# print(cnt)
				tmp = "{0:016b}".format(dnsP.flags)


class FlowControlTestCase(unittest.TestCase):
	def test_pfc(self):
		print_header("FLOW CONTROL PFC")
		# PFC frame
		raw_pkt = b"\x01\x01\x00\xdd\x00\x00\x00\x01\x00\x00\x00\x14\x00\x03\x00(\x00\x03\x01\xf4\x00\x00"
		bytes_time_list = [b'\x00\x00', b'\x00\x01', b'\x00\x00', b'\x00\x14', b'\x00\x03', b'\x00(',
			b'\x00\x03', b'\x01\xf4']
		pkt = flow_control.FlowControl(raw_pkt)
		# parsing
		self.assertEqual(pkt.bin(), raw_pkt)
		self.assertEqual(pkt.opcode, flow_control.PFC_OPCODE)
		self.assertEqual(type(pkt.pfc).__name__, "PFC")
		self.assertEqual(pkt.pfc.ms, 0)
		self.assertEqual(pkt.pfc.ls, 221)
		self.assertEqual(type(pkt.pfc.time).__name__, "TriggerList")
		self.assertEqual(pkt.pfc.time, bytes_time_list)
		self.assertEqual(pkt.pfc.ls_list, [1, 1, 0, 1, 1, 1, 0, 1])
		self.assertEqual(pkt.pfc.time_list, [0, 1, 0, 20, 3, 40, 3, 500])
		# update ls and time fields via list
		pkt.pfc.ls_list = [1, 1, 1, 0, 1, 1, 1, 0]
		self.assertEqual(pkt.pfc.ls_list, [1, 1, 1, 0, 1, 1, 1, 0])
		self.assertEqual(pkt.pfc.ls, 238)
		time_list = [10, 20, 1, 2, 3, 100, 255, 65535]
		raw_time_list = [b'\x00\n', b'\x00\x14', b'\x00\x01', b'\x00\x02', b'\x00\x03', b'\x00d', b'\x00\xff',
			b'\xff\xff']
		pkt.pfc.time_list = time_list
		self.assertEqual(pkt.pfc.time_list, time_list)
		self.assertEqual(pkt.pfc.time, raw_time_list)

	def test_pause(self):
		print_header("FLOW CONTROL PAUSE")
		# Pause frame
		raw_pkt = b"\x01\x80\xc2\x00\x00\x01\x00\x00\x00\x00\x00\xaa\x88\x08\x00\x01\x00\x03"
		pkt = ethernet.Ethernet(raw_pkt)
		# parsing
		self.assertEqual(pkt.bin(), raw_pkt)
		self.assertEqual(pkt.dst_s, "01:80:C2:00:00:01")
		self.assertEqual(pkt[flow_control.FlowControl].opcode, flow_control.PAUSE_OPCODE)
		self.assertEqual(type(pkt[flow_control.FlowControl].pause).__name__, "Pause")
		self.assertEqual(pkt[flow_control.FlowControl].pause.ptime, 3)


class LLDPTestCase(unittest.TestCase):
	def test_lldp(self):
		print_header("LLDP")
		raw_pkt = get_pcap("tests/packets_lldp.pcap")[0]
		pkt = ethernet.Ethernet(raw_pkt)
		# parsing
		self.assertEqual(pkt.bin(), raw_pkt)
		self.assertEqual(pkt.type, ethernet.ETH_TYPE_LLDP)
		self.assertEqual(type(pkt.lldp).__name__, "LLDP")
		self.assertEqual(type(pkt.lldp.tlvlist).__name__, "TriggerList")
		self.assertEqual(len(pkt.lldp.tlvlist), 17)
		# check standard TLVs class
		self.assertEqual(type(pkt.lldp.tlvlist[0]).__name__, "LLDPChassisId")
		self.assertEqual(pkt.lldp.tlvlist[0].tlv_type, 1)
		tlv_value_len = len(pkt.lldp.tlvlist[0].value) + 1
		self.assertEqual(pkt.lldp.tlvlist[0].tlv_len, tlv_value_len)
		self.assertEqual(pkt.lldp.tlvlist[0].subtype, 4)
		self.assertEqual(pkt.lldp.tlvlist[0].value_s, "00:01:30:F9:AD:A0")
		self.assertEqual(type(pkt.lldp.tlvlist[1]).__name__, "LLDPPortId")
		self.assertEqual(pkt.lldp.tlvlist[1].tlv_type, 2)
		tlv_value_len = len(pkt.lldp.tlvlist[1].value) + 1
		self.assertEqual(pkt.lldp.tlvlist[1].tlv_len, tlv_value_len)
		self.assertEqual(pkt.lldp.tlvlist[1].subtype, 5)
		self.assertEqual(pkt.lldp.tlvlist[1].value_s, b"1/1")
		self.assertEqual(type(pkt.lldp.tlvlist[2]).__name__, "LLDPTTL")
		self.assertEqual(pkt.lldp.tlvlist[2].tlv_type, 3)
		self.assertEqual(pkt.lldp.tlvlist[2].seconds, 120)
		self.assertEqual(type(pkt.lldp.tlvlist[3]).__name__, "LLDPPortDescription")
		self.assertEqual(pkt.lldp.tlvlist[3].tlv_type, 4)
		tlv_value_len = len(pkt.lldp.tlvlist[3].value)
		self.assertEqual(pkt.lldp.tlvlist[3].tlv_len, tlv_value_len)
		self.assertEqual(type(pkt.lldp.tlvlist[4]).__name__, "LLDPSystemName")
		self.assertEqual(pkt.lldp.tlvlist[4].tlv_type, 5)
		tlv_value_len = len(pkt.lldp.tlvlist[4].value)
		self.assertEqual(pkt.lldp.tlvlist[4].tlv_len, tlv_value_len)
		self.assertEqual(type(pkt.lldp.tlvlist[5]).__name__, "LLDPSystemDescription")
		self.assertEqual(pkt.lldp.tlvlist[5].tlv_type, 6)
		tlv_value_len = len(pkt.lldp.tlvlist[5].value)
		self.assertEqual(pkt.lldp.tlvlist[5].tlv_len, tlv_value_len)
		self.assertEqual(type(pkt.lldp.tlvlist[6]).__name__, "LLDPSystemCapabilities")
		self.assertEqual(pkt.lldp.tlvlist[6].tlv_type, 7)
		self.assertEqual(pkt.lldp.tlvlist[6].tlv_len, 4)
		self.assertEqual(pkt.lldp.tlvlist[6].capabilities, 20)
		self.assertEqual(pkt.lldp.tlvlist[6].enabled, 20)
		self.assertEqual(type(pkt.lldp.tlvlist[7]).__name__, "LLDPManagementAddress")
		self.assertEqual(pkt.lldp.tlvlist[7].tlv_type, 8)
		tlv_len = len(pkt.lldp.tlvlist[7].bin())
		self.assertEqual(pkt.lldp.tlvlist[7].tlv_len, tlv_len - 2)
		self.assertEqual(pkt.lldp.tlvlist[7].addrlen, 7)
		self.assertEqual(pkt.lldp.tlvlist[7].addrsubtype, 6)
		self.assertEqual(pkt.lldp.tlvlist[7].addrval_s, "00:01:30:F9:AD:A0")
		self.assertEqual(pkt.lldp.tlvlist[7].ifsubtype, 2)
		self.assertEqual(pkt.lldp.tlvlist[7].ifnumber, 1001)
		self.assertEqual(pkt.lldp.tlvlist[7].oidlen, 0)
		self.assertEqual(pkt.lldp.tlvlist[7].oid, b"")
		self.assertEqual(type(pkt.lldp.tlvlist[-1]).__name__, "LLDPDUEnd")
		self.assertEqual(pkt.lldp.tlvlist[-1].tlv_type, 0)
		self.assertEqual(pkt.lldp.tlvlist[-1].tlv_len, 0)


class LACPTestCase(unittest.TestCase):
	def test_lacp(self):
		print_header("LACP")
		raw_pkt = get_pcap("tests/packets_lacp.pcap")[0]
		pkt = ethernet.Ethernet(raw_pkt)
		# parsing
		self.assertEqual(pkt.bin(), raw_pkt)
		self.assertEqual(pkt.type, ethernet.ETH_TYPE_SP)
		self.assertEqual(pkt.dst_s, "01:80:C2:00:00:02")
		self.assertEqual(type(pkt.lacp).__name__, "LACP")
		self.assertEqual(pkt.lacp.subtype, 1)
		self.assertEqual(pkt.lacp.version, 1)
		self.assertEqual(type(pkt.lacp.tlvlist).__name__, "TriggerList")
		self.assertEqual(len(pkt.lacp.tlvlist), 5)
		self.assertEqual(type(pkt.lacp.tlvlist[0]).__name__, "LACPActorInfoTlv")
		self.assertEqual(pkt.lacp.tlvlist[0].type, 1)
		self.assertEqual(pkt.lacp.tlvlist[0].len, 20)
		self.assertEqual(pkt.lacp.tlvlist[0].sys_s, pkt.src_s)
		self.assertEqual(pkt.lacp.tlvlist[0].reserved, b"\x00" * 3)
		self.assertEqual(pkt.lacp.tlvlist[0].expired, 0)
		self.assertEqual(pkt.lacp.tlvlist[0].defaulted, 1)
		self.assertEqual(pkt.lacp.tlvlist[0].distribute, 0)
		self.assertEqual(pkt.lacp.tlvlist[0].collect, 0)
		self.assertEqual(pkt.lacp.tlvlist[0].synch, 0)
		self.assertEqual(pkt.lacp.tlvlist[0].aggregate, 1)
		self.assertEqual(pkt.lacp.tlvlist[0].timeout, 1)
		self.assertEqual(pkt.lacp.tlvlist[0].activity, 1)
		self.assertEqual(type(pkt.lacp.tlvlist[1]).__name__, "LACPPartnerInfoTlv")
		self.assertEqual(pkt.lacp.tlvlist[1].type, 2)
		self.assertEqual(pkt.lacp.tlvlist[1].len, 20)
		self.assertEqual(pkt.lacp.tlvlist[1].reserved, b"\x00" * 3)
		self.assertEqual(type(pkt.lacp.tlvlist[2]).__name__, "LACPCollectorInfoTlv")
		self.assertEqual(pkt.lacp.tlvlist[2].type, 3)
		self.assertEqual(pkt.lacp.tlvlist[2].len, 16)
		self.assertEqual(pkt.lacp.tlvlist[2].reserved, b"\x00" * 12)
		self.assertEqual(type(pkt.lacp.tlvlist[3]).__name__, "LACPTerminatorTlv")
		self.assertEqual(pkt.lacp.tlvlist[3].type, 0)
		self.assertEqual(pkt.lacp.tlvlist[3].len, 0)
		self.assertEqual(type(pkt.lacp.tlvlist[4]).__name__, "LACPReserved")
		self.assertEqual(pkt.lacp.tlvlist[4].reserved, b"\x00" * 50)


class StateMachineTestCase(unittest.TestCase):
	def test_sm(self):
		print_header("State machine")

		class ExampleStateMachine(statemachine.StateMachine):
			@statemachine.sm_state(state_type=statemachine.STATE_TYPE_BEGIN)
			def state_a(self, pkt):  # state: event triggers state change
				print("state a: %r" % pkt)  # check conditions to state change
				self._state = self.state_b  # next state

			def timeout_ack_sent(self):
				print("switching to state a")
				self._state = self.state_a

			# max x seconds in this state: call action and further decide what to do
			@statemachine.sm_state(timeout=2, timeout_cb=timeout_ack_sent)
			def state_b(self, pkt):
				print("state b: %r" % pkt)
				self._state = self.state_c

			@statemachine.sm_state()
			def state_c(self, pkt):
				print("state c: %r" % pkt)
				self._state = self.state_a

		cnt = [0]

		def recv_cb():
			cnt[0] += 1
			if cnt[0] > 10:
				time.sleep(1)
			# time.sleep(random.randrange(0, 3))
			time.sleep(0.1)
			return "packet_content_%X" % random.randrange(0, 999)

		sm = ExampleStateMachine(recv_cb)
		time.sleep(1)
		sm.stop()


class ReassembleTestCase(unittest.TestCase):
	def test_reassemble(self):
		print_header("Reassemble")
		bts_l = get_pcap("tests/packets_ssl2_certs.pcap")
		pkts = [ethernet.Ethernet(bts) for bts in bts_l]
		pkts_tcp = [pkt.ip.tcp for pkt in pkts]
		print("tcp packets: %d" % len(pkts_tcp))

		for pkt in pkts_tcp:
			print("%d %d <-> %d %d" % (pkt.sport, pkt.seq, pkt.dport, pkt.ack))

		tcp_start = pkts_tcp[0]
		tcp_start.ra_collect(pkts_tcp)
		segments_cnt = len(tcp_start.ra_segments)
		self.assertEqual(segments_cnt, 3)
		segments_ra = tcp_start.ra_bin()
		self.assertNotEqual(len(segments_ra), 0)

		with open("tests/certs_extracted_0.bin", "rb") as fd:
			bts_assembled = fd.read()
		self.assertEqual(segments_ra, bts_assembled[:len(segments_ra)])
		tcp_start.ra_segments.clear()

		tcp_start = pkts_tcp[49]
		tcp_start.ra_collect(pkts_tcp)
		segments_cnt = len(tcp_start.ra_segments)
		self.assertEqual(segments_cnt, 5)
		segments_ra = tcp_start.ra_bin()
		self.assertNotEqual(len(segments_ra), 0)

		with open("tests/certs_extracted_1.bin", "rb") as fd:
			bts_assembled = fd.read()
		self.assertEqual(segments_ra, bts_assembled[:len(segments_ra)])


"""
class DERTestCase(unittest.TestCase):
	def test_der(self):
		print_header("DER")
		result_dct = {}

		def extract_cb(tlv_list):
			if len(tlv_list) == 2:
				# b'U\x04\x03' = 2.5.4.3 - id-at-commonName
				# b'U\x04\x06' = 2.5.4.6 - id-at-countryName
				# b'U\x04\x07' = 2.5.4.7 - id-at-localityName
				# b'U\x04\x08' = 2.5.4.8 - id-at-stateOrProvinceName
				# b'U\x04\n' = 2.5.4.10 - id-at-organizationName
				# b'U\x04\x0b' = 2.5.4.11 - id-at-organizationalUnitName
				# print(tlv_list)
				# TODO: extract hash, signature, modulus
				v1, v2 = tlv_list[0][2], tlv_list[1][2]
				result_dct[v1] = v2
			else:
				pass

		result = []
		raw = open("tests/cert1.der", "rb").read()
		der.decode_der(raw, result, extract_cb=extract_cb)
		#pprint.pprint(result)
		#pprint.pprint(result[0][2][0][2][5][2])
		result_dct[result[0][2][0][2][5][2][0][2][0][2]] = result[0][2][0][2][5][2][1][2]
		result_dct[result[0][2][1][2][0][2]] = result[0][2][2][2]
		print("===")
		pprint.pprint(result_dct)
"""

suite = unittest.TestSuite()
loader = unittest.defaultTestLoader

suite.addTests(loader.loadTestsFromTestCase(GeneralTestCase))
suite.addTests(loader.loadTestsFromTestCase(PacketDumpTestCase))
suite.addTests(loader.loadTestsFromTestCase(EthTestCase))
suite.addTests(loader.loadTestsFromTestCase(AOETestCase))
suite.addTests(loader.loadTestsFromTestCase(LinuxCookedCapture))
suite.addTests(loader.loadTestsFromTestCase(CANTestCase))
suite.addTests(loader.loadTestsFromTestCase(IPTestCase))
suite.addTests(loader.loadTestsFromTestCase(TCPTestCase))
suite.addTests(loader.loadTestsFromTestCase(UDPTestCase))
suite.addTests(loader.loadTestsFromTestCase(IP6TestCase))
suite.addTests(loader.loadTestsFromTestCase(ChecksumTestCase))
suite.addTests(loader.loadTestsFromTestCase(HTTPTestCase))
suite.addTests(loader.loadTestsFromTestCase(AccessConcatTestCase))
suite.addTests(loader.loadTestsFromTestCase(IterateTestCase))
suite.addTests(loader.loadTestsFromTestCase(SimpleFieldActivateDeactivateTestCase))
suite.addTests(loader.loadTestsFromTestCase(TriggerListTestCase))
suite.addTests(loader.loadTestsFromTestCase(ICMPTestCase))
suite.addTests(loader.loadTestsFromTestCase(ICMP6TestCase))
suite.addTests(loader.loadTestsFromTestCase(OSPFTestCase))
suite.addTests(loader.loadTestsFromTestCase(PPPTestCase))
suite.addTests(loader.loadTestsFromTestCase(STPTestCase))
suite.addTests(loader.loadTestsFromTestCase(VRRPTestCase))
suite.addTests(loader.loadTestsFromTestCase(IGMPTestCase))
suite.addTests(loader.loadTestsFromTestCase(IPXTestCase))
suite.addTests(loader.loadTestsFromTestCase(PIMTestCase))
suite.addTests(loader.loadTestsFromTestCase(HSRPTestCase))
suite.addTests(loader.loadTestsFromTestCase(DHCPTestCase))
suite.addTests(loader.loadTestsFromTestCase(StunTestCase))
suite.addTests(loader.loadTestsFromTestCase(TFTPTestCase))
suite.addTests(loader.loadTestsFromTestCase(DNSTestCase))
suite.addTests(loader.loadTestsFromTestCase(NTPTestCase))
suite.addTests(loader.loadTestsFromTestCase(RIPTestCase))
suite.addTests(loader.loadTestsFromTestCase(SCTPTestCase))
suite.addTests(loader.loadTestsFromTestCase(ReaderTestCase))
suite.addTests(loader.loadTestsFromTestCase(ReadWriteReadTestCase))
suite.addTests(loader.loadTestsFromTestCase(RadiotapTestCase))
suite.addTests(loader.loadTestsFromTestCase(BTLETestcase))
# Disabled: Takes a bit longer
# suite.addTests(loader.loadTestsFromTestCase(PerfTestCase))
suite.addTests(loader.loadTestsFromTestCase(IEEE80211TestCase))
suite.addTests(loader.loadTestsFromTestCase(DTPTestCase))
suite.addTests(loader.loadTestsFromTestCase(TelnetTestCase))
suite.addTests(loader.loadTestsFromTestCase(PTPv2TestCase))
suite.addTests(loader.loadTestsFromTestCase(SSLTestCase))
suite.addTests(loader.loadTestsFromTestCase(TPKTTestCase))
suite.addTests(loader.loadTestsFromTestCase(PMAPTestCase))
suite.addTests(loader.loadTestsFromTestCase(RadiusTestCase))
suite.addTests(loader.loadTestsFromTestCase(DiameterTestCase))
# Disabled: Needs root
# suite.addTests(loader.loadTestsFromTestCase(SocketTestCase))
suite.addTests(loader.loadTestsFromTestCase(BGPTestCase))
suite.addTests(loader.loadTestsFromTestCase(StaticsTestCase))
suite.addTests(loader.loadTestsFromTestCase(DNS2TestCase))
suite.addTests(loader.loadTestsFromTestCase(FlowControlTestCase))
suite.addTests(loader.loadTestsFromTestCase(LLDPTestCase))
suite.addTests(loader.loadTestsFromTestCase(LACPTestCase))
suite.addTests(loader.loadTestsFromTestCase(StateMachineTestCase))
suite.addTests(loader.loadTestsFromTestCase(ReassembleTestCase))
# suite.addTests(loader.loadTestsFromTestCase(DERTestCase))

# Broken
# suite.addTests(loader.loadTestsFromTestCase(ReaderNgTestCase))
# suite.addTests(loader.loadTestsFromTestCase(ReaderPcapNgTestCase))

# Run all or dedicated tests
if len(sys.argv) == 1:
	# python tests/test_pypacker.py
	print("Running standard test suite")
	unittest.TextTestRunner().run(suite)
else:
	# python tests/test_pypacker.py TestClass
	print("Running tests given as program argument")
	unittest.main()
