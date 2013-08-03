"""
Ethernet II, LLC (802.3+802.2), LLC/SNAP, and Novell raw 802.3,
with automatic 802.1q, MPLS, PPPoE, and Cisco ISL decapsulation.
"""

from .. import pypacker

import logging
import copy
import re
import struct

logger = logging.getLogger("pypacker")

ETH_CRC_LEN	= 4
ETH_HDR_LEN	= 14

ETH_LEN_MIN	= 64		# minimum frame length with CRC
ETH_LEN_MAX	= 1518		# maximum frame length with CRC

ETH_MTU		= (ETH_LEN_MAX - ETH_HDR_LEN - ETH_CRC_LEN)
ETH_MIN		= (ETH_LEN_MIN - ETH_HDR_LEN - ETH_CRC_LEN)

# Ethernet payload types - http://standards.ieee.org/regauth/ethertype
ETH_TYPE_PUP		= 0x0200	# PUP protocol
ETH_TYPE_IP		= 0x0800	# IPv4 protocol
ETH_TYPE_ARP		= 0x0806	# address resolution protocol
ETH_TYPE_WOL		= 0x0842	# Wake on LAN
ETH_TYPE_CDP		= 0x2000	# Cisco Discovery Protocol
ETH_TYPE_DTP		= 0x2004	# Cisco Dynamic Trunking Protocol
ETH_TYPE_REVARP		= 0x8035	# reverse addr resolution protocol
ETH_TYPE_ETHTALK	= 0x809B	# Apple Talk
ETH_TYPE_AARP		= 0x80F3	# Appletalk Address Resolution Protocol
ETH_TYPE_8021Q		= 0x8100	# IEEE 802.1Q VLAN tagging
ETH_TYPE_IPX		= 0x8137	# Internetwork Packet Exchange
ETH_TYPE_NOV		= 0x8138	# Novell
ETH_TYPE_IP6		= 0x86DD	# IPv6 protocol
ETH_TYPE_MPLS_UCAST	= 0x8847	# MPLS unicast
ETH_TYPE_MPLS_MCAST	= 0x8848	# MPLS multicast
ETH_TYPE_PPOE_DISC	= 0x8863	# PPPoE Discovery
ETH_TYPE_PPOE_SESS	= 0x8864	# PPPoE Session
ETH_TYPE_JUMBOF		= 0x8870	# Jumbo Frames
ETH_TYPE_PROFINET	= 0x8892	# Realtime-Ethernet PROFINET
ETH_TYPE_ATAOE		= 0x88A2	# ATA other Ethernet
ETH_TYPE_ETHERCAT	= 0x88A4	# Realtime-Ethernet Ethercat
ETH_TYPE_PBRIDGE	= 0x88A8	# Provider Briding
ETH_TYPE_POWERLINK	= 0x88AB	# Realtime Ethernet POWERLINK
ETH_TYPE_LLDP		= 0x88CC	# Link Layer Discovery Protocol
ETH_TYPE_SERCOS		= 0x88CD	# Realtime Ethernet SERCOS III
ETH_TYPE_FIBRE_ETH	= 0x8906	# Fibre Channel over Ethernet
ETH_TYPE_FCOE		= 0x8914	# FCoE Initialization Protocol (FIP)

# MPLS label stack fields
MPLS_LABEL_MASK	= 0xfffff000
MPLS_QOS_MASK	= 0x00000e00
MPLS_TTL_MASK	= 0x000000ff
MPLS_LABEL_SHIFT= 12
MPLS_QOS_SHIFT	= 9
MPLS_TTL_SHIFT	= 0
MPLS_STACK_BOTTOM=0x0100


class Ethernet(pypacker.Packet):
	"""Convenient access for: dst[_s], src[_s]"""
	__hdr__ = (
		("dst", "6s", b"\xff" * 6),
		("src", "6s", b"\xff" * 6),
		("type", "H", ETH_TYPE_IP)
		)

	def __getdst_s(self):
		return "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", self.dst)
	def __setdst_s(self, value):
		self.dst = b"".join([ bytes.fromhex(x) for x in value.split(":") ])
	dst_s = property(__getdst_s, __setdst_s)

	def __getsrc_s(self):
		return "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", self.src)
	def __setsrc_s(self, value):
		self.src = b"".join([ bytes.fromhex(x) for x in value.split(":") ])
	src_s = property(__getsrc_s, __setsrc_s)

	def __getvlan(self):
		return self._vlan
	# lazy init of vlan
	def __setvlan(self, value):
		try:
			self._vlan = value
			# vlan header field is present, None = no vlan at all
			if value is None:
				self._del_headerfield(3)
		except AttributeError:
			self._insert_headerfield(2, "_vlan", "H", value)	
	vlan = property(__getvlan, __setvlan)

	def _unpack(self, buf):
		# we need to check for VLAN here (0x8100) to get correct header-length
		#if len(buf) >= 15 and buf[13:15] == b"\x81\x00":
		if buf[13:15] == b"\x81\x00":
			self._insert_headerfield(2, "_vlan", "H", b"\x81\x00")
			#self.vlan = b"\x81\x00"

		# avoid calling unpack more than once
		type = struct.unpack(">H", buf[self.__hdr_len__ - 2 : self.__hdr_len__])[0]

		# Ethernet II
		if type > 1500:
			#logger.debug("found Ethernet II")
			#logger.debug("Ethernet buf for handler: %s" % buf)
			pass
		#
		# following: MPLS
		#
		elif type == ETH_TYPE_MPLS_UCAST or \
			type == ETH_TYPE_MPLS_MCAST:
			#logger.debug("found MPLS")
			labels = []
			s = 0
			off = self.__hdr_len__
			# while not end of stack (s=1)
			while s != 1:
				p = MPLSEntry(buf[off : off + 4])
				s = buf[off + 23]
				labels.append( p )
				off += 4
				#label = ((entry & MPLS_LABEL_MASK) >> MPLS_LABEL_SHIFT, \
				#		 (entry & MPLS_QOS_MASK) >> MPLS_QOS_SHIFT, \
				#		 (entry & MPLS_TTL_MASK) >> MPLS_TTL_SHIFT)

			tl = TriggerList(labels)
			self._add_headerfield("label", "", tl)
			type = ETH_TYPE_IP
		#
		# following: IPX over Ethernet
		#
		elif buf[14 : 16] == b"\xFF\xFF":
			# 802.3 (raw)
			#logger.debug("found 802.3 (raw)")
			# type is actually length: dst|src|len|0xFF, 0xFF|IPX-data
			type = ETH_TYPE_IPX
			self._del_headerfield(3, True)	# remove type
			self._add_headerfield("len", "B", 0, True)
			self._add_headerfield("sep", "H", buf[14 : 16])
		elif buf[14 : 16] == b"\xE0\xE0":
			# 802.3 (Novell)
			#logger.debug("found 802.3 (Novell)")
			# type is actually length: dst|src|len|0xE0, 0xE0, 0x03|IPX-data
			type = ETH_TYPE_IPX
			self._del_headerfield(3, True)	# remove type
			self._add_headerfield("len", "B", 0, True)
			self._add_headerfield("sep", "3s", buf[14 : 17])
		elif buf[14 : 22] == b"\xAA\xAA\x03\x00\x00\x00\x81\x37":
			# 802.3 (SNAP)
			#logger.debug("found 802.3 (SNAP)")
			# type is actually length: dst|src|len|LLC header (0xAA, 0xAA, 0x03), SNAP header (0x00, 0x00, 0x00, 0x81, 0x37)|IPX-data
			type = ETH_TYPE_IPX
			self._del_headerfield(3, True)	# remove type
			self._add_headerfield("len", "B", 0, True)
			self._add_headerfield("llc_snap", "8s", buf[14 : 22])
		else:
			raise UnpackError("Unkown Ethernet type: %d" % type)

		try:
			# handle ethernet-padding: remove it but save for later use
			# don't use headers for this because this is a rare situation
			# TODO: handle for different protocols
			hlen = self.__hdr_len__	# header length
			dlen = len(buf) - hlen	# data length [+ padding?]

			# this will only work on complete headers: Ethernet + IP + ...
			# handle padding using IPv4
			if type == ETH_TYPE_IP:
				dlen_ip = struct.unpack(">H", buf[hlen + 2 : hlen + 4])[0]	# real data length
				# padding found
				if dlen > dlen_ip:
					#object.__setattr__(self, "padding", buf[hlen + dlen:])
					object.__setattr__(self, "_padding", buf[hlen + dlen_ip:])
					dlen = dlen_ip
			# handle padding using IPv6
			elif type == ETH_TYPE_IP6:
				dlen_ip = struct.unpack(">H", buf[hlen + 4 : hlen + 6])[0]	# real data length
				# padding found
				if dlen > dlen_ip:
					object.__setattr__(self, "_padding", buf[hlen + dlen_ip:])
					dlen = dlen_ip
			#logger.debug("Ethernet: trying to set handler, type: %d = %s" % (type, self._handler[Ethernet.__name__][type]))
			self._parse_handler(type, buf, hlen, hlen + dlen)
			#type_instance = self._handler[Ethernet.__name__][type]( buf[hlen : hlen + dlen ])
			#self._set_bodyhandler(type_instance)
		# any exception will lead to: body = raw bytes
		except Exception as ex:
			#logger.debug(">>> Ethernet: couldn't set handler: %d -> %s" % (type, ex))
			# no handler and padding present? avoid double adding padding
			self.padding = b""
			pass

		pypacker.Packet._unpack(self, buf)

	def bin(self):
		"""Handle padding for Ethernet."""
		return pypacker.Packet.bin(self) + self.padding

	def direction(self, next, last_packet=None):
		#logger.debug("checking direction: %s<->%s" % (self, next))

		if self.dst == next.dst and self.src == next.src:
			direction = pypacker.Packet.DIR_SAME
		elif self.dst == next.src and self.src == next.dst:
			direction = pypacker.Packet.DIR_REV
		else:
			direction = pypacker.Packet.DIR_BOTH
		# delegate to super implementation for further checks
		return direction | pypacker.Packet.direction(self, next, last_packet)

	# Handle padding attribute
	def __getpadding(self):
		try:
			return self._padding
		except:
			return b""

	def __setpadding(self, padding):
		object.__setattr__(self, "_padding", padding)

	padding = property(__getpadding, __setpadding)


class MPLSEntry(pypacker.Packet):
	__hdr__ = (
		("entry", "I", 0),
		)

	# 20    | 3  | 1 | 8
	# Label | TC | S | TTL
	def getlabel(self):
		return (self.entry & 0xFFFFF000) >> 12
	def setlabel(self, value):
		self.entry = (self.entry & ~0xFFFFF000) | (label & 0xFFFFF000)
	label = property(getlabel, setlabel)
	def gettc(self):
                return (self.entry & 0x00000E00) >> 9
	def settc(self, value):
 		self.entry = (self.entry & ~0x00000E00) | (tc & 0x00000E00)
	tc = property(gettc, settc)
	def gets(self):
 		return (self.entry & 0x00000100) >> 8
	def sets(self, value):
		self.entry = (self.entry & ~0x00000100) | (s & 0x00000100)
	s = property(gets, sets)
	def getttl(self):
		return (self.entry & 0x000000FF)
	def setttl(self, value):
		self.entry = (self.entry & ~0x000000FF) | (ttl & 0x000000FF)
	ttl = property(getttl, setttl)

	#__m_switch_set = {"label":lambda entry,label: (entry & ~0xFFFFF000) | (label & 0xFFFFF000),
	#		"tc":lambda entry,tc: (entry & ~0x00000E00) | (tc & 0x00000E00),
	#		"s":lambda entry,s: (entry & ~0x00000100) | (s & 0x00000100),
	#		"ttl":lambda entry,ttl: (entry & ~0x000000FF) | (ttl & 0x000000FF)
	#		}
	#__m_switch_get = {"label":lambda entry: (entry & 0xFFFFF000) >> 12,
	#		"tc":lambda entry: (entry & 0x00000E00) >> 9,
	#		"s":lambda entry: (entry & 0x00000100) >> 8,
	#		"ttl":lambda entry: (entry & 0x000000FF)
	#		}


# load handler
from pypacker.layer12 import arp, cdp, dtp, pppoe
from pypacker.layer3 import ip, ip6, ipx

pypacker.Packet.load_handler(Ethernet,
				{
				ETH_TYPE_IP : ip.IP,
				ETH_TYPE_ARP : arp.ARP,
				ETH_TYPE_DTP : cdp.CDP,
				ETH_TYPE_DTP : dtp.DTP,
				ETH_TYPE_IPX : ipx.IPX,
				ETH_TYPE_IP6 : ip6.IP6,
				ETH_TYPE_PPOE_DISC : pppoe.PPPoE,
				ETH_TYPE_PPOE_SESS : pppoe.PPPoE
				}
			)
