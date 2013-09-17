"""
Ethernet II, LLC (802.3+802.2), LLC/SNAP, and Novell raw 802.3,
with automatic 802.1q, MPLS, PPPoE, and Cisco ISL decapsulation.

RFC 1042
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
	"""
	Convenient access for: dst[_s], src[_s]. VLAN-Tag can by accessed via 'vlan', header
	structure will be changed accordingly using fomrmat 'H'. Disable using value 'None'.
	"""
	__hdr__ = (
		("dst", "6s", b"\xff" * 6),
		("src", "6s", b"\xff" * 6),
		("type", "H", ETH_TYPE_IP)
		)

	dst_s = pypacker.Packet._get_property_mac("dst")
	src_s = pypacker.Packet._get_property_mac("src")

	def __get_vlan(self):
		try:
			return self._vlan
		except AttributeError:
			# vlan not set until now
			return None

	def __set_vlan(self, value):
		# remove vlan tag
		if value is None:
			if "_vlan" in self._hdr_fields:
				self._del_headerfield(2)
		else:
			if "_vlan" not in self._hdr_fields:
				self._insert_headerfield(2, "_vlan", "4s", value)	
		self._vlan = value
	vlan = property(__get_vlan, __set_vlan)

	def _dissect(self, buf):
		# we need to check for VLAN TPID here (0x8100) to get correct header-length
		if buf[12:14] == b"\x81\x00":
			#logger.debug("got vlan tag")
			# _unpack() will set this for us
			self.vlan = b"\x00\x00\x00\x00"

		# avoid calling unpack more than once
		type = struct.unpack(">H", buf[self._hdr_len - 2 : self._hdr_len])[0]

		# handle ethernet-padding: remove it but save for later use
		# don't use headers for this because this is a rare situation
		hlen = self._hdr_len	# header length
		dlen = len(buf) - hlen	# data length [+ padding?]

		try:
			# this will only work on complete headers: Ethernet + IP + ...
			# handle padding using IPv4
			# TODO: check for other protocols
			if type == ETH_TYPE_IP:
				dlen_ip = struct.unpack(">H", buf[hlen + 2 : hlen + 4])[0]	# real data length
				if dlen_ip < dlen:
					# padding found
					#logger.debug("got padding for IPv4")
					self._padding = buf[hlen + dlen_ip:]
					dlen = dlen_ip
			# handle padding using IPv6
			# IPv6 is a piece of sh$§! payloadlength = exclusive standard header, INCLUSIVE options!
			elif type == ETH_TYPE_IP6:
				dlen_ip = struct.unpack(">H", buf[hlen + 4 : hlen + 6])[0]	# real data length
				if 40 + dlen_ip < dlen:
					# padding found
					#logger.debug("got padding for IPv6")
					self._padding = buf[hlen + dlen_ip:]
					dlen = dlen_ip
		except:
			pass

		self._parse_handler(type, buf, offset_start=hlen, offset_end=hlen + dlen)

	def bin(self):
		"""Custom bin(): handle padding for Ethernet."""
		return pypacker.Packet.bin(self) + self.padding

	def _direction(self, next):
		#logger.debug("checking direction: %s<->%s" % (self, next))
		if self.dst == next.dst and self.src == next.src:
			return pypacker.Packet.DIR_SAME
		# handle broadcast
		elif self.dst in [ next.src, b"\xff\xff\xff\xff\xff\xff" ] and self.src in [ next.dst, b"\xff\xff\xff\xff\xff\xff" ]:
			return pypacker.Packet.DIR_REV
		else:
			return pypacker.Packet.DIR_UNKNOWN

	# handle padding attribute
	def __get_padding(self):
		try:
			return self._padding
		except AttributeError:
			return b""

	def __set_padding(self, padding):
		self._padding = padding

	padding = property(__get_padding, __set_padding)


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
