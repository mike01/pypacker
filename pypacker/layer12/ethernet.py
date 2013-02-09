# $Id: ethernet.py 65 2010-03-26 02:53:51Z dugsong $

"""Ethernet II, LLC (802.3+802.2), LLC/SNAP, and Novell raw 802.3,
with automatic 802.1q, MPLS, PPPoE, and Cisco ISL decapsulation."""

import pypacker as pypacker
from . import stp
#from pypacker import stp
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
ETH_TYPE_IP		= 0x0800	# IP protocol
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
	__hdr__ = (
		('dst', '6s', b"\xff\xff\xff\xff\xff\xff"),
		('src', '6s', b"\xff\xff\xff\xff\xff\xff"),
#		('dst', '6B', ''),
#		('src', '6B', ''),
		('vlan', 'H', None),	# skip VLAN per default
		('type', 'H', ETH_TYPE_IP)
		)
	# TODO: no "_"
	__PROG_MAC = re.compile("(\w{2,2}:){5,5}\w{2,2}")

	def __setattr__(self, k, v):
		# convert "AA:BB:CC:DD:EE:FF" to byte representation
		if not type(v) in [bytes, type(None)] and k in ["dst", "src"] and self.__PROG_MAC.match(v):
			#logger.debug("converting to byte-mac")
			v = b"".join([ bytes.fromhex(x) for x in v.split(":") ])
		pypacker.Packet.__setattr__(self, k, v)

	def __getattribute__(self, k):
		# convert bytes to "AA:BB:CC:DD:EE:FF" representation
		ret = object.__getattribute__(self, k)

		if ret is not None and k in ["dst", "src"]:
			#logger.debug("converting to string-mac: %s" % ret)
			ret = "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", ret)
				
		return ret

	def unpack(self, buf):
		# we need to check for VLAN here (0x8100) to get correct header-length
		if len(buf) >= 15:
			if struct.unpack(">BB", buf[13:15])[0] == b"\x81\x00" or \
				buf[0:6] == b"\x01\x00\x0c\x00\x00" or \
				buf[6:12] == b"\x03\x00\x0c\x00\x00":
				self.vlan = b""

		# avoid calling unpack more than once
		type = struct.unpack(">H", buf[self.__hdr_len__ - 2 : self.__hdr_len__])[0]
		buf_data = b""

		# TODO: fix layer-2 parsing (Ethernet II working so far)
		if type > 1500:
			logger.debug("found Ethernet II")
			# Ethernet II
			buf_data = buf[self.__hdr_len__:]
			#logger.debug("Ethernet buf for handler: %s" % buf)
		elif self.dst.startswith("\x01\x00\x0c\x00\x00") or \
			 self.dst.startswith("\x03\x00\x0c\x00\x00"):
			# Cisco ISL
			self.vlan = struct.unpack('>H', buf[6:8])[0]
			# TODO: check this
			self.unpack(self.data[12:])
		elif buf.startswith(b"\xff\xff"):
			# Novell "raw" 802.3
			self.type = ETH_TYPE_IPX
			buf = buf[2:]
		elif self.type == ETH_TYPE_MPLS or \
			self.type == ETH_TYPE_MPLS_MCAST:
			logger.debug("ETH_TYPE_MPLS ETH_TYPE_MPLS_MCAST")
			# XXX - skip labels (max # of labels is undefined, just use 24)
			self.labels = []
			for i in range(24):
				entry = struct.unpack('>I', buf[i*4:i*4+4])[0]
				label = ((entry & MPLS_LABEL_MASK) >> MPLS_LABEL_SHIFT, \
						 (entry & MPLS_QOS_MASK) >> MPLS_QOS_SHIFT, \
						 (entry & MPLS_TTL_MASK) >> MPLS_TTL_SHIFT)
				self.labels.append(label)
				if entry & MPLS_STACK_BOTTOM:
					break
			self.type = ETH_TYPE_IP
			buf = buf[(i + 1) * 4:]
		else:
			# 802.2 LLC
			self.dsap, self.ssap, self.ctl = struct.unpack('BBB', buf[:3])

			if buf.startswith(b"\xaa\xaa"):
				# SNAP
				type = struct.unpack('>H', buf[6:8])[0]
				buf_data = buf[8:]
			else:
				# non-SNAP
				#dsap = ord(buf[0])
				#dsap = buf[0]

				#if dsap == 0x06: # SAP_IP
				#	type = self._typesw[Ethernet.__class__][ETH_TYPE_IP](buf[3:])
				#elif dsap == 0x10 or dsap == 0xe0: # SAP_NETWARE{1,2}
				#	type = self._typesw[Ethernet.__class__][ETH_TYPE_IPX](buf[3:])
				#elif dsap == 0x42: # SAP_STP
				#	type = stp.STP(buf[3:])
				pass

		try:
			logger.debug("Ethernet: trying to set handler, type: %d = %s" % (type, self._handler[Ethernet.__name__][type]))
			type_instance = self._handler[Ethernet.__name__][type](buf_data)
			self._set_bodyhandler(type_instance)
		except pypacker.NeedData:
			pass
		except (KeyError, pypacker.UnpackError) as e:
			logger.debug("Ethernet: coudln't set handler: %s" % e)

		pypacker.Packet.unpack(self, buf)

	def is_related(self, next):
		# TODO: make this more easy
		logger.debug("checking relation: %s<->%s" % (self, next))
		related_self = False
		try:
			addr = [ next.dst, next.src ]
			# check if src and dst are known
			related_self = self.dst in addr and self.src in addr
		except:
			return False
		# delegate to super implementation for further checks
		return related_self and pypacker.Packet.is_related(self, next)


pypacker.Packet.load_handler(globals(), Ethernet, "ETH_TYPE_", ["layer12", "layer3"])
