# $Id: ethernet.py 65 2010-03-26 02:53:51Z dugsong $

"""Ethernet II, LLC (802.3+802.2), LLC/SNAP, and Novell raw 802.3,
with automatic 802.1q, MPLS, PPPoE, and Cisco ISL decapsulation."""

#from .. import pypacker
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
ETH_TYPE_CDP		= 0x2000	# Cisco Discovery Protocol
ETH_TYPE_DTP		= 0x2004	# Cisco Dynamic Trunking Protocol
ETH_TYPE_REVARP		= 0x8035	# reverse addr resolution protocol
ETH_TYPE_8021Q		= 0x8100	# IEEE 802.1Q VLAN tagging
ETH_TYPE_IPX		= 0x8137	# Internetwork Packet Exchange
ETH_TYPE_IP6		= 0x86DD	# IPv6 protocol
ETH_TYPE_PPP		= 0x880B	# PPP
ETH_TYPE_MPLS		= 0x8847	# MPLS
ETH_TYPE_MPLS_MCAST	= 0x8848	# MPLS Multicast
ETH_TYPE_PPPoE_DISC	= 0x8863	# PPP Over Ethernet Discovery Stage
ETH_TYPE_PPPoE		= 0x8864	# PPP Over Ethernet Session Stage
ETH_TYPE_LLDP		= 0x88CC	#Link Layer Discovery Protocol

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
		('dst', '6s', ''),
		('src', '6s', ''),
#		('dst', '6B', ''),
#		('src', '6B', ''),
		('vlan', 'H', None),	# skip VLAN per default
		('type', 'H', ETH_TYPE_IP)
		)
	# TODO: no "_"
	__PROG_MAC = re.compile("(\w{2,2}:){5,5}\w{2,2}")

	def __setattr__(self, k, v):
		# convert "AA:BB:CC:DD:EE:FF" to byte representation
		if not type(v).__name__ in ["bytes", "NoneType"] and k in ["dst", "src"] and self.__PROG_MAC.match(v):
			#logger.debug("converting to byte-mac")
			v = b"".join([ bytes.fromhex(x) for x in v.split(":") ])
		pypacker.Packet.__setattr__(self, k, v)

	def __getattribute__(self, k):
		# convert bytes to "AA:BB:CC:DD:EE:FF" representation
		ret = object.__getattribute__(self, k)

		if ret is not None and k in ["dst", "src"]:
			#logger.debug("converting to string-mac")
			ret = "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", ret)
				
		return ret

	def unpack(self, buf):
		logger.debug("Ethernet unpack")
		# we need to check for VLAN here (0x8100) and THEN call super implementation (optional header)
		# TODO: test this
		if len(buf) >= 15:
			if struct.unpack(">BB", buf[13:15])[0] == b"\x81\x00":
				self.vlan = ''
		# unpack header and data. data will become the body data of this layer
		pypacker.Packet.unpack(self, buf)

		if self.type > 1500:
			logger.debug("Ethernet II")
			# Ethernet II
			buf = buf[self.__hdr_len__:]
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
				self.type = struct.unpack('>H', buf[6:8])[0]
				buf = buf[8:]
			else:
				# non-SNAP
				#dsap = ord(buf[0])
				dsap = buf[0]

				if dsap == 0x06: # SAP_IP
					self.type = self._typesw[Ethernet.__class__][ETH_TYPE_IP](buf[3:])
				elif dsap == 0x10 or dsap == 0xe0: # SAP_NETWARE{1,2}
					self.type = self._typesw[Ethernet.__class__][ETH_TYPE_IPX](buf[3:])
				elif dsap == 0x42: # SAP_STP
					self.type = stp.STP(buf[3:])

		try:
			logger.debug("Ethernet set handler: %d" % self.type)
			type_instance = self._handler[Ethernet.__name__][self.type](buf)
			self._set_bodyhandler(type_instance)
		except (KeyError, pypacker.UnpackError) as e:
			logger.debug("Ethernet: coudln't set handler: %s" % e)
			# raw accessible data
			self.data = buf


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
