"""
Linux cooked capture format
"""
import logging
import struct

from pypacker import pypacker

# handler
from pypacker.layer12 import can, arp, dtp, pppoe
from pypacker.layer3 import ip, ip6, ipx

# avoid references for performance reasons
unpack_H = struct.Struct(">H").unpack
logger = logging.getLogger("pypacker")

# Ethernet payload types - http://standards.ieee.org/regauth/ethertype
LCC_TYPE_CAN		= 0x000C		# CAN protocol
LCC_TYPE_PUP		= 0x0200		# PUP protocol
LCC_TYPE_IP		= 0x0800		# IPv4 protocol
LCC_TYPE_ARP		= 0x0806		# address resolution protocol
LCC_TYPE_WOL		= 0x0842		# Wake on LAN
LCC_TYPE_CDP		= 0x2000		# Cisco Discovery Protocol
LCC_TYPE_DTP		= 0x2004		# Cisco Dynamic Trunking Protocol
LCC_TYPE_REVARP		= 0x8035		# reverse addr resolution protocol
LCC_TYPE_ETHTALK	= 0x809B		# Apple Talk
LCC_TYPE_AARP		= 0x80F3		# Appletalk Address Resolution Protocol
LCC_TYPE_8021Q		= 0x8100		# IEEE 802.1Q VLAN tagging
LCC_TYPE_IPX		= 0x8137		# Internetwork Packet Exchange
LCC_TYPE_NOV		= 0x8138		# Novell
LCC_TYPE_IP6		= 0x86DD		# IPv6 protocol
LCC_TYPE_MPLS_UCAST	= 0x8847		# MPLS unicast
LCC_TYPE_MPLS_MCAST	= 0x8848		# MPLS multicast
LCC_TYPE_PPOE_DISC	= 0x8863		# PPPoE Discovery
LCC_TYPE_PPOE_SESS	= 0x8864		# PPPoE Session
LCC_TYPE_JUMBOF		= 0x8870		# Jumbo Frames
LCC_TYPE_PROFINET	= 0x8892		# Realtime-Ethernet PROFINET
LCC_TYPE_ATAOE		= 0x88A2		# ATA other Ethernet
LCC_TYPE_ETHERCAT	= 0x88A4		# Realtime-Ethernet Ethercat
LCC_TYPE_PBRIDGE	= 0x88A8		# Provider Briding
LCC_TYPE_POWERLINK	= 0x88AB		# Realtime Ethernet POWERLINK
LCC_TYPE_LLDP		= 0x88CC		# Link Layer Discovery Protocol
LCC_TYPE_SERCOS		= 0x88CD		# Realtime Ethernet SERCOS III
LCC_TYPE_FIBRE_ETH	= 0x8906		# Fibre Channel over Ethernet
LCC_TYPE_FCOE		= 0x8914		# FCoE Initialization Protocol (FIP)

PACKET_DIR_TO_US	= 0
PACKET_DIR_FROM_US	= 4


class LinuxCC(pypacker.Packet):
	__hdr__ = (
		("dir", "H", 4),
		("addrtype", "H", 0),
		("addrlen", "H", 0),
		("info", "Q", 0),
		("type", "H", LCC_TYPE_IP)
	)

	__handler__ = {
		LCC_TYPE_CAN: can.CAN,
		LCC_TYPE_IP: ip.IP,
		LCC_TYPE_ARP: arp.ARP,
		LCC_TYPE_DTP: dtp.DTP,
		LCC_TYPE_IPX: ipx.IPX,
		LCC_TYPE_IP6: ip6.IP6,
		LCC_TYPE_PPOE_DISC: pppoe.PPPoE,
		LCC_TYPE_PPOE_SESS: pppoe.PPPoE
	}

	def _dissect(self, buf):
		htype = unpack_H(buf[14: 16])[0]
		# logger.debug("type: %X" % type)
		self._init_handler(htype, buf[16:])
		return 16
