"""Internet Protocol."""

from .. import pypacker

import copy
import logging
import re
import struct

logger = logging.getLogger("pypacker")

class IP(pypacker.Packet):
	"""Convenient access for: src[_s], dst[_s]"""
	__hdr__ = (
		("v_hl", "B", (4 << 4) | (20 >> 2)),
		("tos", "B", 0),
		("_len", "H", 20),		# _len = len
		("id", "H", 0),
		("off", "H", 0),
		("ttl", "B", 64),
		("p", "B", 0),
		("_sum", "H", 0),		# _sum = sum
		("src", "4s", b"\x00" * 4),
		("dst", "4s", b"\x00" * 4)
						# _opts = opts
		)

	def getv(self):
		return self.v_hl >> 4
	def setv(self, value):
		self.v_hl = (value << 4) | (self.v_hl & 0xf)
	v = property(getv, setv)
	def gethl(self):
		return self.v_hl & 0xf
	def sethl(self, value):
		self.v_hl = (self.v_hl & 0xf0) | value
	hl = property(gethl, sethl)
	## update length on changes
	def getlen(self):
		if self._changed():
	 		self._len = len(self)
		return self._len
	def setlen(self, value):
		self._len = value
	len = property(getlen, setlen)
	def getsum(self):
		if self.header_changed:
		# change to header = we need a checksum update
		#if self._header_cached is None:
			self.__calc_sum()
		return self._sum
	def setsum(self, value):
		self._sum = value
	sum = property(getsum, setsum)
	## convenient access
	def getsrc_s(self):
		return "%d.%d.%d.%d" % struct.unpack("BBBB", self.src)
	def setsrc_s(self, value):
		ips = [ int(x) for x in value.split(".")]
		value = struct.pack("BBBB", ips[0], ips[1], ips[2], ips[3])
		self.src = value
	src_s = property(getsrc_s, setsrc_s)
	def getdst_s(self):
		return "%d.%d.%d.%d" % struct.unpack("BBBB", self.dst)
	def setdst_s(self, value):
		ips = [ int(x) for x in value.split(".")]
		value = struct.pack("BBBB", ips[0], ips[1], ips[2], ips[3])
		self.dst = value
	dst_s = property(getdst_s, setdst_s)
	## lazy init of dynamic header
	def getopts(self):
		if not hasattr(self, "_opts"):
			tl = IPTriggerList()
			self._add_headerfield("_opts", "", tl)
		return self._opts
	def setopts(self, value):
		self._opts = value
	#opts = property(getopts, setopts)
	opts = property(getopts)

	def _unpack(self, buf):
		ol = ((buf[0] & 0xf) << 2) - 20	# total IHL - standard IP-len = options length
		if ol < 0:
			raise UnpackError("IP: invalid header length: %d" % ol)
		elif ol > 0:
			opts = buf[20 : 20 + ol]
			# IP opts: make them accessible via ip.options using Packets
			#logger.debug("got some IP options")
			tl_opts = self.__parse_opts(opts)
			self._add_headerfield("_opts", "", tl_opts)

		# now we know the real header length
		buf_data = buf[self.__hdr_len__:]

		try:
			type = buf[9]
			# fix: https://code.google.com/p/pypacker/issues/attachmentText?id=75
			#if self.off & 0x1fff > 0:
			#	raise KeyError
			#logger.debug(">>> IP: trying to set handler, type: %d = %s" % (123, pypacker.Packet._handler[IP.__name__][type]))
			#logger.debug(">>> IP: trying to set handler, type: %d = %s" % (123, pypacker.Packet._handler[IP.__name__]))
			type_instance = self._handler[IP.__name__][type](buf_data)
			# set callback to calculate checksum
			type_instance.callback = self.callback_impl
			self._set_bodyhandler(type_instance)
		# any exception will lead to: body = raw bytes
		except Exception as ex:
			logger.debug(">>> IP: couldn't set handler: %d -> %s" % (type, ex))
			pass

		pypacker.Packet._unpack(self, buf)

	def __parse_opts(self, buf):
		"""Parse IP options and return them as TriggerList."""
		optlist = []
		i = 0
		p = None

		while i < len(buf):
			#logger.debug("got IP-option type %s" % buf[i])
			if buf[i] in [IP_OPT_EOOL, IP_OPT_NOP]:
				p = IPOptSingle(type=buf[i])
				i += 1
			else:
				olen = buf[i + 1]
				p = IPOptMulti(type=buf[i], len=olen, data= buf[ i+2 : i+2+olen ])
				i += 2+olen	# typefield + lenfield + data-len
			optlist.append( p )

		#return TriggerList(optlist)
		return IPTriggerList(optlist)

	def bin(self):
		if self._changed():
			#logger.debug(">>> IP: updating length because of changes")
			if self.header_changed:
				self.__calc_sum()
			# update length on changes
			object.__setattr__(self, "_len", len(self))
			#self.len = len(self)
		# on changes this will return a fresh length
		return pypacker.Packet.bin(self)

	def __calc_sum(self):
		"""Recalculate checksum."""
		#logger.debug("calculating sum")
		# reset checksum for recalculation
		#logger.debug("header is: %s" % self.pack_hdr(cached=False))
		object.__setattr__(self, "_sum", 0)
		object.__setattr__(self, "_sum", pypacker.in_cksum(self.pack_hdr()) )

	def direction(self, next, last_packet=None):
		#logger.debug("checking direction: %s<->%s" % (self, next))

		if self.src == next.src and self.dst == next.dst:
			direction = pypacker.Packet.DIR_SAME
		elif self.src == next.dst and self.dst == next.src:
			direction = pypacker.Packet.DIR_REV
		else:
			direction = pypacker.Packet.DIR_BOTH
		# delegate to super implementation for further checks
		return direction | pypacker.Packet.direction(self, next, last_packet)

	def callback_impl(self, id):
		"""Callback to get data needed for checksum-computation. Used id: 'ip_src_dst_changed'"""
		# TCP and underwriting are freaky bitches: we need the IP pseudoheader to calculate
		# their checksum. A TCP (6) or UDP (17)layer uses a callback to IP get the needed information.
		if id == "ip_src_dst_changed":
			return self.src, self.dst, self.header_changed


class IPTriggerList(pypacker.TriggerList):
	"""DHCP-TriggerList to enable "opts += [(DHCP_OPT_X, b"xyz")], opts[x] = (DHCP_OPT_X, b"xyz")",
	length should be auto-calculated."""
	def __iadd__(self, li):
		"""TCP-options are added via opts += [(TCP_OPT_X, b"xyz")]."""
		return pypacker.TriggerList.__iadd__(self, self.__tuple_to_opt(li))

	def __setitem__(self, k, v):
		"""TCP-options are set via opts[x] = (TCP_OPT_X, b"xyz")."""
		pypacker.TriggerList.__setitem__(self, k, self.__tuple_to_opt([v]))

	def _handle_mod(self, val, add_listener):
		"""Update header length. NOTE: needs to be a multiple of 4 Bytes."""
		# packet should be allready present after adding this TriggerList as field.
		# we need to update format prior to get the correct header length: this
		# should have allready happened
		try:
			# TODO: options length need to be multiple of 4 Bytes, allow different lengths?
			hdr_len_off = int(self.packet.__hdr_len__ / 4) & 0xf
			self.packet.hl = hdr_len_off
		except Exception as e:
			logger.warning("IP: couldn't update header length: %s" % e)

		pypacker.TriggerList._handle_mod(self, val, add_listener=add_listener)

	def __tuple_to_opt(self, tuple_list):
		"""convert [(IP_OPT_X, b""), ...] to [IPOptX_obj, ...]."""
		opt_packets = []

		# parse tuples to IP-option Packets
		for opt in tuple_list:
			p = None
			if opt[0] in [IP_OPT_EOOL, IP_OPT_NOP]:
				p = IPOptSingle(type=opt[0])
			else:
				p = IPOptMulti(type=opt[0], len=len(opt[1]), data=opt[1])
			opt_packets += p
		return opt_packets


class IPOptSingle(pypacker.Packet):
	__hdr__ = (
		("type", "B", 0),
		)

class IPOptMulti(pypacker.Packet):
	__hdr__ = (
		("type", "B", 0),
		("len", "B", 0),
		)

# Type of service (ip_tos), RFC 1349 ("obsoleted by RFC 2474")
IP_TOS_DEFAULT			= 0x00	# default
IP_TOS_LOWDELAY			= 0x10	# low delay
IP_TOS_THROUGHPUT		= 0x08	# high throughput
IP_TOS_RELIABILITY		= 0x04	# high reliability
IP_TOS_LOWCOST			= 0x02	# low monetary cost - XXX
IP_TOS_ECT			= 0x02	# ECN-capable transport
IP_TOS_CE			= 0x01	# congestion experienced

# IP precedence (high 3 bits of ip_tos), hopefully unused
IP_TOS_PREC_ROUTINE		= 0x00
IP_TOS_PREC_PRIORITY		= 0x20
IP_TOS_PREC_IMMEDIATE		= 0x40
IP_TOS_PREC_FLASH		= 0x60
IP_TOS_PREC_FLASHOVERRIDE	= 0x80
IP_TOS_PREC_CRITIC_ECP		= 0xa0
IP_TOS_PREC_INTERNETCONTROL	= 0xc0
IP_TOS_PREC_NETCONTROL		= 0xe0

# Fragmentation flags (ip_off)
IP_RF				= 0x8000	# reserved
IP_DF				= 0x4000	# don't fragment
IP_MF				= 0x2000	# more fragments (not last frag)
IP_OFFMASK			= 0x1fff	# mask for fragment offset

# Time-to-live (ip_ttl), seconds
IP_TTL_DEFAULT			= 64		# default ttl, RFC 1122, RFC 1340
IP_TTL_MAX			= 255		# maximum ttl

# IP options
# http://www.iana.org/assignments/ip-parameters/ip-parameters.xml
IP_OPT_EOOL			= 0
IP_OPT_NOP			= 1
IP_OPT_SEC			= 2
IP_OPT_LSR			= 3
IP_OPT_TS			= 4
IP_OPT_ESEC			= 5
IP_OPT_CIPSO			= 6
IP_OPT_RR			= 7
IP_OPT_SID			= 8
IP_OPT_SSR			= 9
IP_OPT_ZSU			= 10
IP_OPT_MTUP			= 11
IP_OPT_MTUR			= 12
IP_OPT_FINN			= 13
IP_OPT_VISA			= 14
IP_OPT_ENCODE			= 15
IP_OPT_IMITD			= 16
IP_OPT_EIP			= 17
IP_OPT_TR			= 18
IP_OPT_ADDEXT			= 19
IP_OPT_RTRALT			= 20
IP_OPT_SDB			= 21
IP_OPT_UNASSGNIED		= 22
IP_OPT_DPS			= 23
IP_OPT_UMP			= 24
IP_OPT_QS			= 25
IP_OPT_EXP			= 30

# Protocol (ip_p) - http://www.iana.org/assignments/protocol-numbers
IP_PROTO_IP			= 0		# dummy for IP
IP_PROTO_HOPOPTS		= IP_PROTO_IP	# IPv6 hop-by-hop options
IP_PROTO_ICMP			= 1		# ICMP
IP_PROTO_IGMP			= 2		# IGMP
IP_PROTO_GGP			= 3		# gateway-gateway protocol
IP_PROTO_IPIP			= 4		# IP in IP
IP_PROTO_ST			= 5		# ST datagram mode
IP_PROTO_TCP			= 6		# TCP
IP_PROTO_CBT			= 7		# CBT
IP_PROTO_EGP			= 8		# exterior gateway protocol
IP_PROTO_IGP			= 9		# interior gateway protocol
IP_PROTO_BBNRCC			= 10		# BBN RCC monitoring
IP_PROTO_NVP			= 11		# Network Voice Protocol
IP_PROTO_PUP			= 12		# PARC universal packet
IP_PROTO_ARGUS			= 13		# ARGUS
IP_PROTO_EMCON			= 14		# EMCON
IP_PROTO_XNET			= 15		# Cross Net Debugger
IP_PROTO_CHAOS			= 16		# Chaos
IP_PROTO_UDP			= 17		# UDP
IP_PROTO_MUX			= 18		# multiplexing
IP_PROTO_DCNMEAS		= 19		# DCN measurement
IP_PROTO_HMP			= 20		# Host Monitoring Protocol
IP_PROTO_PRM			= 21		# Packet Radio Measurement
IP_PROTO_IDP			= 22		# Xerox NS IDP
IP_PROTO_TRUNK1			= 23		# Trunk-1
IP_PROTO_TRUNK2			= 24		# Trunk-2
IP_PROTO_LEAF1			= 25		# Leaf-1
IP_PROTO_LEAF2			= 26		# Leaf-2
IP_PROTO_RDP			= 27		# "Reliable Datagram" proto
IP_PROTO_IRTP			= 28		# Inet Reliable Transaction
IP_PROTO_TP			= 29		# ISO TP class 4
IP_PROTO_NETBLT			= 30		# Bulk Data Transfer
IP_PROTO_MFPNSP			= 31		# MFE Network Services
IP_PROTO_MERITINP		= 32		# Merit Internodal Protocol
IP_PROTO_SEP			= 33		# Sequential Exchange proto
IP_PROTO_3PC			= 34		# Third Party Connect proto
IP_PROTO_IDPR			= 35		# Interdomain Policy Route
IP_PROTO_XTP			= 36		# Xpress Transfer Protocol
IP_PROTO_DDP			= 37		# Datagram Delivery Proto
IP_PROTO_CMTP			= 38		# IDPR Ctrl Message Trans
IP_PROTO_TPPP			= 39		# TP++ Transport Protocol
IP_PROTO_IL			= 40		# IL Transport Protocol
IP_PROTO_IP6			= 41		# IPv6
IP_PROTO_SDRP			= 42		# Source Demand Routing
IP_PROTO_ROUTING		= 43		# IPv6 routing header
IP_PROTO_FRAGMENT		= 44		# IPv6 fragmentation header
IP_PROTO_RSVP			= 46		# Reservation protocol
IP_PROTO_GRE			= 47		# General Routing Encap
IP_PROTO_MHRP			= 48		# Mobile Host Routing
IP_PROTO_ENA			= 49		# ENA
IP_PROTO_ESP			= 50		# Encap Security Payload
IP_PROTO_AH			= 51		# Authentication Header
IP_PROTO_INLSP			= 52		# Integated Net Layer Sec
IP_PROTO_SWIPE			= 53		# SWIPE
IP_PROTO_NARP			= 54		# NBMA Address Resolution
IP_PROTO_MOBILE			= 55		# Mobile IP, RFC 2004
IP_PROTO_TLSP			= 56		# Transport Layer Security
IP_PROTO_SKIP			= 57		# SKIP
IP_PROTO_ICMP6			= 58		# ICMP for IPv6
IP_PROTO_NONE			= 59		# IPv6 no next header
IP_PROTO_DSTOPTS		= 60		# IPv6 destination Woptions
IP_PROTO_ANYHOST		= 61		# any host internal proto
IP_PROTO_CFTP			= 62		# CFTP
IP_PROTO_ANYNET			= 63		# any local network
IP_PROTO_EXPAK			= 64		# SATNET and Backroom EXPAK
IP_PROTO_KRYPTOLAN		= 65		# Kryptolan
IP_PROTO_RVD			= 66		# MIT Remote Virtual Disk
IP_PROTO_IPPC			= 67		# Inet Pluribus Packet Core
IP_PROTO_DISTFS			= 68		# any distributed fs
IP_PROTO_SATMON			= 69		# SATNET Monitoring
IP_PROTO_VISA			= 70		# VISA Protocol
IP_PROTO_IPCV			= 71		# Inet Packet Core Utility
IP_PROTO_CPNX			= 72		# Comp Proto Net Executive
IP_PROTO_CPHB			= 73		# Comp Protocol Heart Beat
IP_PROTO_WSN			= 74		# Wang Span Network
IP_PROTO_PVP			= 75		# Packet Video Protocol
IP_PROTO_BRSATMON		= 76		# Backroom SATNET Monitor
IP_PROTO_SUNND			= 77		# SUN ND Protocol
IP_PROTO_WBMON			= 78		# WIDEBAND Monitoring
IP_PROTO_WBEXPAK		= 79		# WIDEBAND EXPAK
IP_PROTO_EON			= 80		# ISO CNLP
IP_PROTO_VMTP			= 81		# Versatile Msg Transport
IP_PROTO_SVMTP			= 82		# Secure VMTP
IP_PROTO_VINES			= 83		# VINES
IP_PROTO_TTP			= 84		# TTP
IP_PROTO_NSFIGP			= 85		# NSFNET-IGP
IP_PROTO_DGP			= 86		# Dissimilar Gateway Proto
IP_PROTO_TCF			= 87		# TCF
IP_PROTO_EIGRP			= 88		# EIGRP
IP_PROTO_OSPF			= 89		# Open Shortest Path First
IP_PROTO_SPRITERPC		= 90		# Sprite RPC Protocol
IP_PROTO_LARP			= 91		# Locus Address Resolution
IP_PROTO_MTP			= 92		# Multicast Transport Proto
IP_PROTO_AX25			= 93		# AX.25 Frames
IP_PROTO_IPIPENCAP		= 94		# yet-another IP encap
IP_PROTO_MICP			= 95		# Mobile Internet Ctrl
IP_PROTO_SCCSP			= 96		# Semaphore Comm Sec Proto
IP_PROTO_ETHERIP		= 97		# Ethernet in IPv4
IP_PROTO_ENCAP			= 98		# encapsulation header
IP_PROTO_ANYENC			= 99		# private encryption scheme
IP_PROTO_GMTP			= 100		# GMTP
IP_PROTO_IFMP			= 101		# Ipsilon Flow Mgmt Proto
IP_PROTO_PNNI			= 102		# PNNI over IP
IP_PROTO_PIM			= 103		# Protocol Indep Multicast
IP_PROTO_ARIS			= 104		# ARIS
IP_PROTO_SCPS			= 105		# SCPS
IP_PROTO_QNX			= 106		# QNX
IP_PROTO_AN			= 107		# Active Networks
IP_PROTO_IPCOMP			= 108		# IP Payload Compression
IP_PROTO_SNP			= 109		# Sitara Networks Protocol
IP_PROTO_COMPAQPEER		= 110		# Compaq Peer Protocol
IP_PROTO_IPXIP			= 111		# IPX in IP
IP_PROTO_VRRP			= 112		# Virtual Router Redundancy
IP_PROTO_PGM			= 113		# PGM Reliable Transport
IP_PROTO_ANY0HOP		= 114		# 0-hop protocol
IP_PROTO_L2TP			= 115		# Layer 2 Tunneling Proto
IP_PROTO_DDX			= 116		# D-II Data Exchange (DDX)
IP_PROTO_IATP			= 117		# Interactive Agent Xfer
IP_PROTO_STP			= 118		# Schedule Transfer Proto
IP_PROTO_SRP			= 119		# SpectraLink Radio Proto
IP_PROTO_UTI			= 120		# UTI
IP_PROTO_SMP			= 121		# Simple Message Protocol
IP_PROTO_SM			= 122		# SM
IP_PROTO_PTP			= 123		# Performance Transparency
IP_PROTO_ISIS			= 124		# ISIS over IPv4
IP_PROTO_FIRE			= 125		# FIRE
IP_PROTO_CRTP			= 126		# Combat Radio Transport
IP_PROTO_CRUDP			= 127		# Combat Radio UDP
IP_PROTO_SSCOPMCE		= 128		# SSCOPMCE
IP_PROTO_IPLT			= 129		# IPLT
IP_PROTO_SPS			= 130		# Secure Packet Shield
IP_PROTO_PIPE			= 131		# Private IP Encap in IP
IP_PROTO_SCTP			= 132		# Stream Ctrl Transmission
IP_PROTO_FC			= 133		# Fibre Channel
IP_PROTO_RSVPIGN		= 134		# RSVP-E2E-IGNORE
IP_PROTO_RAW			= 255		# Raw IP packets
IP_PROTO_RESERVED		= IP_PROTO_RAW	# Reserved
IP_PROTO_MAX			= 255

pypacker.Packet.load_handler(globals(), IP, "IP_PROTO_", ["layer3", "layer4"])
