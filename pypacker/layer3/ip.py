"""Internet Protocol version 4."""

from .. import pypacker
from .. import triggerlist
from .ip_shared import *

import logging
import struct

logger = logging.getLogger("pypacker")

class IPTriggerList(triggerlist.TriggerList):
	def _handle_mod(self, val):
		"""Update header length. NOTE: needs to be a multiple of 4 Bytes."""
		try:
			# TODO: options length need to be multiple of 4 Bytes, allow different lengths?
			hdr_len_off = int(self.packet.hdr_len / 4) & 0xf
			#logger.debug("IP: new hl: %d / %d" % (self.packet.hdr_len, hdr_len_off))
			self.packet.hl = hdr_len_off
		except Exception as e:
			logger.warning("IP: couldn't update header length: %s" % e)

	def _tuples_to_packets(self, tuple_list):
		"""Convert [(IP_OPT_X, b""), ...] to [IPOptX_obj, ...]."""
		opt_packets = []

		# parse tuples to IP-option Packets
		for opt in tuple_list:
			p = None
			if opt[0] in [IP_OPT_EOOL, IP_OPT_NOP]:
				p = IPOptSingle(type=opt[0])
			else:
				p = IPOptMulti(type=opt[0], len=len(opt[1])+2, data=opt[1])
			opt_packets.append(p)
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

class IP(pypacker.Packet):
	"""Convenient access for: src[_s], dst[_s]"""
	__hdr__ = (
		("v_hl", "B", 69),		# = 0x45
		("tos", "B", 0),
		("_len", "H", 20),		# _len = len
		("id", "H", 0),
		("off", "H", 0),
		("ttl", "B", 64),
		("p", "B", 0),
		("_sum", "H", 0),		# _sum = sum
		("src", "4s", b"\x00" * 4),
		("dst", "4s", b"\x00" * 4),
		("opts", None, IPTriggerList)
		)

	def __get_v(self):
		return self.v_hl >> 4
	def __set_v(self, value):
		self.v_hl = (value << 4) | (self.v_hl & 0xf)
	v = property(__get_v, __set_v)

	def __get_hl(self):
		return self.v_hl & 0x0f
	def __set_hl(self, value):
		self.v_hl = (self.v_hl & 0xf0) | value
	hl = property(__get_hl, __set_hl)

	## update length on changes
	def __get_len(self):
		if self._changed():
	 		self._len = len(self)
		return self._len
	def __set_len(self, value):
		self._len = value
	len = property(__get_len, __set_len)

	def __get_sum(self):
		if self.__needs_checksum_update():
			self.__calc_sum()
		return self._sum
	def __set_sum(self, value):
		self._sum = value
		# sum is user-defined
		self._sum_ud = True
	sum = property(__get_sum, __set_sum)

	## convenient access
	src_s = pypacker.Packet._get_property_ip4("src")
	dst_s = pypacker.Packet._get_property_ip4("dst")

	def _dissect(self, buf):
		ol = ((buf[0] & 0xf) << 2) - 20	# total IHL - standard IP-len = options length
		if ol < 0:
			raise UnpackError("IP: invalid header length: %d" % ol)
		elif ol > 0:
			opts = buf[20 : 20 + ol]
			tl_opts = self.__parse_opts(opts)
			#logger.debug("got some IP options: %s" % tl_opts)
			#for o in tl_opts:
			#	logger.debug("%s, len: %d, data: %s" % (o, len(o), o.data))
			self.opts.extend(tl_opts)

		type = buf[9]
		self._parse_handler(type, buf, offset_start=self.hdr_len)

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
				p = IPOptMulti(type=buf[i], len=olen, data=buf[ i+2 : i+olen ])
				i += olen	# typefield + lenfield + data-len
			optlist.append(p)

		return optlist

	def bin(self):
		if self._changed():
			# changes in length when: more IP options or data
			# TODO: update on header/data-changes could be redundant
			#logger.debug(">>> IP: updating length because of changes")
			self._len = len(self)

			if self.__needs_checksum_update():
				#logger.debug(">>> IP: header changed, calculating sum (bin)")
				self.__calc_sum()
		# on changes this will return a fresh length
		return pypacker.Packet.bin(self)

	def __needs_checksum_update(self):
		"""
		IP-checksum needs to be updated if header changed and sum was
		not set directly by user.
		"""
		# don't change user defined sum, LBYL: this is unlikely
		if hasattr(self, "_sum_ud"):
			#logger.debug("sum was user-defined, return")
			return False

		return self._header_changed

	# TODO: check if checksum update is needed
	def __calc_sum(self):
		"""Recalculate checksum."""
		#logger.debug(">>> IP: calculating sum")
		# reset checksum for recalculation,  mark as changed / clear cache
		self._sum = 0
		#logger.debug(">>> IP: bytes for sum: %s" % self.pack_hdr())
		self._sum = pypacker.in_cksum( self.pack_hdr() )

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

	def _callback_impl(self, id):
		"""Callback to get data needed for checksum-computation. Used id: 'ip_src_dst_changed'"""
		# TCP and underwriting are freaky bitches: we need the IP pseudoheader to calculate
		# their checksum. A TCP (6) or UDP (17)layer uses a callback to IP get the needed information.
		if id == "ip_src_dst_changed":
			return self.src, self.dst, self.header_changed


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

# load handler
from pypacker.layer3 import esp, icmp, igmp, ip6, ipx, pim
from pypacker.layer4 import tcp, udp, sctp

pypacker.Packet.load_handler(IP,
				{
				IP_PROTO_IP : IP,
				IP_PROTO_ICMP : icmp.ICMP,
				IP_PROTO_IGMP : igmp.IGMP,
				IP_PROTO_TCP : tcp.TCP,
				IP_PROTO_UDP : udp.UDP,
				IP_PROTO_IP6 : ip6.IP6,
				IP_PROTO_ESP : esp.ESP,
				# TODO: update AH
				#IP_PROTO_AH : ah.AH,
				IP_PROTO_PIM : pim.PIM,
				IP_PROTO_IPXIP : ipx.IPX,
				IP_PROTO_SCTP : sctp.SCTP
				}
				)
