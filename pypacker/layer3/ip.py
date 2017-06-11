"""
Internet Protocol version 4.

RFC 791
"""
import logging

from pypacker import pypacker, triggerlist, checksum
from pypacker.layer3.ip_shared import IP_PROTO_IP6, IP_PROTO_ICMP, IP_PROTO_IGMP, IP_PROTO_TCP, IP_PROTO_UDP, IP_PROTO_ESP, IP_PROTO_PIM, IP_PROTO_IPXIP, IP_PROTO_SCTP, IP_PROTO_OSPF
from pypacker.pypacker import FIELD_FLAG_AUTOUPDATE, FIELD_FLAG_IS_TYPEFIELD
# handler
from pypacker.layer3 import esp, icmp, igmp, ip6, ipx, ospf, pim
from pypacker.layer4 import tcp, udp, sctp


logger = logging.getLogger("pypacker")

# avoid references for performance reasons
in_cksum = checksum.in_cksum

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


class IPOptSingle(pypacker.Packet):
	__hdr__ = (
		("type", "B", 0),
	)


class IPOptMulti(pypacker.Packet):
	"""
	len = total length (header + data)
	"""
	__hdr__ = (
		("type", "B", 0),
		("len", "B", 2),
	)

	def bin(self, update_auto_fields=True):
		if update_auto_fields:
			self.len = len(self)
		return pypacker.Packet.bin(self, update_auto_fields=update_auto_fields)


class IP(pypacker.Packet):
	__hdr__ = (
		("v_hl", "B", 69, FIELD_FLAG_AUTOUPDATE),  # = 0x45
		("tos", "B", 0),
		("len", "H", 20, FIELD_FLAG_AUTOUPDATE),
		("id", "H", 0),
		# TODO: rename to frag_off
		("off", "H", 0),
		("ttl", "B", 64),
		("p", "B", IP_PROTO_TCP, FIELD_FLAG_AUTOUPDATE | FIELD_FLAG_IS_TYPEFIELD),
		("sum", "H", 0, FIELD_FLAG_AUTOUPDATE),
		("src", "4s", b"\x00" * 4),
		("dst", "4s", b"\x00" * 4),
		("opts", None, triggerlist.TriggerList)
	)

	__handler__ = {
		IP_PROTO_ICMP: icmp.ICMP,
		IP_PROTO_IGMP: igmp.IGMP,
		IP_PROTO_TCP: tcp.TCP,
		IP_PROTO_UDP: udp.UDP,
		IP_PROTO_IP6: ip6.IP6,
		IP_PROTO_ESP: esp.ESP,
		IP_PROTO_PIM: pim.PIM,
		IP_PROTO_IPXIP: ipx.IPX,
		IP_PROTO_SCTP: sctp.SCTP,
		IP_PROTO_OSPF: ospf.OSPF
	}

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

	def __get_flags(self):
		return (self.off & 0xE000) >> 13

	def __set_flags(self, value):
		self.off = (self.off & ~0xE000) | (value << 13)
	flags = property(__get_flags, __set_flags)

	def __get_offset(self):
		return self.off & ~0xE000

	def __set_offset(self, value):
		self.off = (self.off & 0xE000) | value
	offset = property(__get_offset, __set_offset)

	def create_fragments(self, fragment_len=1480):
		"""
		Create fragment packets from this IP packet with max fragment_len bytes each.
		This will set the flags and offset values accordingly (see header field off).

		fragment_len -- max length of a fragment (IP header + payload)
		return -- fragment IP packets created from this packet
		"""
		if fragment_len % 8 != 0:
			raise Exception("fragment_len not multipe of 8 bytes: %r" % fragment_len)

		fragments = []
		length_ip_total = len(self.bin())
		payload = self.body_bytes
		length_ip_header = length_ip_total - len(payload)
		length_payload = length_ip_total - length_ip_header

		off = 0

		while off < length_payload:
			payload_sub = payload[off: off + fragment_len]

			ip_frag = IP(id=self.id, p=self.p, src=self.src, dst=self.dst)

			if length_payload - off > fragment_len:
				# more fragments follow
				ip_frag.flags = 0x1
			else:
				# last fragment
				ip_frag.flags = 0x0

			ip_frag.offset = int(off / 8)
			ip_frag.body_bytes = payload_sub
			fragments.append(ip_frag)
			off += fragment_len

		return fragments

	# Convenient access for: src[_s], dst[_s]
	src_s = pypacker.get_property_ip4("src")
	dst_s = pypacker.get_property_ip4("dst")

	def _dissect(self, buf):
		total_header_length = ((buf[0] & 0xf) << 2)
		options_length = total_header_length - 20		# total IHL - standard IP-len = options length

		if options_length < 0:
			# invalid header length: assume no options at all
			raise Exception("invalid header length: %d" % options_length)
		elif options_length > 0:
			# logger.debug("got some IP options: %s" % tl_opts)
			self._init_triggerlist("opts", buf[20: 20 + options_length], self.__parse_opts)

		self._init_handler(buf[9], buf[total_header_length:])
		return total_header_length

	__IP_OPT_SINGLE = {IP_OPT_EOOL, IP_OPT_NOP}

	@staticmethod
	def __parse_opts(buf):
		"""Parse IP options and return them as list."""
		optlist = []
		i = 0
		p = None

		while i < len(buf):
			# logger.debug("got IP-option type %s" % buf[i])
			if buf[i] in IP.__IP_OPT_SINGLE:
				p = IPOptSingle(type=buf[i])
				i += 1
			else:
				olen = buf[i + 1]
				# logger.debug("IPOptMulti")
				p = IPOptMulti(type=buf[i], len=olen, body_bytes=buf[i + 2: i + olen])
				# logger.debug("body bytes: %s" % buf[i + 2: i + olen])
				i += olen		# typefield + lenfield + data-len
				# logger.debug("IPOptMulti 2")
			optlist.append(p)
		return optlist

	def bin(self, update_auto_fields=True):
		if update_auto_fields and self._changed():
			self._update_bodyhandler_id()

			if self.len_au_active:
				self.len = len(self)
			if self.v_hl_au_active:
				# Update header length. NOTE: needs to be a multiple of 4 Bytes.
				# logger.debug("updating: %r" % self._packet)
					# options length need to be multiple of 4 Bytes
				self.hl = int(self.header_len / 4) & 0xf
			if self.sum_au_active:
				# length changed so we have to recalculate checksum
				# logger.debug(">>> IP: calculating sum")
				# reset checksum for recalculation,  mark as changed / clear cache
				self.sum = 0
				# logger.debug(">>> IP: bytes for sum: %s" % self.header_bytes)
				self.sum = in_cksum(self._pack_header())
				# logger.debug("IP: new hl: %d / %d" % (self._packet.hdr_len, hdr_len_off))
				# logger.debug("new sum: %0X" % self.sum)

		return pypacker.Packet.bin(self, update_auto_fields=update_auto_fields)

	def direction(self, other):
		# logger.debug("checking direction: %s<->%s" % (self, next))
		# TODO: handle broadcast
		if self.src == other.src and self.dst == other.dst:
			# consider packet to itself: can be DIR_REV
			return pypacker.Packet.DIR_SAME | pypacker.Packet.DIR_REV
		elif self.src == other.dst and self.dst == other.src:
			return pypacker.Packet.DIR_REV
		else:
			return pypacker.Packet.DIR_UNKNOWN

	def reverse_address(self):
		self.src, self.dst = self.dst, self.src


# Type of service (ip_tos), RFC 1349 ("obsoleted by RFC 2474")
IP_TOS_DEFAULT			= 0x00			# default
IP_TOS_LOWDELAY			= 0x10			# low delay
IP_TOS_THROUGHPUT		= 0x08			# high throughput
IP_TOS_RELIABILITY		= 0x04			# high reliability
IP_TOS_LOWCOST			= 0x02			# low monetary cost - XXX
IP_TOS_ECT			= 0x02			# ECN-capable transport
IP_TOS_CE			= 0x01			# congestion experienced

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
IP_RF				= 0x8000		# reserved
IP_DF				= 0x4000		# don't fragment
IP_MF				= 0x2000		# more fragments (not last frag)
IP_OFFMASK			= 0x1fff		# mask for fragment offset

# Time-to-live (ip_ttl), seconds
IP_TTL_DEFAULT			= 64			# default ttl, RFC 1122, RFC 1340
IP_TTL_MAX			= 255			# maximum ttl
