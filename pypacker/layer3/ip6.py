"""
Internet Protocol version 6..for whoever needs it (:

RFC 2460
"""
import logging

from pypacker import pypacker, triggerlist
from pypacker.layer3.ip_shared import IP_PROTO_HOPOPTS, IP_PROTO_ROUTING, IP_PROTO_FRAGMENT, IP_PROTO_AH, IP_PROTO_ESP, IP_PROTO_DSTOPTS, IP_PROTO_ICMP6, IP_PROTO_IGMP, IP_PROTO_TCP, IP_PROTO_UDP, IP_PROTO_IP6, IP_PROTO_PIM, IP_PROTO_IPXIP, IP_PROTO_SCTP, IP_PROTO_OSPF
# handler
from pypacker.layer3 import esp, icmp6, igmp, ipx, ospf, pim
from pypacker.layer4 import tcp, udp, sctp


logger = logging.getLogger("pypacker")

# TODO: to be implemented
# Encapsulation Security Payload Header = 50
# IP_PROTO_MOBILITY	= 135
# IP_PROTO_NONEXT	= 59


ext_hdrs = {
		IP_PROTO_HOPOPTS,
		IP_PROTO_ROUTING,
		IP_PROTO_FRAGMENT,
		IP_PROTO_AH,
		IP_PROTO_ESP,
		IP_PROTO_DSTOPTS,
		# TODO: to be implemented
		# IP_PROTO_MOBILITY
		# IP_PROTO_NONEXT
	}


class IP6(pypacker.Packet):
	__hdr__ = (
		("v_fc_flow", "I", 0x60000000),
		("dlen", "H", 0),		# payload length (not including standard header)
		("nxt", "B", 0),		# next header protocol
		("hlim", "B", 0),		# hop limit
		("src", "16s", b"\x00" * 16),
		("dst", "16s", b"\x00" * 16),
		("opts", None, triggerlist.TriggerList)
	)

	def __get_v(self):
		return self.v_fc_flow >> 28

	def __set_v(self, v):
		self.v_fc_flow = (self.v_fc_flow & ~0xf0000000) | (v << 28)
	v = property(__get_v, __set_v)

	def __get_fc(self):
		return (self.v_fc_flow >> 20) & 0xff

	def __set_fc(self, v):
		self.v_fc_flow = (self.v_fc_flow & ~0xff00000) | (v << 20)
	fc = property(__get_fc, __set_fc)

	def __get_flow(self):
		return self.v_fc_flow & 0xfffff

	def __set_flow(self, v):
		self.v_fc_flow = (self.v_fc_flow & ~0xfffff) | (v & 0xfffff)
	flow = property(__get_flow, __set_flow)

	# Convenient access for: src[_s], dst[_s]
	src_s = pypacker.get_property_ip6("src")
	dst_s = pypacker.get_property_ip6("dst")

	__handler__ = {
		IP_PROTO_ICMP6: icmp6.ICMP6,
		IP_PROTO_IGMP: igmp.IGMP,
		IP_PROTO_TCP: tcp.TCP,
		IP_PROTO_UDP: udp.UDP,
		IP_PROTO_ESP: esp.ESP,
		IP_PROTO_PIM: pim.PIM,
		IP_PROTO_IPXIP: ipx.IPX,
		IP_PROTO_SCTP: sctp.SCTP,
		IP_PROTO_OSPF: ospf.OSPF
	}

	def _dissect(self, buf):
		type_nxt = buf[6]
		off = 40
		opts = []

		# logger.debug("type: %d buflen: %d" % (type_nxt, len(buf)))
		# logger.debug("parsing opts from bytes (dst: %s): (len: %d) %s" %
		#	 (buf[24:40], self.hdr_len, buf[off:]))
		# parse options until type is an upper layer one
		while type_nxt in ext_hdrs:
			length = 8 + buf[off + 1] * 8
			# logger.debug("next type is: %s, len: %d, %r" % (type_nxt, length, buf[off:off + length]))
			opt = ext_hdrs_cls[type_nxt](buf[off:off + length])
			opts.append(opt)
			type_nxt = buf[off]
			off += length

		# TODO: lazy dissect possible?
		self.opts.extend(opts)
		# IPv6 and IPv4 share same handler
		self._init_handler(type_nxt, buf[off:])
		# TODO: return length without parsing everything
		return off

	def direction(self, other):
		# logger.debug("checking direction: %s<->%s" % (self, next))
		if self.src == other.src and self.dst == other.dst:
			# consider packet to itself: can be DIR_REV
			return pypacker.Packet.DIR_SAME | pypacker.Packet.DIR_REV
		elif self.src == other.dst and self.dst == other.src:
			return pypacker.Packet.DIR_REV
		else:
			return pypacker.Packet.DIR_UNKNOWN

	def reverse_address(self):
		self.src, self.dst = self.dst, self.src


#
# Basic shared option classes
#
class IP6OptsHeader(pypacker.Packet):
	__hdr__ = (
		("nxt", "B", 0),  # next extension header protocol
		("len", "B", 0),  # option data length in 8 octect units (ignoring first 8 octets) so, len 0 == 64bit header
		("opts", None, triggerlist.TriggerList)
	)

	def _dissect(self, buf):
		length = 8 + buf[1] * 8
		options = []
		off = 2

		# TODO: check https://code.google.com/p/pypacker/issues/attachmentText?id=72
		while off < length:
			opt_type = buf[off]
			# logger.debug("IP6OptsHeader: type: %d" % opt_type)

			# http://tools.ietf.org/html/rfc2460#section-4.2
			# PAD1 option: no length or data field
			if opt_type == 0:
				opt = IP6OptionPad(type=opt_type)
				# logger.debug("next ip6 bytes 1: %r" % (buf[off:off + 2]))
				off += 1
			else:
				opt_len = buf[off + 1]
				opt = IP6Option(type=opt_type, len=opt_len, body_bytes=buf[off + 2: off + 2 + opt_len])
				# logger.debug("next ip6 bytes 2: %r" % (buf[off + 2: off + 2 + opt_len]))
				off += 2 + opt_len
			options.append(opt)

		self.opts.extend(options)
		return off


class IP6Option(pypacker.Packet):
	__hdr__ = (
		("type", "B", 0),
		("len", "B", 0)
	)


class IP6OptionPad(pypacker.Packet):
	__hdr__ = (
		("type", "B", 0),
	)


class IP6HopOptsHeader(IP6OptsHeader):
	def _dissect(self, buf):
		# logger.debug("IP6HopOptsHeader parsing")
		return IP6OptsHeader._dissect(self, buf)


class IP6RoutingHeader(pypacker.Packet):
	__hdr__ = (
		("nxt", "B", 0),  # next extension header protocol
		("len", "B", 0),  # extension data length in 8 octect units (ignoring first 8 octets) (<= 46 for type 0)
		("type", "B", 0),  # routing type (currently, only 0 is used)
		("segs_left", "B", 0),  # remaining segments in route, until destination (<= 23)
		("rsvd_sl_bits", "I", 0),  # reserved (1 byte), strict/loose bitmap for addresses
		("addresses", None, triggerlist.TriggerList)
	)

	def __get_sl_bits(self):
		return self.rsvd_sl_bits & 0xffffff

	def __set_sl_bits(self, v):
		self.rsvd_sl_bits = (self.rsvd_sl_bits & ~0xfffff) | (v & 0xfffff)
	sl_bits = property(__get_sl_bits, __set_sl_bits)

	def _dissect(self, buf):
		hdr_size = 8
		addr_size = 16
		addresses = []
		num_addresses = self.buf[1] / 2

		buf = buf[hdr_size:hdr_size + num_addresses * addr_size]

		# logger.debug("IP6RoutingHeader: parsing addresses")
		for i in range(num_addresses):
			addresses.append(buf[i * addr_size: i * addr_size + addr_size])

		self.addresses.extend(addresses)
		return len(num_addresses) * addr_size + addr_size
		# setattr(self, "addresses", addresses)
		# setattr(self, "length", self.len * 8 + 8)


class IP6FragmentHeader(pypacker.Packet):
	__hdr__ = (
		("nxt", "B", 0),			# next extension header protocol
		("resv", "B", 0),			# reserved, set to 0
		("frag_off_resv_m", "H", 0),		# frag offset (13 bits), reserved zero (2 bits), More frags flag
		("id", "I", 0)				# fragments id
	)

	def __get_frag_off(self):
		return self.frag_off_resv_m >> 3

	def __set_frag_off(self, v):
		self.frag_off_resv_m = (self.frag_off_resv_m & ~0xfff8) | (v << 3)
	frag_off = property(__get_frag_off, __set_frag_off)

	def __get_m_flag(self):
		return self.frag_off_resv_m & 1

	def __set_m_flag(self, v):
		self.frag_off_resv_m = (self.frag_off_resv_m & ~0xfffe) | v
	m_flag = property(__get_m_flag, __set_m_flag)


class IP6AHHeader(pypacker.Packet):
	__hdr__ = (
		("nxt", "B", 0),			 # next extension header protocol
		("len", "B", 0),			 # length of header in 4 octet units (ignoring first 2 units)
		("resv", "H", 0),			 # reserved, 2 bytes of 0
		("spi", "I", 0),			 # SPI security parameter index
		("seq", "I", 0)				 # sequence no.
	)


class IP6ESPHeader(pypacker.Packet):
	def _dissect(self, buf):
		raise NotImplementedError("ESP extension headers are not supported.")


class IP6DstOptsHeader(IP6OptsHeader):
	def _dissect(self, buf):
		# logger.debug("IP6DstOptsHeader parsing")
		IP6OptsHeader._dissect(self, buf)

ext_hdrs_cls = {
		IP_PROTO_HOPOPTS: IP6HopOptsHeader,
		IP_PROTO_ROUTING: IP6RoutingHeader,
		IP_PROTO_FRAGMENT: IP6FragmentHeader,
		IP_PROTO_ESP: IP6ESPHeader,
		IP_PROTO_AH: IP6AHHeader,
		IP_PROTO_DSTOPTS: IP6DstOptsHeader
		# IP_PROTO_MOBILITY:
		# IP_PROTO_NONEXT:
}
