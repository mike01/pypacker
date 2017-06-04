"""Internet Control Message Protocol for IPv6."""
import logging
import struct

from pypacker import pypacker
from pypacker import triggerlist
from pypacker import checksum

logger = logging.getLogger("pypacker")

unpack_H = struct.Struct(">H").unpack

ICMP6_DST_UNREACH		= 1		# dest unreachable, codes:
ICMP6_PACKET_TOO_BIG		= 2		# packet too big
ICMP6_TIME_EXCEEDED		= 3		# time exceeded, code:
ICMP6_PARAM_PROB		= 4		# ip6 header bad

ICMP6_ECHO_REQUEST		= 128		# echo service
ICMP6_ECHO_REPLY		= 129		# echo reply
MLD_LISTENER_QUERY		= 130		# multicast listener query
MLD_LISTENER_REPORT		= 131		# multicast listener report
MLD_LISTENER_DONE		= 132		# multicast listener done

# RFC2292 decls
ICMP6_MEMBERSHIP_QUERY		= 130		# group membership query
ICMP6_MEMBERSHIP_REPORT		= 131		# group membership report
ICMP6_MEMBERSHIP_REDUCTION	= 132		# group membership termination

ND_ROUTER_SOLICIT		= 133		# router solicitation
ND_ROUTER_ADVERT		= 134		# router advertisment
ND_NEIGHBOR_SOLICIT		= 135		# neighbor solicitation
ND_NEIGHBOR_ADVERT		= 136		# neighbor advertisment
ND_REDIRECT			= 137		# redirect

ICMP6_ROUTER_RENUMBERING	= 138		# router renumbering

ICMP6_WRUREQUEST		= 139		# who are you request
ICMP6_WRUREPLY			= 140		# who are you reply
ICMP6_FQDN_QUERY		= 139		# FQDN query
ICMP6_FQDN_REPLY		= 140		# FQDN reply
ICMP6_NI_QUERY			= 139		# node information request
ICMP6_NI_REPLY			= 140		# node information reply

ICMP6_MAXTYPE			= 201


pack_ipv6_icmp6 = struct.Struct(">16s16sII").pack


class ICMP6(pypacker.Packet):
	__hdr__ = (
		("type", "B", 0),
		("code", "B", 0),
		("sum", "H", 0)
	)

	def _calc_sum(self):
		try:
			# we need src/dst for checksum-calculation
			src, dst = self._lower_layer.src, self._lower_layer.dst
			# logger.debug("TCP sum recalc: IP=%d / %s / %s" % (len(src), src, dst))
			# pseudoheader
			# packet length = length of upper layers
			self.sum = 0
			pkt = self.header_bytes + self.body_bytes
			hdr = pack_ipv6_icmp6(src, dst, len(pkt), 58)
			self.sum = checksum.in_cksum(hdr + pkt)
			#logger.debug(">>> new checksum: %0X" % self._sum)
		except Exception:
			# not an IP packet as lower layer (src, dst not present) or invalid src/dst
			# logger.debug("could not calculate checksum: %r" % e)
			pass

	def _dissect(self, buf):
		self._init_handler(buf[0], buf[4:])
		return 4

	def bin(self, update_auto_fields=True):
		if update_auto_fields:
			try:
				if self.lower_layer._changed():
					self._calc_sum()
			except Exception:
				# no lower layer, nothing to update
				# logger.debug("%r" % ex)
				pass

		return pypacker.Packet.bin(self, update_auto_fields=update_auto_fields)

	class Error(pypacker.Packet):
		__hdr__ = (("pad", "I", 0), )

	class Unreach(Error):
		pass

	class TooBig(Error):
		__hdr__ = (("mtu", "I", 1232), )

	class TimeExceed(Error):
		pass

	class ParamProb(Error):
		__hdr__ = (("ptr", "I", 0), )

	class Echo(pypacker.Packet):
		__hdr__ = (
			("id", "H", 0),
			("seq", "H", 0)
		)

	class ICMPv6Opt(pypacker.Packet):
		__hdr__ = (
			("type", "B", 0),
			("len", "B", 0)
		)

	@staticmethod
	def _parse_icmp6opt(buf):
		# TODO: create generic TLV-parser
		opts = []
		off = 0

		while off < len(buf):
			optlen = unpack_H(buf[1:3])[0] * 8
			opt = ICMP6.ICMPv6Opt(buf[off: off + optlen])
			opts.append(opt)
			off += optlen
		return opts

	class NeighbourSolicitation(pypacker.Packet):
		__hdr__ = (
			("rsv", "4s", b"\x00" * 4),
			("target", "16s", b"\x00" * 16),
			("opts", None, triggerlist.TriggerList)
		)

		def _dissect(self, buf):
			self._init_triggerlist("opts", buf[20:], ICMP6._parse_icmp6opt)
			return len(buf)

	class NeighbourAdvertisement(pypacker.Packet):
		__hdr__ = (
			("flags", "4s", b"\x00" * 4),
			("target", "16s", b"\x00" * 16),
			("opts", None, triggerlist.TriggerList)
		)

		def _dissect(self, buf):
			self._init_triggerlist("opts", buf[20:], ICMP6._parse_icmp6opt)
			return len(buf)

	__handler__ = {
		1: Unreach,
		2: TooBig,
		3: TimeExceed,
		4: ParamProb,
		128: Echo,
		129: Echo,
		135: NeighbourSolicitation,
		136: NeighbourAdvertisement
	}
