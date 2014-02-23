"""
Transmission Control Protocol (TCP)

RFC 675 – Specification of Internet Transmission Control Program, December 1974 Version
RFC 793 – TCP v4
RFC 1122 – includes some error corrections for TCP
RFC 1323 – TCP-Extensions
RFC 1379 – Extending TCP for Transactions—Concepts
RFC 1948 – Defending Against Sequence Number Attacks
RFC 2018 – TCP Selective Acknowledgment Options
RFC 4614 – A Roadmap for TCP Specification Documents
RFC 5681 – TCP Congestion Control
RFC 6298 – Computing TCP's Retransmission Timer
RFC 6824 - TCP Extensions for Multipath Operation with Multiple Addresses
"""

from pypacker import pypacker, triggerlist, checksum

import logging
import struct

# avoid unneeded references for performance reasons
pack = struct.pack
unpack = struct.unpack

logger = logging.getLogger("pypacker")

# TCP control flags
TH_FIN		= 0x01		# end of data
TH_SYN		= 0x02		# synchronize sequence numbers
TH_RST		= 0x04		# reset connection
TH_PUSH		= 0x08		# push
TH_ACK		= 0x10		# acknowledgment number set
TH_URG		= 0x20		# urgent pointer set
TH_ECE		= 0x40		# ECN echo, RFC 3168
TH_CWR		= 0x80		# congestion window reduced

TCP_PORT_MAX	= 65535		# maximum port
TCP_WIN_MAX	= 65535		# maximum (unscaled) window

# TCP Options (opt_type) - http://www.iana.org/assignments/tcp-parameters
TCP_OPT_EOL		= 0	# end of option list
TCP_OPT_NOP		= 1	# no operation
TCP_OPT_MSS		= 2	# maximum segment size
TCP_OPT_WSCALE		= 3	# window scale factor, RFC 1072
TCP_OPT_SACKOK		= 4	# SACK permitted, RFC 2018
TCP_OPT_SACK		= 5	# SACK, RFC 2018
TCP_OPT_ECHO		= 6	# echo (obsolete), RFC 1072
TCP_OPT_ECHOREPLY	= 7	# echo reply (obsolete), RFC 1072
TCP_OPT_TIMESTAMP	= 8	# timestamp, RFC 1323
TCP_OPT_POCONN		= 9	# partial order conn, RFC 1693
TCP_OPT_POSVC		= 10	# partial order service, RFC 1693
TCP_OPT_CC		= 11	# connection count, RFC 1644
TCP_OPT_CCNEW		= 12	# CC.NEW, RFC 1644
TCP_OPT_CCECHO		= 13	# CC.ECHO, RFC 1644
TCP_OPT_ALTSUM		= 14	# alt checksum request, RFC 1146
TCP_OPT_ALTSUMDATA	= 15	# alt checksum data, RFC 1146
TCP_OPT_SKEETER		= 16	# Skeeter
TCP_OPT_BUBBA		= 17	# Bubba
TCP_OPT_TRAILSUM	= 18	# trailer checksum
TCP_OPT_MD5		= 19	# MD5 signature, RFC 2385
TCP_OPT_SCPS		= 20	# SCPS capabilities
TCP_OPT_SNACK		= 21	# selective negative acks
TCP_OPT_REC		= 22	# record boundaries
TCP_OPT_CORRUPT		= 23	# corruption experienced
TCP_OPT_SNAP		= 24	# SNAP
TCP_OPT_TCPCOMP		= 26	# TCP compression filter
TCP_OPT_MAX		= 27


class TCPTriggerList(triggerlist.TriggerList):
	def _handle_mod(self, val):
		"""Update header length. NOTE: needs to be a multiple of 4 Bytes."""
		# packet should be already present after adding this TriggerList as field.
		# we need to update format prior to get the correct header length: this
		# should have already happened
		try:
			# TODO: options length need to be multiple of 4 Bytes, allow different lengths?
			hdr_len_off = int(self._packet.hdr_len / 4) & 0xf
			#logger.debug("TCP: setting new header length/offset: %d/%d" % (self.packet._hdr_len, hdr_len_off))
			self._packet.off = hdr_len_off
		except:
			pass

	__TCP_OPT_SINGLE = set([TCP_OPT_EOL, TCP_OPT_NOP])

	def _tuples_to_packets(self, tuple_list):
		"""Convert [(TCP_OPT_X, b"xyz"), ...] to [TCPOptXXX]."""
		opt_packets = []

		# parse tuples to TCP-option Packets
		for opt in tuple_list:
			#logger.debug("checking tuple: %s" % str(opt))
			p = None
			if opt[0] in TCPTriggerList.__TCP_OPT_SINGLE:
				p = TCPOptSingle(type=opt[0])
			else:
				p = TCPOptMulti(type=opt[0], len=len(opt[1])+2, data=opt[1])
			opt_packets.append(p)

		return opt_packets


class TCPOptSingle(pypacker.Packet):
	__hdr__ = (
		("type", "1B", 0),
		)


class TCPOptMulti(pypacker.Packet):
	__hdr__ = (
		("type", "1B", 0),
		("len", "1B", 0)
		)


class TCP(pypacker.Packet):
	__hdr__ = (
		("sport", "H", 0xdead),
		("dport", "H", 0),
		("seq", "I", 0xdeadbeef),
		("ack", "I", 0),
		("off_x2", "B", ((5 << 4) | 0)),	# 10*4 Byte
		("flags", "B", TH_SYN),			# acces via (obj.flags & TH_XYZ)
		("win", "H", TCP_WIN_MAX),
		("_sum", "H", 0),			# _sum = sum
		("urp", "H", 0),
		("opts", None, TCPTriggerList)
		)

	# 4 bits | 4 bits
	# offset | reserved
	# offset * 4 = header length
	def __get_off(self):
		return self.off_x2 >> 4

	def __set_off(self, value):
		self.off_x2 = (value << 4) | (self.off_x2 & 0xf)
	off = property(__get_off, __set_off)

	def __get_sum(self):
		if self.__needs_checksum_update():
			self.__calc_sum()
		return self._sum

	def __set_sum(self, value):
		self._sum = value
		# sum was set by user: no further updates
		self._sum_ud = True
	sum = property(__get_sum, __set_sum)

	def _dissect(self, buf):
		# update dynamic header parts. buf: 1010???? -clear reserved-> 1010 -> *4
		ol = ((buf[12] >> 4) << 2) - 20 # dataoffset - TCP-standard length
		if ol < 0:
			raise UnpackError("invalid header length")
		elif ol > 0:
			# parse options, add offset-length to standard-length
			opts_bytes = buf[self._hdr_len : self._hdr_len + ol]
			self.opts.init_lazy_dissect(opts_bytes, self.__parse_opts)

		ports = [ unpack(">H", buf[0:2])[0], unpack(">H", buf[2:4])[0] ]

		try:
			# source or destination port should match
			type = [ x for x in ports if x in self._handler[TCP.__name__]][0]
			#logger.debug("TCP: trying to set handler, type: %d = %s" % (type, self._handler[TCP.__name__][type]))
			self._parse_handler(type, buf[self.hdr_len:])
		# no type found
		except:
			pass

	__TCP_OPT_SINGLE = set([TCP_OPT_EOL, TCP_OPT_NOP])

	def __parse_opts(self, buf):
		"""Parse TCP options using buf and return them as List."""
		optlist = []
		i = 0

		while i < len(buf):
			#logger.debug("got TCP-option type %s" % buf[i])
			if buf[i] in TCP.__TCP_OPT_SINGLE:
				p = TCPOptSingle(type=buf[i])
				i += 1
			else:
				olen = buf[i + 1]
				p = TCPOptMulti(type=buf[i], len=olen, data=buf[ i+2 : i+olen ])
				i += olen     # typefield + lenfield + data-len
			optlist.append(p)
		return optlist

	def bin(self):
		"""
		Custom bin() to handle checksum calculation.
		"""
		if self.__needs_checksum_update():
			self.__calc_sum()
		return pypacker.Packet.bin(self)

	def __calc_sum(self):
		"""Recalculate the TCP-checksum This won't reset changed state."""
		self._sum = 0
		tcp_bin = self.pack_hdr() + self.data
		# we need src/dst for checksum-calculation
		src, dst, changed = self._callback("ip_src_dst_changed")
		#logger.debug("TCP sum recalc: IP=%d/%s/%s/%s" % (len(src), src, dst, changed))

		# IP-pseudoheader, check if version 4 or 6
		if len(src) == 4:
			s = pack(">4s4sxBH", src, dst, 6, len(tcp_bin)) # 6 = TCP
		else:
			s = pack(">16s16sxBH", src, dst, 6, len(tcp_bin)) # 6 = TCP

		# Get checksum of concatenated pseudoheader+TCP packet
		self._sum = checksum.in_cksum(s + tcp_bin)

	def _direction(self, next):
		#logger.debug("checking direction: %s<->%s" % (self, next))
		if self.sport == next.sport and self.dport == next.dport:
			# consider packet to itself: can be DIR_REV
			return pypacker.Packet.DIR_SAME | pypacker.Packet.DIR_REV
		elif self.sport == next.dport and self.dport == next.sport:
			return pypacker.Packet.DIR_REV
		else:
			return pypacker.Packet.DIR_UNKNOWN

	def __needs_checksum_update(self):
		"""
		TCP-checksum needs to be updated on one of the following:
		- this layer itself or any upper layer changed
		- changes to the IP-pseudoheader
		There is no update on user-set checksums.
		"""
		# don't change user defined sum, LBYL: this is unlikely
		if hasattr(self, "_sum_ud"):
			return False

		try:
			# changes to IP-layer
			a, b, changed = self._callback("ip_src_dst_changed")
			if changed:
				# change to IP-pseudoheader
				return True
		except TypeError:
			# no callback to IP: we can't calculate the checksum
			return False

		# pseudoheader didn't change, further check for changes in layers
		return self._changed()


TCP_PROTO_TELNET	= 23
TCP_PROTO_TPKT		= 102
TCP_PROTO_PMAP		= 111
TCP_PROTO_BGP		= 179
TCP_PROTO_SSL		= 443
TCP_PROTO_HTTP		= (80, 8008, 8080)
TCP_PROTO_RTP 		= (5004, 5005)
TCP_PROTO_SIP		= (5060, 5061)

# load handler
from pypacker.layer4 import ssl
from pypacker.layer567 import bgp, http, rtp, sip, telnet, tpkt, pmap

pypacker.Packet.load_handler(TCP,
	{
	TCP_PROTO_BGP : bgp.BGP,
	TCP_PROTO_TELNET : telnet.Telnet,
	TCP_PROTO_TPKT : tpkt.TPKT,
	TCP_PROTO_PMAP : pmap.Pmap,
	TCP_PROTO_HTTP : http.HTTP,
	#TCP_PROTO_SSL : ssl.SSL,
	TCP_PROTO_RTP : rtp.RTP,
	TCP_PROTO_SIP : sip.SIP
	}
)
