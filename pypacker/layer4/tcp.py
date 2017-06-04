"""
Transmission Control Protocol (TCP)

RFC 675 - Specification of Internet Transmission Control Program, December 1974 Version
RFC 793 - TCP v4
RFC 1122 - includes some error corrections for TCP
RFC 1323 - TCP-Extensions
RFC 1379 - Extending TCP for Transactions—Concepts
RFC 1948 - Defending Against Sequence Number Attacks
RFC 2018 - TCP Selective Acknowledgment Options
RFC 4614 - A Roadmap for TCP Specification Documents
RFC 5681 - TCP Congestion Control
RFC 6298 - Computing TCP's Retransmission Timer
RFC 6824 - TCP Extensions for Multipath Operation with Multiple Addresses
"""
import logging
import struct

from pypacker import pypacker, triggerlist, checksum
from pypacker.pypacker import FIELD_FLAG_AUTOUPDATE
# handler
from pypacker.layer567 import bgp, http, rtp, sip, telnet, tpkt, pmap
from pypacker.layer4 import ssl


# avoid unneeded references for performance reasons
unpack_H = struct.Struct(">H").unpack
pack_ipv4 = struct.Struct(">4s4sxBH").pack
pack_ipv6 = struct.Struct(">16s16sxBH").pack

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
TCP_OPT_EOL		= 0		# end of option list
TCP_OPT_NOP		= 1		# no operation
TCP_OPT_MSS		= 2		# maximum segment size
TCP_OPT_WSCALE		= 3		# window scale factor, RFC 1072
TCP_OPT_SACKOK		= 4		# SACK permitted, RFC 2018
TCP_OPT_SACK		= 5		# SACK, RFC 2018
TCP_OPT_ECHO		= 6		# echo (obsolete), RFC 1072
TCP_OPT_ECHOREPLY	= 7		# echo reply (obsolete), RFC 1072
TCP_OPT_TIMESTAMP	= 8		# timestamp, RFC 1323
TCP_OPT_POCONN		= 9		# partial order conn, RFC 1693
TCP_OPT_POSVC		= 10		# partial order service, RFC 1693
TCP_OPT_CC		= 11		# connection count, RFC 1644
TCP_OPT_CCNEW		= 12		# CC.NEW, RFC 1644
TCP_OPT_CCECHO		= 13		# CC.ECHO, RFC 1644
TCP_OPT_ALTSUM		= 14		# alt checksum request, RFC 1146
TCP_OPT_ALTSUMDATA	= 15		# alt checksum data, RFC 1146
TCP_OPT_SKEETER		= 16		# Skeeter
TCP_OPT_BUBBA		= 17		# Bubba
TCP_OPT_TRAILSUM	= 18		# trailer checksum
TCP_OPT_MD5		= 19		# MD5 signature, RFC 2385
TCP_OPT_SCPS		= 20		# SCPS capabilities
TCP_OPT_SNACK		= 21		# selective negative acks
TCP_OPT_REC		= 22		# record boundaries
TCP_OPT_CORRUPT		= 23		# corruption experienced
TCP_OPT_SNAP		= 24		# SNAP
TCP_OPT_TCPCOMP		= 26		# TCP compression filter
TCP_OPT_MAX		= 27


class TCPOptSingle(pypacker.Packet):
	__hdr__ = (
		("type", "B", 0),
	)


class TCPOptMulti(pypacker.Packet):
	"""
	len = total length (header + data)
	"""
	__hdr__ = (
		("type", "B", 0),
		("len", "B", 2, FIELD_FLAG_AUTOUPDATE)
	)

	def bin(self, update_auto_fields=True):
		if update_auto_fields and self.len_au_active:
			self.len = len(self)
		return pypacker.Packet.bin(self, update_auto_fields=update_auto_fields)

TCP_PROTO_TELNET	= 23
TCP_PROTO_TPKT		= 102
TCP_PROTO_PMAP		= 111
TCP_PROTO_BGP		= 179
TCP_PROTO_SSL		= 443
TCP_PROTO_HTTP		= (80, 8008, 8080)
TCP_PROTO_RTP 		= (5004, 5005)
TCP_PROTO_SIP		= (5060, 5061)


class TCP(pypacker.Packet):
	__hdr__ = (
		("sport", "H", 0xdead),
		("dport", "H", 0),
		("seq", "I", 0xdeadbeef),
		("ack", "I", 0),
		("off_x2", "B", ((5 << 4) | 0), FIELD_FLAG_AUTOUPDATE),  # 10*4 Byte
		("flags", "B", TH_SYN),  # acces via (obj.flags & TH_XYZ)
		("win", "H", TCP_WIN_MAX),
		("sum", "H", 0, FIELD_FLAG_AUTOUPDATE),
		("urp", "H", 0),
		("opts", None, triggerlist.TriggerList)
	)

	# 4 bits | 4 bits
	# offset | reserved
	# offset * 4 = header length
	def __get_off(self):
		return self.off_x2 >> 4

	def __set_off(self, value):
		self.off_x2 = (value << 4) | (self.off_x2 & 0xf)
	off = property(__get_off, __set_off)

	__handler__ = {
		TCP_PROTO_BGP: bgp.BGP,
		TCP_PROTO_TELNET: telnet.Telnet,
		TCP_PROTO_TPKT: tpkt.TPKT,
		TCP_PROTO_PMAP: pmap.Pmap,
		TCP_PROTO_HTTP: http.HTTP,
		TCP_PROTO_SSL: ssl.SSL,
		TCP_PROTO_RTP: rtp.RTP,
		TCP_PROTO_SIP: sip.SIP
	}

	def bin(self, update_auto_fields=True):
		if update_auto_fields:
			"""
			TCP-checksum needs to be updated on one of the following:
			- this layer itself or any upper layer changed
			- changes to the IP-pseudoheader
			There is no update on user-set checksums.
			"""
			update = True
			# update header length. NOTE: needs to be a multiple of 4 Bytes.
			# options length need to be multiple of 4 Bytes
			if self._header_changed and self.off_x2_au_active:
				self.off = int(self.header_len / 4) & 0xf
			try:
				# changes to IP-layer, don't mind if this isn't IP
				if not self._lower_layer._header_changed:
					# pseudoheader didn't change, further check for changes in layers
					update = self._changed()
				# logger.debug("lower layer found!")
			except AttributeError:
				# assume not an IP packet: we can't calculate the checksum
				# logger.debug("no lower layer found!")
				update = False

			if update and self.sum_au_active:
				# logger.debug(">>> updating checksum")
				self._calc_sum()

		return pypacker.Packet.bin(self, update_auto_fields=update_auto_fields)

	def _dissect(self, buf):
		# update dynamic header parts. buf: 1010???? -clear reserved-> 1010 -> *4
		ol = ((buf[12] >> 4) << 2) - 20			# dataoffset - TCP-standard length

		if ol < 0:
			raise Exception("invalid header length")
		elif ol > 0:
			# parse options, add offset-length to standard-length
			opts_bytes = buf[20: 20 + ol]
			self._init_triggerlist("opts", opts_bytes, self.__parse_opts)

		ports = [unpack_H(buf[0:2])[0], unpack_H(buf[2:4])[0]]

		try:
			# source or destination port should match
			# logger.debug("TCP handler: %r" % self._id_handlerclass_dct[TCP])
			htype = [x for x in ports if x in self._id_handlerclass_dct[TCP]][0]
			#logger.debug("TCP: trying to set handler, type: %d = %s" %
			#(type, self._id_handlerclass_dct[TCP][type]))
			self._init_handler(htype, buf[20 + ol:])
		except:
			# no type found
			pass
		return 20 + ol

	__TCP_OPT_SINGLE = {TCP_OPT_EOL, TCP_OPT_NOP}

	@staticmethod
	def __parse_opts(buf):
		"""Parse TCP options using buf and return them as List."""
		optlist = []
		i = 0

		while i < len(buf):
			# logger.debug("got TCP-option type %s" % buf[i])
			if buf[i] in TCP.__TCP_OPT_SINGLE:
				p = TCPOptSingle(type=buf[i])
				i += 1
			else:
				olen = buf[i + 1]
				# p = TCPOptMulti(type=buf[i], len=olen, body_bytes=buf[i + 2: i + olen])
				p = TCPOptMulti(buf[i: i + olen])
				i += olen     # typefield + lenfield + data-len
			optlist.append(p)
		# logger.debug("tcp: parseopts finished, length: %d" % len(optlist))
		return optlist

	def _calc_sum(self):
		"""Recalculate the TCP-checksum. This won't reset changed state."""
		# TCP and underwriting are freaky bitches: we need the IP pseudoheader
		# to calculate their checksum.
		try:
			# we need src/dst for checksum-calculation
			src, dst = self._lower_layer.src, self._lower_layer.dst
			self.sum = 0
			# logger.debug("TCP sum recalc: IP=%d / %s / %s" % (len(src), src, dst))

			tcp_bin = self.header_bytes + self.body_bytes
			# IP-pseudoheader, check if version 4 or 6
			if len(src) == 4:
				s = pack_ipv4(src, dst, 6, len(tcp_bin))  # 6 = TCP
			else:
				s = pack_ipv6(src, dst, 6, len(tcp_bin))  # 6 = TCP

			# Get checksum of concatenated pseudoheader+TCP packet
			# logger.debug("pseudoheader: %r" % s)
			# logger.debug("tcp_bin: %r" % tcp_bin)
			# assign via non-shadowed variable to trigger re-packing
			self.sum = checksum.in_cksum(s + tcp_bin)
			# logger.debug(">>> new checksum: %0X" % self._sum)
		except Exception:
			# not an IP packet as lower layer (src, dst not present) or invalid src/dst
			# logger.debug("could not calculate checksum: %r" % e)
			pass

	def is_next_in_stream(self, packet):
		"""
		return -- True if packet is the next expected packet in stream, False otherwise
			This assumes in-order segments, otherwise they stream can't be followed
		"""
		try:
			exptected_seq = self.seq + len(self.body_bytes)
			#logger.debug("comparing sequence: %d == %d" % (packet[TCP].seq, exptected_seq))
			return packet[TCP].seq == exptected_seq or\
				packet[TCP].seq - 1 == exptected_seq
		except:
			return False

	def direction(self, other):
		# logger.debug("checking direction: %s<->%s" % (self, other))
		if self.sport == other.sport and self.dport == other.dport:
			# consider packet to itself: can be DIR_REV
			return pypacker.Packet.DIR_SAME | pypacker.Packet.DIR_REV
		elif self.sport == other.dport and self.dport == other.sport:
			return pypacker.Packet.DIR_REV
		else:
			return pypacker.Packet.DIR_UNKNOWN

	def reverse_address(self):
		self.sport, self.dport = self.dport, self.sport
