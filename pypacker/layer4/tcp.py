"""Transmission Control Protocol."""

from .. import pypacker

import logging
import struct

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
		("urp", "H", 0)
							# _opts = opts
		)

	# 4 bits | 4 bits
	# offset | reserved
	# offset * 4 = header length

	def getoff(self):
                return self.off_x2 >> 4
	def setoff(self, value):
		self.off_x2 = (value << 4) | (self.off_x2 & 0xf)
	off = property(getoff, setoff)
	def getsum(self):
		if self.__needs_checksum_update():
			self.__calc_sum()
		return self._sum
	def setsum(self, value):
		self._sum = value
	sum = property(getsum, setsum)
	# check if opts not present and add it (lazy init)
	# this will enable: p.opts += [opt1, opt2, ...]
	def getopts(self):
		if not hasattr(self, "_opts"):
			tl = TCPTriggerList()
			self._add_headerfield("_opts", "", tl)
		return self._opts
	#def setopts(self, value):
	#	self._opts = value
	opts = property(getopts)

	def _unpack(self, buf):
		# update dynamic header parts. buf: 1010???? -clear reserved-> 1010 -> *4
		ol = ((buf[12] >> 4) << 2) - 20 # dataoffset - TCP-standard length
		if ol < 0:
			raise UnpackError("invalid header length")
		# parse options, add offset-length to standard-length
		opts = buf[self.__hdr_len__ : self.__hdr_len__ + ol]

		if len(opts) > 0:
			#logger.debug("got some TCP options" % opts)
			tl_opts = self.__parse_opts(opts)
			self._add_headerfield("_opts", "", tl_opts)

		ports = [ struct.unpack(">H", buf[0:2])[0], struct.unpack(">H", buf[2:4])[0] ]

		try:
			# source or destination port should match
			type = [ x for x in ports if x in self._handler[TCP.__name__]][0]
			#logger.debug("TCP: trying to set handler, type: %d = %s" % (type, self._handler[TCP.__name__][type]))
			type_instance = self._handler[TCP.__name__][type](buf[self.__hdr_len__:])
			self._set_bodyhandler(type_instance)
		# any exception will lead to: body = raw bytes
		except Exception as e:
			logger.debug("TCP: failed to set handler: %s" % e)
			pass

		pypacker.Packet._unpack(self, buf)

	def __parse_opts(self, buf):
		"""Parse TCP options using buf and return them as TriggerList."""
		optlist = []
		i = 0
		#p = None

		while i < len(buf):
			#logger.debug("got TCP-option type %s" % buf[i])
			if buf[i] in [TCP_OPT_EOL, TCP_OPT_NOP]:
				p = TCPOptSingle(type=buf[i])
				i += 1
			else:
				olen = buf[i + 1]
				p = TCPOptMulti(type=buf[i], len=olen, data=buf[ i+2 : i+olen ])
				i += olen     # typefield + lenfield + data-len
			optlist.append(p)
		return TCPTriggerList(optlist)

	def bin(self):
		if self.__needs_checksum_update():
			self.__calc_sum()
		return pypacker.Packet.bin(self)

	def __calc_sum(self):
		"""Recalculate the TCP-checksum."""
		# we need src/dst for checksum-calculation
		if self.callback is None:
			return

		# mark as changed
		#object.__setattr__(self, "_sum", 0)
		self.sum = 0
		tcp_bin = self.pack_hdr() + self.data
		src, dst, changed = self.callback("ip_src_dst_changed")

		#logger.debug("TCP sum recalc: %s/%s/%s" % (src, dst, changed))

		# IP-pseudoheader
		s = struct.pack(">4s4sxBH",
			src,		# avoid reformating
			dst,		# avoid reformating
			6,		# TCP
			len(tcp_bin))
		# Get the checksum of concatenated pseudoheader+TCP packet
		# fix: ip and tcp checksum together https://code.google.com/p/pypacker/issues/detail?id=54
		sum = pypacker.in_cksum(s + tcp_bin)
		#logger.debug("new tcp sum: %d" % sum)
		object.__setattr__(self, "_sum", sum)
		#object.__setattr__(self, "header_changed", True)


	def direction(self, next, last_packet=None):
		#logger.debug("checking direction: %s<->%s" % (self, next))
		try:
			if self.sport == next.sport and self.dport == next.dport:
				direction = pypacker.Packet.DIR_SAME
			elif self.sport == next.dport and self.dport == next.sport:
				direction = pypacker.Packet.DIR_REV
			else:
				direction = pypacker.Packet.DIR_BOTH
		except:
			return pypacker.Packet.DIR_NONE
                # delegate to super implementation for further checks
		return direction | pypacker.Packet.direction(self, next, last_packet)

	def __needs_checksum_update(self):
		"""TCP-checksum needs to be updated if this layer itself or any
		upper layer changed AND sum is None. Changes to the IP-pseudoheader lead to update
		of TCP-checksum."""
		if self.callback is None:
			return False
		# changes to IP-layer
		a, b, changed = self.callback("ip_src_dst_changed")
		if changed:
			return True
		# check this and upper layers
		return self._changed()


class TCPTriggerList(pypacker.TriggerList):
	def _handle_mod(self, val, add_listener=True):
		"""Update header length. NOTE: needs to be a multiple of 4 Bytes."""
		# packet should be already present after adding this TriggerList as field.
		# we need to update format prior to get the correct header length: this
		# should have already happened
		try:
			# TODO: options length need to be multiple of 4 Bytes, allow different lengths?
			hdr_len_off = int(self.packet.__hdr_len__ / 4) & 0xf
			#logger.debug("TCP: setting new header length/offset: %d/%d" % (self.packet.__hdr_len__, hdr_len_off))
			self.packet.off = hdr_len_off
		except:
			pass

		pypacker.TriggerList._handle_mod(self, val, add_listener=add_listener)

	def _tuples_to_packets(self, tuple_list):
		"""Convert [(TCP_OPT_X, b"xyz"), ...] to [TCPOptXXX]."""
		opt_packets = []

		# parse tuples to TCP-option Packets
		for opt in tuple_list:
			#logger.debug("checking tuple: %s" % str(opt))
			p = None
			if opt[0] in [TCP_OPT_EOL, TCP_OPT_NOP]:
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


# Options (opt_type) - http://www.iana.org/assignments/tcp-parameters
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

TCP_PROTO_HTTP		= [80, 8008, 8080]
TCP_PROTO_RTP 		= [5004, 5005]
TCP_PROTO_SIP		= [5060, 5061]

pypacker.Packet.load_handler(globals(), TCP, "TCP_PROTO_", ["layer567"])
