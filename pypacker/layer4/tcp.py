# $Id: tcp.py 42 2007-08-02 22:38:47Z jon.oberheide $

"""Transmission Control Protocol."""

import logging
import struct
import pypacker as pypacker
from pypacker import TriggerList

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
		# TODO: update on change (new options)
		("off_x2", "B", ((5 << 4) | 0)),	# 10*4 Byte
		("flags", "B", TH_SYN),			# acces via (obj.flags & TH_XYZ)
		("win", "H", TCP_WIN_MAX),
		("sum", "H", 0),
		("urp", "H", 0)
		)

	def unpack(self, buf):
		# update dynamic header parts. buf: 1010???? -clear reserved-> 1010 -> *4
		ol = ((buf[12] >> 4) << 2) - 20 # dataoffset - TCP-standard length
		if ol < 0:
			raise pypacker.UnpackError("invalid header length")
		# parse options, add offset-length to standard-length
		opts = buf[self.__hdr_len__ : self.__hdr_len__ + ol]

		if len(opts) > 0:
			logger.debug("got some TCP options" % opts)
			tl_opts = self.__parse_opts(opts)
			self._add_headerfield("opts", "", tl_opts)

		ports = [ struct.unpack(">H", buf[0:2])[0], struct.unpack(">H", buf[2:4])[0] ]

		try:
			# source or destination port should match
			type = [ x for x in ports if x in self._handler[TCP.__name__]][0]
			logger.debug("TCP: trying to set handler, type: %d = %s" % (type, self._handler[TCP.__name__][type]))
			#logger.debug("TCP: trying to set handler, type: %d = %s" % (type, self._handler))
			type_instance = self._handler[TCP.__name__][type](buf[self.__hdr_len__:])
			self._set_bodyhandler(type_instance)
		except (IndexError, pypacker.NeedData):
			pass
		except (KeyError, pypacker.UnpackError) as e:
			logger.debug("TCP: coudln't set handler: %s" % e)

		pypacker.Packet.unpack(self, buf)

	def __parse_opts(self, buf):
		"""Parse TCP options and return them as TriggerList."""
		optlist = []
		i = 0
		p = None

		while i < len(buf):
			#logger.debug("got TCP-option type %s" % buf[i])
			if buf[i] == TCP_OPT_NOP:
				p = TCPOptSingle(type=buf[i])
				i += 1
			else:
				type = buf[i]
				olen = buf[i + 1]
				val = buf[ i+2 : i+2+olen ]
				p = TCPOptMulti(type=type, len=olen)
				p._add_headerfield("val", None, val)
				i += 2+olen     # typefield + lenfield + data-len
			optlist += [p]

		return TriggerList(optlist)

#	def _get_off(self):
#		return self.off_x2 >> 4
#	def _set_off(self, off):
#		self.off_x2 = (off << 4) | (self.off_x2 & 0xf)
#	off = property(_get_off, _set_off)
	def __getattribute__(self, k):
		"""Track changes to fields relevant for TCP-chcksum."""
		# only update sum on access: all upper layers need to be parsed
		# TODO: mark as recalculated? reset changed-flag?
		if k == "sum" and self.__needs_checksum_update():
				self.__calc_sum()

		return object.__getattribute__(self, k)

	def __calc_sum(self):
		"""Recalculate the TCP-checksum."""
		# we need src/dst for checksum-calculation
		if self.callback is None:
			return

		object.__setattr__(self, "sum", 0)
		tcp_bin = pypacker.Packet.bin(self)
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
		object.__setattr__(self, "sum", sum)
		#object.__setattr__(self, "header_changed", True)

	def bin(self):
		if self.__needs_checksum_update():
			self.__calc_sum()
		return pypacker.Packet.bin(self)


	def is_related(self, next):
		related_self = False
		try:
			ports = [ next.sport, next.dport ]		
			related_self = self.sport in ports and self.dport in ports
		except:
			return False
		# delegate to super implementation for further checks
		return related_self and pypacker.Packet.is_related(self, next)

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

		# check upper layers
		return self._changed()

class TCPOptSingle(pypacker.Packet):
	__hdr__ = (
		("type", "1B", 0),
		)

class TCPOptMulti(pypacker.Packet):
	__hdr__ = (
		("type", "1B", 0),
		("len", "1B", 0),
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


# TODO: 1:n relation of proto:ports, enable multiple port definitions for same port
TCP_PROTO_HTTP		= [80, 8008, 8080]

#if not TCP.typesw:
pypacker.Packet.load_handler(globals(), TCP, "TCP_PROTO_", ["layer567"])
