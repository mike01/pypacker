# $Id: tcp.py 42 2007-08-02 22:38:47Z jon.oberheide $

"""Transmission Control Protocol."""

from . import dpkt

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

class TCP(dpkt.Packet):
	__hdr__ = (
		('sport', 'H', 0xdead),
		('dport', 'H', 0),
		('seq', 'I', 0xdeadbeef),
		('ack', 'I', 0),
		('off_x2', 'B', ((5 << 4) | 0)),	# 10*4 Byte
		('flags', 'B', TH_SYN),
		('win', 'H', TCP_WIN_MAX),
		('sum', 'H', 0)
		)
	_opts = ''

	def _get_off(self):
		return self.off_x2 >> 4
	def _set_off(self, off):
		self.off_x2 = (off << 4) | (self.off_x2 & 0xf)
	off = property(_get_off, _set_off)

	def __len__(self):
		return self.__hdr_len__ + len(self.data)

	def __str__(self):
		# TODO: separate function for checksum to update sum on access to it
		return self.pack_hdr() + str(self.data)

	def unpack(self, buf):
		# TODO: get header length before super-unpacking
		# update dynamic header parts. buf: 1010???? -clear reserved-> 1010 -> *4
		ol = (buf[12] >> 4) << 2) - self.__hdr_len__	# dataoffset - TCP-len
		if ol < 0:
			raise dpkt.UnpackError('invalid header length')
		self._opts = buf[self.__hdr_len__:self.__hdr_len__ + ol]
		# TODO: parse options separately
		if len(self._opts) > 0:
			_add_headerfield("opts", "%dB" % len(self._opts), self._opts)
			options = parse_opts(self._opts)
		# dynamic header parts set, unpack all
		dpkt.Packet.unpack(self, buf)
		self.data = buf[self.__hdr_len_:]

	def __getattribute__(self, k):
		"""Updates sum on access to it. TCP needs an IP-layer so we tell
		it to compute the sum for us."""
		if k == "sum":
			# can be None if created for itself
			if callback is not None:
				callback("calc_sum")
			return self.sum
		else
			# delegate futher to get actual value of k
			return object.__getattribute__(self, k)

	def parse_opts(buf):
		"""Parse TCP option buffer into a list of (option, data) tuples."""
		opts = []
		while buf:
			o = ord(buf[0])
			if o > TCP_OPT_NOP:
				try:
					l = ord(buf[1])
					d, buf = buf[2:l], buf[l:]
				except ValueError:
					#print 'bad option', repr(str(buf))
					opts.append(None) # XXX
					break
			else:
				d, buf = '', buf[1:]
			opts.append((o,d))
		return opts

	class TCPOpt(dpkt.Packet):
		pass

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
