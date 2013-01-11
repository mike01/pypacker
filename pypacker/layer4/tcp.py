# $Id: tcp.py 42 2007-08-02 22:38:47Z jon.oberheide $

"""Transmission Control Protocol."""

from . import pypacker

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
		('sport', 'H', 0xdead),
		('dport', 'H', 0),
		('seq', 'I', 0xdeadbeef),
		('ack', 'I', 0),
		('off_x2', 'B', ((5 << 4) | 0)),	# 10*4 Byte
		('flags', 'B', TH_SYN),			# acces via (obj.flags & TH_XYZ)
		('win', 'H', TCP_WIN_MAX),
		('sum', 'H', 0)
		)
	_opts = ''

#	def _get_off(self):
#		return self.off_x2 >> 4
#	def _set_off(self, off):
#		self.off_x2 = (off << 4) | (self.off_x2 & 0xf)
#	off = property(_get_off, _set_off)

	def __getattr__(self, k, v):
		# always get a fresh checksum
		if k == "sum" and self.callback is not None:
			self.callback("calc_sum")
			return self.sum
		else:
			return object.__getattr__(k, v)

        def __setattr__(self, k, v):
		"""Track changes to fields relevant for TCP-chcksum."""
		pypacker.Packet.__setattr__(k, v)
		# ANY changes to the TCP-layer or upper layers are relevant
		# TODO: lazy calculation
		if self.callback is not None:
			self.callback("calc_sum")

	####
	# >>> Track changes for checksum
	####
	def bin(self, v):
		if self.callback is not None and __needs_checksum_update():
			self.callback("calc_sum")
		return pypacker.Packet.bin()
	def __str__(self, v):
		if self.callback is not None and __needs_checksum_update():
			self.callback("calc_sum")
		return pypacker.Packet.__str__()
	####
	# <<<
	####

	# TODO: overwrite bytes
	def unpack(self, buf):
		# update dynamic header parts. buf: 1010???? -clear reserved-> 1010 -> *4
		ol = (buf[12] >> 4) << 2) - 40 # dataoffset - TCP-standard length
		if ol < 0:
			raise pypacker.UnpackError('invalid header length')
		self._opts = buf[self.__hdr_len__:self.__hdr_len__ + ol]
		# TODO: parse options separately
		if len(self._opts) > 0:
			_add_headerfield("opts", "%dB" % len(self._opts), self._opts)
			options = parse_opts(self._opts)
		# dynamic header parts set, unpack all
		pypacker.Packet.unpack(self, buf)
		self.data = buf[self.__hdr_len_:]

	def is_related(self, next):
		# TODO: make this more easy
		related_self = False
		try:
			ports = [ next.sport, next.dport ]		
			related_self = self.sport in ports or self.dport in ports

			if not related_self:
				return False
			# sent by as, seq needs to be greater
			# TODO: resent frames
			#if self.sport is next.sport:
			#	return self.seq <= next.seq
			# sent by peer
			# TODO: check for acks for old/new packets	
		except:
			return False
		# delegate to super implementation for further checks
		return related_self and pypacker.Packet.is_related(next)

	def __needs_checksum_update(self):
		"""TCP-checkusm needs to be updated if this layer itself or any
		upper layer changed. Changes to the IP-pseudoheader are handled
		by the IP-layer itself."""
		needs_update = False
		try:
			p_instance = self
			while type(p_instance) is not None
				if p_instance.packet_changed:
					needs_update = True
					break
				if p_instance.last_bodytypename is not None:
					p_instance = getattr(self, p_instance.last_bodytypename)
				else:
					p_instance = None
		except:
			pass
		return needs_update

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
					#print("bad option: ", repr(str(buf))
					opts.append(None) # XXX
					break
			else:
				d, buf = '', buf[1:]
			opts.append((o,d))
		return opts

	class TCPOpt(pypacker.Packet):
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
