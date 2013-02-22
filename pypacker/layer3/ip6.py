"""Internet Protocol, version 6."""

from .. import pypacker

class IP6(pypacker.Packet):
	__hdr__ = (
		("v_fc_flow", "I", 0x60000000),
		("plen", "H", 0),	# payload length (not including header)
		("nxt", "B", 0),	# next header protocol
		("hlim", "B", 0),	# hop limit
		("src", "16s", b""),
		("dst", "16s", b"")
		)

	# XXX - to be shared with IP. We cannot refer to the ip module
	# right now because ip.__load_protos() expects the IP6 class to be
	# defined.
	_protosw = None

	def _get_v(self):
		return self.v_fc_flow >> 28
	def _set_v(self, v):
		self.v_fc_flow = (self.v_fc_flow & ~0xf0000000) | (v << 28)
	v = property(_get_v, _set_v)

	def _get_fc(self):
		return (self.v_fc_flow >> 20) & 0xff
	def _set_fc(self, v):
		self.v_fc_flow = (self.v_fc_flow & ~0xff00000) | (v << 20)
	fc = property(_get_fc, _set_fc)

	def _get_flow(self):
		return self.v_fc_flow & 0xfffff
	def _set_flow(self, v):
		self.v_fc_flow = (self.v_fc_flow & ~0xfffff) | (v & 0xfffff)
	flow = property(_get_flow, _set_flow)

	def _unpack(self, buf):
		pypacker.Packet._unpack(self, buf)
		self.extension_hdrs = dict(((i, None) for i in ext_hdrs))

		buf = self.data[:self.plen]

		next = self.nxt

		while (next in ext_hdrs):
			ext = ext_hdrs_cls[next](buf)
			self.extension_hdrs[next] = ext
			buf = buf[ext.length:]
			next = ext.nxt

		# set the payload protocol id
		setattr(self, "p", next)

		try:
			self.data = self._protosw[next](buf)
			setattr(self, self.data.__class__.__name__.lower(), self.data)
		except (KeyError, pypacker.UnpackError):
			self.data = buf

	def headers_str(self):
		"""
		Output extension headers in order defined in RFC1883 (except dest opts)
		"""

		header_str = ""

		# fix: https://code.google.com/p/pypacker/issues/detail?id=67
		if getattr(self, "extension_hdrs", None):
			for hdr in ext_hdrs:
				if not self.extension_hdrs[hdr] is None:
					header_str += str(self.extension_hdrs[hdr])
		return header_str


	def __str__(self):
		# fix https://code.google.com/p/pypacker/issues/detail?id=59
		if (self.p == 6 or self.p == 17 or self.p == 58) and not self.data.sum:
			# XXX - set TCP, UDP, and ICMPv6 checksums
			p = str(self.data)
			s = pypacker.struct.pack(">16s16sxBH", self.src, self.dst, self.p, len(p))
			s = pypacker.in_cksum_add(0, s)
			s = pypacker.in_cksum_add(s, p)
			try:
				self.data.sum = pypacker.in_cksum_done(s)
			except AttributeError:
				pass
		return self.pack_hdr() + self.headers_str() + str(self.data)

	def set_proto(cls, p, pktclass):
		cls._protosw[p] = pktclass
	set_proto = classmethod(set_proto)

	def get_proto(cls, p):
		return cls._protosw[p]
	get_proto = classmethod(get_proto)

from . import ip
# We are most likely still in the middle of ip.__load_protos() which
# implicitly loads this module through __import__(), so the content of
# ip.IP._protosw is still incomplete at the moment.	 By sharing the
# same dictionary by reference as opposed to making a copy, when
# ip.__load_protos() finishes, we will also automatically get the most
# up-to-date dictionary.

###IP6._protosw = ip.IP._protosw

class IP6ExtensionHeader(pypacker.Packet): 
	"""
	An extension header is very similar to a "sub-packet".
	We just want to re-use all the hdr unpacking etc.
	"""
	pass

class IP6OptsHeader(IP6ExtensionHeader):
	__hdr__ = (
		("nxt", "B", 0),	# next extension header protocol
		("len", "B", 0)		# option data length in 8 octect units (ignoring first 8 octets) so, len 0 == 64bit header
		)

	def _unpack(self, buf):
		pypacker.Packet._unpack(self, buf)		
		setattr(self, "length", (self.len + 1) * 8)
		options = []

		index = 0
		# TODO: check https://code.google.com/p/pypacker/issues/attachmentText?id=72
		while (index < self.length - 2):
			opt_type = ord(self.data[index])

			# PAD1 option
			if opt_type == 0:					 
				index += 1
				continue;

			opt_length = ord(self.data[index + 1])

			if opt_type == 1: # PADN option
				# PADN uses opt_length bytes in total
				index += opt_length + 2
				continue

			options.append({"type": opt_type, "opt_length": opt_length, "data": self.data[index + 2:index + 2 + opt_length]})

			# add the two chars and the option_length, to move to the next option
			index += opt_length + 2

		setattr(self, "options", options)

class IP6HopOptsHeader(IP6OptsHeader): pass

class IP6DstOptsHeader(IP6OptsHeader): pass

class IP6RoutingHeader(IP6ExtensionHeader):
	__hdr__ = (
		("nxt", "B", 0),			# next extension header protocol
		("len", "B", 0),			# extension data length in 8 octect units (ignoring first 8 octets) (<= 46 for type 0)
		("type", "B", 0),			# routing type (currently, only 0 is used)
		("segs_left", "B", 0),		# remaining segments in route, until destination (<= 23)
		("rsvd_sl_bits", "I", 0),	# reserved (1 byte), strict/loose bitmap for addresses
		)

	def _get_sl_bits(self):
		return self.rsvd_sl_bits & 0xffffff
	def _set_sl_bits(self, v):
		self.rsvd_sl_bits = (self.rsvd_sl_bits & ~0xfffff) | (v & 0xfffff)
	sl_bits = property(_get_sl_bits, _set_sl_bits)

	def _unpack(self, buf):
		hdr_size = 8
		addr_size = 16

		pypacker.Packet._unpack(self, buf)

		addresses = []
		num_addresses = self.len / 2
		buf = buf[hdr_size:hdr_size + num_addresses * addr_size]

		for i in range(num_addresses):
			addresses.append(buf[i * addr_size: i * addr_size + addr_size])

		self.data = buf
		setattr(self, "addresses", addresses)
		setattr(self, "length", self.len * 8 + 8)

class IP6FragmentHeader(IP6ExtensionHeader):
	__hdr__ = (
		("nxt", "B", 0),			 # next extension header protocol
		("resv", "B", 0),			 # reserved, set to 0
		("frag_off_resv_m", "H", 0), # frag offset (13 bits), reserved zero (2 bits), More frags flag
		("id", "I", 0)				 # fragments id
		)

	def _unpack(self, buf):
		pypacker.Packet._unpack(self, buf)
		setattr(self, "length", self.__hdr_len__)

	def _get_frag_off(self):
		return self.frag_off_resv_m >> 3
	def _set_frag_off(self, v):
		self.frag_off_resv_m = (self.frag_off_resv_m & ~0xfff8) | (v << 3)
	frag_off = property(_get_frag_off, _set_frag_off)

	def _get_m_flag(self):
		return self.frag_off_resv_m & 1
	def _set_m_flag(self, v):
		self.frag_off_resv_m = (self.frag_off_resv_m & ~0xfffe) | v
	m_flag = property(_get_m_flag, _set_m_flag)

class IP6AHHeader(IP6ExtensionHeader):
	__hdr__ = (
		("nxt", "B", 0),			 # next extension header protocol
		("len", "B", 0),			 # length of header in 4 octet units (ignoring first 2 units)
		("resv", "H", 0),			 # reserved, 2 bytes of 0
		("spi", "I", 0),			 # SPI security parameter index
		("seq", "I", 0)				 # sequence no.
		)

	def _unpack(self, buf):
		pypacker.Packet._unpack(self, buf)
		setattr(self, "length", (self.len + 2) * 4)
		setattr(self, "auth_data", self.data[:(self.len - 1) * 4])


class IP6ESPHeader(IP6ExtensionHeader):
	def _unpack(self, buf):
		raise NotImplementedError("ESP extension headers are not supported.")


ext_hdrs = [ip.IP_PROTO_HOPOPTS, ip.IP_PROTO_ROUTING, ip.IP_PROTO_FRAGMENT, ip.IP_PROTO_AH, ip.IP_PROTO_ESP, ip.IP_PROTO_DSTOPTS]
ext_hdrs_cls = {ip.IP_PROTO_HOPOPTS: IP6HopOptsHeader, 
				ip.IP_PROTO_ROUTING: IP6RoutingHeader,
				ip.IP_PROTO_FRAGMENT: IP6FragmentHeader, 
				ip.IP_PROTO_ESP: IP6ESPHeader, 
				ip.IP_PROTO_AH: IP6AHHeader, 
				ip.IP_PROTO_DSTOPTS: IP6DstOptsHeader}
