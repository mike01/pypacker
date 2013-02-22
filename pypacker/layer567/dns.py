"""Domain Name System."""

from .. import pypacker

import struct

DNS_Q = 0
DNS_R = 1

# Opcodes
DNS_QUERY = 0
DNS_IQUERY = 1
DNS_STATUS = 2
DNS_NOTIFY = 4
DNS_UPDATE = 5

# Flags
DNS_CD = 0x0010	# checking disabled
DNS_AD = 0x0020	# authenticated data
DNS_Z =	 0x0040	# unused
DNS_RA = 0x0080	# recursion available
DNS_RD = 0x0100	# recursion desired
DNS_TC = 0x0200	# truncated
DNS_AA = 0x0400	# authoritative answer

# Response codes
DNS_RCODE_NOERR = 0
DNS_RCODE_FORMERR = 1
DNS_RCODE_SERVFAIL = 2
DNS_RCODE_NXDOMAIN = 3
DNS_RCODE_NOTIMP = 4
DNS_RCODE_REFUSED = 5
DNS_RCODE_YXDOMAIN = 6
DNS_RCODE_YXRRSET = 7
DNS_RCODE_NXRRSET = 8
DNS_RCODE_NOTAUTH = 9
DNS_RCODE_NOTZONE = 10

# RR types
DNS_A = 1
DNS_NS = 2
DNS_CNAME = 5
DNS_SOA = 6
DNS_PTR = 12
DNS_HINFO = 13
DNS_MX = 15
DNS_TXT = 16
DNS_AAAA = 28
DNS_SRV = 33

# RR classes
DNS_IN = 1
DNS_CHAOS = 3
DNS_HESIOD = 4
DNS_ANY = 255

def pack_name(name, off, label_ptrs):
	if name:
		labels = name.split('.')
	else:
		labels = []
	labels.append('')
	buf = ''
	for i, label in enumerate(labels):
		key = '.'.join(labels[i:]).upper()
		ptr = label_ptrs.get(key)
		if not ptr:
			if len(key) > 1:
				ptr = off + len(buf)
				if ptr < 0xc000:
					label_ptrs[key] = ptr
			i = len(label)
			buf += chr(i) + label
		else:
			buf += struct.pack('>H', (0xc000 | ptr))
			break
	return buf

def unpack_name(buf, off):
	name = ''
	saved_off = 0
	for i in range(100): # XXX
		n = ord(buf[off])
		if n == 0:
			off += 1
			break
		elif (n & 0xc0) == 0xc0:
			ptr = struct.unpack('>H', buf[off:off+2])[0] & 0x3fff
			off += 2
			if not saved_off:
				saved_off = off
			# XXX - don't use recursion!@#$
			name = name + unpack_name(buf, ptr)[0] + '.'
			break
		else:
			off += 1
			name = name + buf[off:off+n] + '.'
			if len(name) > 255:
				raise pypacker.UnpackError('name longer than 255 bytes')
			off += n
	return name.strip('.'), off

class DNS(pypacker.Packet):
	__hdr__ = (
		('id', 'H', 0),
		('op', 'H', DNS_RD),	# recursive query
		# XXX - lists of query, RR objects
		('qd', 'H', []),
		('an', 'H', []),
		('ns', 'H', []),
		('ar', 'H', [])
		)
	def get_qr(self):
		return int((self.op & 0x8000) == 0x8000)
	def set_qr(self, v):
		if v: self.op |= 0x8000
		else: self.op &= ~0x8000
	qr = property(get_qr, set_qr)

	def get_opcode(self):
		return (self.op >> 11) & 0xf
	def set_opcode(self, v):
		self.op = (self.op & ~0x7800) | ((v & 0xf) << 11)
	opcode = property(get_opcode, set_opcode)

	def get_rcode(self):
		return self.op & 0xf
	def set_rcode(self, v):
		self.op = (self.op & ~0xf) | (v & 0xf)
	rcode = property(get_rcode, set_rcode)

	class Q(pypacker.Packet):
		"""DNS question."""
		__hdr__ = (
			('name', '1025s', ''),
			('type', 'H', DNS_A),
			('cls', 'H', DNS_IN)
			)
		# XXX - suk
		def __len__(self):
			raise NotImplementedError
		__str__ = __len__
		def unpack(self, buf):
			raise NotImplementedError

	class RR(Q):
		"""DNS resource record."""
		__hdr__ = (
			('name', '1025s', ''),
			('type', 'H', DNS_A),
			('cls', 'H', DNS_IN),
			('ttl', 'I', 0),
			('rlen', 'H', 4),
			('rdata', 's', '')
			)
		def pack_rdata(self, off, label_ptrs):
			# XXX - yeah, this sux
			if self.rdata:
				return self.rdata
			if self.type == DNS_A:
				return self.ip
			elif self.type == DNS_NS:
				return pack_name(self.nsname, off, label_ptrs)
			elif self.type == DNS_CNAME:
				return pack_name(self.cname, off, label_ptrs)
			elif self.type == DNS_PTR:
				return pack_name(self.ptrname, off, label_ptrs)
			elif self.type == DNS_SOA:
				l = []
				l.append(pack_name(self.mname, off, label_ptrs))
				l.append(pack_name(self.rname, off + len(l[0]), label_ptrs))
				l.append(struct.pack('>IIIII', self.serial, self.refresh,
									 self.retry, self.expire, self.minimum))
				return ''.join(l)
			elif self.type == DNS_MX:
				return struct.pack('>H', self.preference) + \
					pack_name(self.mxname, off + 2, label_ptrs)
			elif self.type == DNS_TXT or self.type == DNS_HINFO:
				return ''.join([ '%s%s' % (chr(len(x)), x)
								 for x in self.text ])
			elif self.type == DNS_AAAA:
				return self.ip6
			elif self.type == DNS_SRV:
				return struct.pack('>HHH', self.priority, self.weight, self.port) + \
					pack_name(self.srvname, off + 6, label_ptrs)

		def unpack_rdata(self, buf, off):
			if self.type == DNS_A:
				self.ip = self.rdata
			elif self.type == DNS_NS:
				self.nsname, off = unpack_name(buf, off)
			elif self.type == DNS_CNAME:
				self.cname, off = unpack_name(buf, off)
			elif self.type == DNS_PTR:
				self.ptrname, off = unpack_name(buf, off)
			elif self.type == DNS_SOA:
				self.mname, off = unpack_name(buf, off)
				self.rname, off = unpack_name(buf, off)
				self.serial, self.refresh, self.retry, self.expire, \
					self.minimum = struct.unpack('>IIIII', buf[off:off+20])
			elif self.type == DNS_MX:
				self.preference = struct.unpack('>H', self.rdata[:2])
				self.mxname, off = unpack_name(buf, off+2)
			elif self.type == DNS_TXT or self.type == DNS_HINFO:
				self.text = []
				buf = self.rdata
				while buf:
					n = ord(buf[0])
					self.text.append(buf[1:1+n])
					buf = buf[1+n:]
			elif self.type == DNS_AAAA:
				self.ip6 = self.rdata
			elif self.type == DNS_SRV:
				self.priority, self.weight, self.port = \
					struct.unpack('>HHH', self.rdata[:6])
				self.srvname, off = unpack_name(buf, off+6)

	def pack_q(self, buf, q):
		"""Append packed DNS question and return buf."""
		return buf + pack_name(q.name, len(buf), self.label_ptrs) + \
			struct.pack('>HH', q.type, q.cls)

	def unpack_q(self, buf, off):
		"""Return DNS question and new offset."""
		q = self.Q()
		q.name, off = unpack_name(buf, off)
		q.type, q.cls = struct.unpack('>HH', buf[off:off+4])
		off += 4
		return q, off

	def pack_rr(self, buf, rr):
		"""Append packed DNS RR and return buf."""
		name = pack_name(rr.name, len(buf), self.label_ptrs)
		rdata = rr.pack_rdata(len(buf) + len(name) + 10, self.label_ptrs)
		return buf + name + struct.pack('>HHIH', rr.type, rr.cls, rr.ttl,
										len(rdata)) + rdata

	def unpack_rr(self, buf, off):
		"""Return DNS RR and new offset."""
		rr = self.RR()
		rr.name, off = unpack_name(buf, off)
		rr.type, rr.cls, rr.ttl, rdlen = struct.unpack('>HHIH', buf[off:off+10])
		off += 10
		rr.rdata = buf[off:off+rdlen]
		rr.unpack_rdata(buf, off)
		off += rdlen
		return rr, off

	def unpack(self, buf):
		pypacker.Packet.unpack(self, buf)
		off = self.__hdr_len__
		cnt = self.qd
		self.qd = []
		for i in range(cnt):
			q, off = self.unpack_q(buf, off)
			self.qd.append(q)
		for x in ('an', 'ns', 'ar'):
			cnt = getattr(self, x, 0)
			setattr(self, x, [])
			for i in range(cnt):
				rr, off = self.unpack_rr(buf, off)
				getattr(self, x).append(rr)
		self.data = ''

	def __len__(self):
		# XXX - cop out
		return len(str(self))

	def __str__(self):
		# XXX - compress names on the fly
		self.label_ptrs = {}
		buf = struct.pack(self.__hdr_fmt__, self.id, self.op, len(self.qd),
						len(self.an), len(self.ns), len(self.ar))
		for q in self.qd:
			buf = self.pack_q(buf, q)
		for x in ('an', 'ns', 'ar'):
			for rr in getattr(self, x):
				buf = self.pack_rr(buf, rr)
		del self.label_ptrs
		return buf
