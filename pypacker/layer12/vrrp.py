"""Virtual Router Redundancy Protocol."""

from .. import pypacker

class VRRP(pypacker.Packet):
	__hdr__ = (
		("vtype", "B", 0x21),
		("vrid", "B", 0),
		("priority", "B", 0),
		("count", "B", 0),
		("atype", "B", 0),
		("advtime", "B", 0),
		("_sum", "H", 0),	# _sum = sum
		)

	def getv(self):
		return self.vtype >> 4
	def setv(self, v):
		self.vtype = (self.vtype & ~0xf) | (v << 4)
	v = property(getv, setv)
	def gettype(self):
		return self.vtype & 0xf
	def settype(self, v):
		self.vtype = (self.vtype & ~0xf0) | (v & 0xf)
	type = property(gettype, settype)
	def getsum(self):
		if self._changed():
			self.__calc_sum()
		return self._sum
	def setsum(self, value):
		self._sum = value
	sum = property(getsum, setsum)


	def _unpack(self, buf):
		#l = []
		## fix: https://code.google.com/p/pypacker/issues/attachmentText?id=87
		#off = 0
		#for off in range(0, 4 * self.count, 4):
		#	l.append(self.data[off:off+4])
		#self.addrs = l
		#self.auth = self.data[off+4:]
		#self.data = ''
		pypacker.Packet._unpack(self, buf)

	def bin(self):
		if self._changed():
			__calc_sum()
		return pypacker.Packet.bin(self)

	def __calc_sum(self):
		# mark as changed
		#object.__setattr__(self, "sum", 0)
		self.sum = 0
		object.__setattr__(self, "_sum", pypacker.in_cksum(pypacker.Packet.bin()) )

