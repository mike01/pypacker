"""Virtual Router Redundancy Protocol."""

import pypacker as pypacker

class VRRP(pypacker.Packet):
	__hdr__ = (
		("vtype", "B", 0x21),
		("vrid", "B", 0),
		("priority", "B", 0),
		("count", "B", 0),
		("atype", "B", 0),
		("advtime", "B", 0),
		("sum", "H", 0),
		)

	#addrs = ()
	#auth = ''
	#def _get_v(self):
	#	return self.vtype >> 4
	#def _set_v(self, v):
	#	self.vtype = (self.vtype & ~0xf) | (v << 4)
	#v = property(_get_v, _set_v)
	#def _get_type(self):
	#	return self.vtype & 0xf
	#def _set_type(self, v):
	#	self.vtype = (self.vtype & ~0xf0) | (v & 0xf)
	#type = property(_get_type, _set_type)

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

	def __getattribute__(self, k):
		if k == "sum" and self._changed():
			#logger.debug(">>> vrrp: recalc of sum")
			self.__calc_sum()
		return pypacker.Packet.__getattribute__(self, k)

	def __calc_sum(self):
		# mark as changed
		#object.__setattr__(self, "sum", 0)
		self.sum = 0
		object.__setattr__(self, "sum", pypacker.in_cksum(pypacker.Packet.bin()) )

