"""Protocol Independent Multicast."""

from .. import pypacker

class PIM(pypacker.Packet):
	__hdr__ = (
		("v_type", "B", 0x20),
		("rsvd", "B", 0),
		("_sum", "H", 0)	# _sum = sum
		)
	def getv(self):
		return self.v_type >> 4
	def setv(self, v):
		self.v_type = (v << 4) | (self.v_type & 0xf)
	v = property(getv, setv)
	def gettype(self):
		return self.v_type & 0xf
	def settype(self, type):
		self.v_type = (self.v_type & 0xf0) | type
	type = property(gettype, settype)
	def getsum(self):
		if self._changed():
			self.__calc_sum()
		return self._sum
	def setsum(self, value):
		self._sum = value
	sum = property(getsum, setsum)


	def bin(self):
		if self._changed():
			self.__calc_sum()
		return pypacker.Packet.bin(self)

	def __calc_sum(self):
		# mark as changed
		self.sum = 0
		object.__setattr__(self, "_sum", pypacker.in_cksum(pypacker.Packet.bin(self)) )

