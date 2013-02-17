"""Open Shortest Path First."""

import pypacker as pypacker

AUTH_NONE = 0
AUTH_PASSWORD = 1
AUTH_CRYPTO = 2

class OSPF(pypacker.Packet):
	__hdr__ = (
		("v", "B", 0),
		("type", "B", 0),
		("len", "H", 0),
		("router", "I", 0),
		("area", "I", 0),
		("_sum", "H", 0),	# _sum = sum
		("atype", "H", 0),
		("auth", "8s", b"")
		)

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
		#object.__setattr__(self, "sum", 0)
		self.sum = 0
		object.__setattr__(self, "_sum", pypacker.in_cksum(pypacker.Packet.bin(self)))
