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
		("sum", "H", 0),
		("atype", "H", 0),
		("auth", "8s", b"")
		)

	def bin(self):
		if self._changed():
			self.__calc_sum()
		return pypacker.Packet.bin(self)

	def __getattribute__(self, k):
		if k == "sum" and self._changed():
			self.__calc_sum()
		return pypacker.Packet.__getattribute__(self, k)

	def __calc_sum(self):
		# mark as changed
		#object.__setattr__(self, "sum", 0)
		self.sum = 0
		object.__setattr__(self, "sum", pypacker.in_cksum(pypacker.Packet.bin(self)))
