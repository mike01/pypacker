"""Open Shortest Path First."""

from pypacker import pypacker

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

	def __get_sum(self):
		if self.__needs_checksum_update():
			self.__calc_sum()
		return self._sum
	def __set_sum(self, value):
		self._sum = value
		self._sum_ud = True
	sum = property(__get_sum, __set_sum)


	def bin(self):
		if self.__needs_checksum_update():
			self.__calc_sum()
		return pypacker.Packet.bin(self)

	def __calc_sum(self):
		self._sum = 0
		self._sum = pypacker.in_cksum(pypacker.Packet.bin(self))

	def __needs_checksum_update(self):
		if hasattr(self, "_sum_ud"):
			return False
		return self._changed()
