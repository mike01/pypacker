"""Internet Group Management Protocol."""

from pypacker import pypacker, checksum


class IGMP(pypacker.Packet):
	__hdr__ = (
		("type", "B", 0),
		("maxresp", "B", 0),
		("_sum", "H", 0),	# _sum = sum
		("group", "I", 0)
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
		# mark as changed
		self._sum = 0
		self._sum = checksum.in_cksum( pypacker.Packet.bin(self) )

	def __needs_checksum_update(self):
		if hasattr(self, "_sum_ud"):
			return False
		return self._changed()
