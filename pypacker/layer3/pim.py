"""Protocol Independent Multicast."""

from .. import pypacker

class PIM(pypacker.Packet):
	__hdr__ = (
		("v_type", "B", 0x20),
		("rsvd", "B", 0),
		("_sum", "H", 0)	# _sum = sum
		)

	def __get_v(self):
		return self.v_type >> 4
	def __set_v(self, v):
		self.v_type = (v << 4) | (self.v_type & 0xf)
	v = property(__get_v, __set_v)

	def __get_type(self):
		return self.v_type & 0xf
	def __set_type(self, type):
		self.v_type = (self.v_type & 0xf0) | type
	type = property(__get_type, __set_type)

	def __get_sum(self):
		if self.__needs_checksum_update():
			self.__calc_sum()
		return self._sum
	def __set_sum(self, value):
		self._sum = value
	sum = property(__get_sum, __set_sum)

	def bin(self):
		if self.__needs_checksum_update():
			self.__calc_sum()
		return pypacker.Packet.bin(self)

	def __calc_sum(self):
		# mark as changed
		self._sum = 0
		self._sum = pypacker.in_cksum( pypacker.Packet.bin(self) )

	def __needs_checksum_update(self):
		if hasattr(self, "_sum_ud"):
			return False
		return self._changed()

