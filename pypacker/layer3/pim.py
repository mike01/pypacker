"""Protocol Independent Multicast."""

from pypacker import pypacker, checksum
from pypacker.pypacker import FIELD_FLAG_AUTOUPDATE


class PIM(pypacker.Packet):
	__hdr__ = (
		("v_type", "B", 0x20),
		("rsvd", "B", 0),
		("sum", "H", 0, FIELD_FLAG_AUTOUPDATE)  # _sum = sum
	)

	def __get_v(self):
		return self.v_type >> 4

	def __set_v(self, v):
		self.v_type = (v << 4) | (self.v_type & 0xf)
	v = property(__get_v, __set_v)

	def __get_type(self):
		return self.v_type & 0xf

	def __set_type(self, pimtype):
		self.v_type = (self.v_type & 0xf0) | pimtype
	type = property(__get_type, __set_type)

	def bin(self, update_auto_fields=True):
		if update_auto_fields and self.sum_au_active and self._changed():
			self.sum = 0
			self.sum = checksum.in_cksum(pypacker.Packet.bin(self))
		return pypacker.Packet.bin(self, update_auto_fields=update_auto_fields)
