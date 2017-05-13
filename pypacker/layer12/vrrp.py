"""Virtual Router Redundancy Protocol."""

from pypacker import pypacker, checksum
from pypacker.pypacker import FIELD_FLAG_AUTOUPDATE


class VRRP(pypacker.Packet):
	__hdr__ = (
		("vtype", "B", 0x21),
		("vrid", "B", 0),
		("priority", "B", 0),
		("count", "B", 0),
		("atype", "B", 0),
		("advtime", "B", 0),
		("sum", "H", 0, FIELD_FLAG_AUTOUPDATE),
	)

	def __get_v(self):
		return self.vtype >> 4

	def __set_v(self, v):
		self.vtype = (self.vtype & ~0xf) | (v << 4)
	v = property(__get_v, __set_v)

	def __get_type(self):
		return self.vtype & 0xf

	def __set_type(self, v):
		self.vtype = (self.vtype & ~0xf0) | (v & 0xf)
	type = property(__get_type, __set_type)

	def bin(self, update_auto_fields=True):
		if update_auto_fields and self.sum_au_active and self._changed():
			# logger.debug(">>> IP: calculating sum")
			# reset checksum for recalculation,  mark as changed / clear cache
			self.sum = 0
			# logger.debug(">>> IP: bytes for sum: %s" % self.header_bytes)
			self.sum = checksum.in_cksum(pypacker.Packet.bin(self, update_auto_fields=True))

		return pypacker.Packet.bin(self, update_auto_fields=update_auto_fields)
