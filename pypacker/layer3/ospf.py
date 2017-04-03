"""Open Shortest Path First."""

from pypacker import pypacker, checksum
from pypacker.pypacker import FIELD_FLAG_AUTOUPDATE

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
		("sum", "H", 0, FIELD_FLAG_AUTOUPDATE),  # _sum = sum
		("atype", "H", 0),
		("auth", "8s", b"")
	)

	def bin(self, update_auto_fields=True):
		if update_auto_fields and self.sum_au_active and self._changed():
			self.sum = 0
			self.sum = checksum.in_cksum(pypacker.Packet.bin(self))
		return pypacker.Packet.bin(self, update_auto_fields=update_auto_fields)
