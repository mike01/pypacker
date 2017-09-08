"""Internet Group Management Protocol."""

from pypacker import pypacker, checksum
from pypacker.pypacker import FIELD_FLAG_AUTOUPDATE


class IGMP(pypacker.Packet):
	__hdr__ = (
		("type", "B", 0),
		("maxresp", "B", 0),
		("sum", "H", 0, FIELD_FLAG_AUTOUPDATE),
		("group", "4s", b"\x00" * 4)
	)

	# Convenient access for: group[_s]
	group_s = pypacker.get_property_ip4("group")

	def _update_fields(self):
		if self.sum_au_active and self._changed():
			self.sum = 0
			self.sum = checksum.in_cksum(pypacker.Packet.bin(self))
