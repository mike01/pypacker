"""Protocol Independent Multicast."""

import pypacker as pypacker

class PIM(pypacker.Packet):
	__hdr__ = (
		("v_type", "B", 0x20),
		("rsvd", "B", 0),
		("sum", "H", 0)
		)
	#def _get_v(self): return self.v_type >> 4
	#def _set_v(self, v): self.v_type = (v << 4) | (self.v_type & 0xf)
	#v = property(_get_v, _set_v)
	#def _get_type(self): return self.v_type & 0xf
	#def _set_type(self, type): self.v_type = (self.v_type & 0xf0) | type
	#type = property(_get_type, _set_type)

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
		self.sum = 0
		object.__setattr__(self, "sum", pypacker.in_cksum(pypacker.Packet.bin(self)) )

