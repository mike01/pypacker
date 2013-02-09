# $Id: igmp.py 23 2006-11-08 15:45:33Z dugsong $

"""Internet Group Management Protocol."""

import pypacker as pypacker

class IGMP(pypacker.Packet):
	__hdr__ = (
		("type", "B", 0),
		("maxresp", "B", 0),
		("sum", "H", 0),
		("group", "I", 0)
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
		object.__setattr__(self, "sum", 0)
		object.__setattr__(self, "sum", pypacker.in_cksum(pypacker.Packet.bin(self)) )
