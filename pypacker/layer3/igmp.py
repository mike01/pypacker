"""Internet Group Management Protocol."""

from .. import pypacker

class IGMP(pypacker.Packet):
	__hdr__ = (
		("type", "B", 0),
		("maxresp", "B", 0),
		("_sum", "H", 0),	# _sum = sum
		("group", "I", 0)
		)

	def getsum(self):
		if self._changed():	
			self.__calc_sum()
		return self._sum
	def setsum(self, value):
		self._sum = value
	sum = property(getsum, setsum)

	def bin(self):
		if self._changed():
			self.__calc_sum()
		return pypacker.Packet.bin(self)

	def __calc_sum(self):
		# mark as changed
		self.sum = 0
		object.__setattr__(self, "_sum", pypacker.in_cksum(pypacker.Packet.bin(self)) )
