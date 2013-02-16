"""Transparent Network Substrate."""

from . import pypacker

class TNS(pypacker.Packet):
	__hdr__ = (
	('length', 'H', 0),
	('pktsum', 'H', 0),
	('type', 'B', 0),
	('rsvd', 'B', 0),
	('hdrsum', 'H', 0),
	('msg', '0s', ''),
	)
	def unpack(self, buf):
		pypacker.Packet.unpack(self, buf)
		n = self.length - self.__hdr_len__
		if n > len(self.data):
			raise pypacker.NeedData('short message (missing %d bytes)' %
								(n - len(self.data)))
		self.msg = self.data[:n]
		self.data = self.data[n:]

