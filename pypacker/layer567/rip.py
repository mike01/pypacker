# $Id: rip.py 23 2006-11-08 15:45:33Z dugsong $

"""Routing Information Protocol."""

from . import pypacker

# RIP v2 - RFC 2453
# http://tools.ietf.org/html/rfc2453

REQUEST = 1
RESPONSE = 2

class RIP(pypacker.Packet):
	__hdr__ = (
		('cmd', 'B', REQUEST),
		('v', 'B', 2),
		('rsvd', 'H', 0)
		)

	def unpack(self, buf):
		pypacker.Packet.unpack(self, buf)
		l = []
		self.auth = None
		while self.data:
			rte = RTE(self.data[:20])
			if rte.family == 0xFFFF:
				self.auth = Auth(self.data[:20])
			else:
				l.append(rte)
			self.data = self.data[20:]
		self.data = self.rtes = l

	def __len__(self):
		len = self.__hdr_len__
		if self.auth:
			len += len(self.auth)
		len += sum(map(len, self.rtes))
		return len

	def __str__(self):
		auth = ''
		if self.auth:
			auth = str(self.auth)
		return self.pack_hdr() + \
			   auth + \
			   ''.join(map(str, self.rtes))

class RTE(pypacker.Packet):
	__hdr__ = (
		('family', 'H', 2),
		('route_tag', 'H', 0),
		('addr', 'I', 0),
		('subnet', 'I', 0),
		('next_hop', 'I', 0),
		('metric', 'I', 1)
		)

class Auth(pypacker.Packet):
	__hdr__ = (
		('rsvd', 'H', 0xFFFF),
		('type', 'H', 2),
		('auth', '16s', 0)
		)
