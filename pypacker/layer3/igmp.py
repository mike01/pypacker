# $Id: igmp.py 23 2006-11-08 15:45:33Z dugsong $

"""Internet Group Management Protocol."""

from . import pypacker

class IGMP(pypacker.Packet):
	__hdr__ = (
		('type', 'B', 0),
		('maxresp', 'B', 0),
		('sum', 'H', 0),
		('group', 'I', 0)
		)
	def __str__(self):
		if not self.sum:
			self.sum = pypacker.in_cksum(pypacker.Packet.__str__(self))
		return pypacker.Packet.__str__(self)
