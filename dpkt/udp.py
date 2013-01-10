# $Id: udp.py 23 2006-11-08 15:45:33Z dugsong $

"""User Datagram Protocol."""

from . import dpkt

UDP_PORT_MAX	= 65535

class UDP(dpkt.Packet):
	__hdr__ = (
		('sport', 'H', 0xdead),
		('dport', 'H', 0),
		('ulen', 'H', 8),
		('sum', 'H', 0)
		)

	def __getattribute__(self, k):
		"""Updates sum on access to it. UDP needs an IP-layer so we tell
		it to compute the sum for us."""
		if k == "sum":
			# can be None if created for itself
			if callback is not None:
				callback("calc_sum")
			return self.sum
		else
			# delegate futher to get actual value of k
			return object.__getattribute__(self, k)

