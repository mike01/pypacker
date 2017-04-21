"""ISO Transport Service on top of the TCP (TPKT)."""

from pypacker import pypacker

# TPKT - RFC 1006 Section 6
# http://www.faqs.org/rfcs/rfc1006.html


class TPKT(pypacker.Packet):
	__hdr__ = (
		("v", "B", 3),
		("rsvd", "B", 0),
		("len", "H", 0)
	)
