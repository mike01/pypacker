"""Internetwork Packet Exchange."""

from pypacker import pypacker

IPX_HDR_LEN = 30


class IPX(pypacker.Packet):
	__hdr__ = (
		("sum", "H", 0xffff),
		("len", "H", IPX_HDR_LEN),
		("tc", "B", 0),
		("pt", "B", 0),
		("dst", "12s", b""),
		("src", "12s", b"")
	)
