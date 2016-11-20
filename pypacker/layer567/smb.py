"""Server Message Block."""

from pypacker import pypacker


class SMB(pypacker.Packet):
	__hdr__ = [
		("proto", "4s", b""),
		("cmd", "B", 0),
		("err", "I", 0),
		("flags1", "B", 0),
		("flags2", "B", 0),
		("pad", "6s", b""),
		("tid", "H", 0),
		("pid", "H", 0),
		("uid", "H", 0),
		("mid", "H", 0)
	]
