"""Yahoo Messenger."""

import pypacker as pypacker

class YHOO(pypacker.Packet):
	__hdr__ = [
		("version", "8s", b" " * 8),
		("length", "I", 0),
		("service", "I", 0),
		("connid", "I", 0),
		("magic", "I", 0),
		("unknown", "I", 0),
		("type", "I", 0),
		("nick1", "36s", b" " * 36),
		("nick2", "36s", b" " * 36)
	]
	__byte_order__ = "<"

class YMSG(pypacker.Packet):
	__hdr__ = [
		("version", "8s", b" " * 8),
		("length", "H", 0),
		("type", "H", 0),
		("unknown1", "I", 0),
		("unknown2", "I", 0)
	]
