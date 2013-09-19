"""Authentication Header."""

from pypacker import pypacker

import logging

logger = logging.getLogger("pypacker")

class AH(pypacker.Packet):
	__hdr__ = (
		("nxt", "B", 0),
		("len", "B", 0),	# payload length
		("rsvd", "H", 0),
		("spi", "I", 0),
		("seq", "I", 0)
		)

	def _dissect(self, buf):
		type = buf[0]
		len = buf[1]
		self._parse_handler(type, buf, offset_start=len)
