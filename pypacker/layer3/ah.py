"""Authentication Header."""

import pypacker as pypacker
import logging
from layer3.ip import IP

logger = logging.getLogger("pypacker")

class AH(pypacker.Packet):
	__hdr__ = (
		("nxt", "B", 0),
		("len", "B", 0),	# payload length
		("rsvd", "H", 0),
		("spi", "I", 0),
		("seq", "I", 0)
		)

	def _unpack(self, buf):
		type = buf[0]
		len = buf[1]

		try:
			logger.debug("AH: trying to set handler, type: %d = %s" % (type, self._handler[IP.__name__][type]))
			type_instance = self._handler[IP.__name__][type](buf[len:])
			self._set_bodyhandler(type_instance)
		except (KeyError, pypacker.UnpackError):
			pass

		pypacker.Packet._unpack(self, buf)
