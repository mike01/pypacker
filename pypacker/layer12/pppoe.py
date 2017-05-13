"""PPP-over-Ethernet."""
import struct

from pypacker import pypacker
from pypacker.layer12.ppp import PPP

# RFC 2516 codes
PPPoE_PADI	= 0x09
PPPoE_PADO	= 0x07
PPPoE_PADR	= 0x19
PPPoE_PADS	= 0x65
PPPoE_PADT	= 0xA7
PPPoE_SESSION	= 0x00


class PPPoE(pypacker.Packet):
	__hdr__ = (
		("v_type", "B", 0x11),
		("code", "B", 0),
		("session", "H", 0),
		("len", "H", 0)		# payload length
	)

	def __get_v(self):
		return self.v_type >> 4

	def __set_v(self, v):
		self.v_type = (v << 4) | (self.v_type & 0xf)
	v = property(__get_v, __set_v)

	def __get_type(self):
		return self.v_type & 0xf

	def __set_type(self, t):
		self.v_type = (self.v_type & 0xf0) | t
	type = property(__get_type, __set_type)

	def _dissect(self, buf):
		code = buf[1]
		if code == PPPoE_SESSION:
			try:
				self._set_bodyhandler(PPP(buf[6:]))
			except (KeyError, struct.error):
				pass
		else:
			pass
		return 6
