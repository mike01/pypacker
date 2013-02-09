# $Id: ppp.py 65 2010-03-26 02:53:51Z dugsong $

"""Point-to-Point Protocol."""

import pypacker as pypacker
import logging
import struct
import copy

logger = logging.getLogger("pypacker")

# XXX - finish later

# http://www.iana.org/assignments/ppp-numbers
PPP_IP	= 0x21		# Internet Protocol
PPP_IP6 = 0x57		# Internet Protocol v6

# Protocol field compression
PFC_BIT	= 0x01

class PPP(pypacker.Packet):
	__hdr__ = (
		)

	#def set_p(cls, p, pktclass):
	#	cls._protosw[p] = pktclass
	#set_p = classmethod(set_p)
	#def get_p(cls, p):
	#	return cls._protosw[p]
	#get_p = classmethod(get_p)

	def unpack(self, buf):
		offset = 1
		type = buf[0]

		if buf[0] & PFC_BIT == 0:
			type = struct.unpack(">H", buf[:2])
			offset = 2
			self._add_headerfield("p", "H", type)
		else:
			self._add_headerfield("p", "B", type)

		try:
			logger.debug("PPP: trying to set handler, type: %d" % type)
			type_instance = self._handler[PPP.__name__][type](buf[offset:])
			self._set_bodyhandler(type_instance)
			#self.data = self._protosw[self.p](buf[offset:])
		except (KeyError, struct.error, pypacker.UnpackError) as e:
			pass
		pypacker.Packet.unpack(self, buf)


pypacker.Packet.load_handler(globals(), PPP, "PPP_", ["layer3"])
