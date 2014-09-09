"""Point-to-Point Protocol."""

from pypacker import pypacker, triggerlist

import logging
import struct

logger = logging.getLogger("pypacker")

# http://www.iana.org/assignments/ppp-numbers
PPP_IP	= 0x21		# Internet Protocol
PPP_IP6 = 0x57		# Internet Protocol v6

# Protocol field compression
PFC_BIT	= 0x01


class PPP(pypacker.Packet):
	__hdr__ = (
		("p", None, triggerlist.TriggerList),
	)

	#def set_p(cls, p, pktclass):
	#	cls._protosw[p] = pktclass
	#set_p = classmethod(set_p)
	#def get_p(cls, p):
	#	return cls._protosw[p]
	#get_p = classmethod(get_p)

	def _dissect(self, buf):
		logger.debug("dissecting ppp")
		offset = 1
		type = buf[0]

		if buf[0] & PFC_BIT == 0:
			type = struct.unpack(">H", buf[:2])[0]
			offset = 2
			self.p.append(buf[0:2])
		else:
			self.p.append(buf[0:1])
		self._parse_handler(type, buf[offset:])

# load handler
from pypacker.layer3 import ip, ip6

pypacker.Packet.load_handler(PPP,
	{
		PPP_IP: ip.IP,
		PPP_IP6: ip6.IP6
	}
)
