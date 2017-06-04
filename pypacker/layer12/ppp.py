"""Point-to-Point Protocol."""
import logging
import struct

from pypacker import pypacker, triggerlist
# handler
from pypacker.layer3 import ip, ip6


logger = logging.getLogger("pypacker")

# http://www.iana.org/assignments/ppp-numbers
PPP_IP	= 0x21		# Internet Protocol
PPP_IP6 = 0x57		# Internet Protocol v6

# Protocol field compression
PFC_BIT	= 0x01

# avoid references for performance reasons
unpack_H = struct.Struct(">H").unpack


class PPP(pypacker.Packet):
	__hdr__ = (
		("p", None, triggerlist.TriggerList),
	)

	__handler__ = {
		PPP_IP: ip.IP,
		PPP_IP6: ip6.IP6
	}

	def _dissect(self, buf):
		offset = 1
		ppp_type = buf[0]

		if buf[0] & PFC_BIT == 0:
			ppp_type = unpack_H(buf[:2])[0]
			offset = 2
			self.p.append(buf[0:2])
		else:
			self.p.append(buf[0:1])
		self._init_handler(ppp_type, buf[offset:])
		return offset
