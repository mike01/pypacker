"""Platform-dependent loopback header."""

from .. import pypacker
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip,ip6

import struct

class Loopback(pypacker.Packet):
	__hdr__ = (("family", "I", 0), )
	__byte_order__ = "@"

	def unpack(self, buf):
		family = struct.unpack("@I", buf[0:4])
		hndl = None

		if family == 2:
			hndl = ip.IP(buf[4:])
		elif family == 0x02000000:
			#self.family = 2
			hndl = ip.IP(buf[4:])
		elif family in (24, 28, 30):
			hndl = ip.IP6(self.data)
		elif family > 1500:
			hndl = ethernet.Ethernet(buf[4:])

		if hndl is not None:
			self._set_bodyhandler(hndl)

		pypacker.Packet.unpack(self, buf)

