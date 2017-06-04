import struct

from pypacker import pypacker
# handler
from pypacker.layer12 import arp
from pypacker.layer3 import ip, ip6

LLC_TYPE_IP		= 0x0800		# IPv4 protocol
LLC_TYPE_ARP		= 0x0806		# address resolution protocol
LLC_TYPE_IP6		= 0x86DD		# IPv6 protocol

# avoid references for performance reasons
unpack_H = struct.Struct(">H").unpack


class LLC(pypacker.Packet):
	__hdr__ = (
		("dsap", "B", 0),
		("ssap", "B", 0),
		("ctrl", "B", 0),
		("snap", "5s", b"\x00" * 5),
	)

	__handler__ = {
		LLC_TYPE_IP: ip.IP,
		LLC_TYPE_ARP: arp.ARP,
		LLC_TYPE_IP6: ip6.IP6
	}

	def _dissect(self, buf):
		if buf[0] == 170:		# = 0xAA
			# SNAP is following ctrl
			htype = unpack_H(buf[5:7])[0]
			self._init_handler(htype, buf[8:])
		else:
			# deactivate SNAP
			self.snap = None
		return 8
