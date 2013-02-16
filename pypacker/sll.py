"""Linux libpcap "cooked" capture encapsulation."""

import pypacker as pypacker
from pypacker.layer12 import ethernet, arp

class SLL(pypacker.Packet):
	__hdr__ = (
		("type", "H", 0), # 0: to us, 1: bcast, 2: mcast, 3: other, 4: from us
		("hrd", "H", arp.ARP_HRD_ETH),
		("hlen", "H", 6),	# hardware address length
		("hdr", "8s", ""),	# first 8 bytes of link-layer header
		("ethtype", "H", ethernet.ETH_TYPE_IP),
		)
	_typesw = ethernet.Ethernet._typesw

	def unpack(self, buf):
		pypacker.Packet.unpack(self, buf)
		try:
			self.data = self._typesw[self.ethtype](self.data)
			setattr(self, self.data.__class__.__name__.lower(), self.data)
		except (KeyError, pypacker.UnpackError):
			pass
