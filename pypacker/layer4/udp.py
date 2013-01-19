# $Id: udp.py 23 2006-11-08 15:45:33Z dugsong $

"""User Datagram Protocol."""

import pypacker as pypacker

UDP_PORT_MAX	= 65535

class UDP(pypacker.Packet):
	__hdr__ = (
		('sport', 'H', 0xdead),
		('dport', 'H', 0),
		('ulen', 'H', 8),
		('sum', 'H', 0)
		)

	def __getattr__(self, k, v):
		# always get a fresh checksum
		if k == "sum" and self.callback is not None:
			self.callback("calc_sum")
			return self.sum
		else:
			return object.__getattribute__(k, v)

	def __setattr__(self, k, v):
		"""Track changes to fields relevant for UDP-chcksum."""
		pypacker.Packet.__setattr__(self, k, v)
		# ANY changes to the UDP-layer or upper layers are relevant
		# TODO: lazy calculation
		if self.callback is not None:
			self.callback("calc_sum")

	####
	# >>> Track changes for checksum
	####
	def bin(self):
		if self.callback is not None and __needs_checksum_update():
			self.callback("calc_sum")
		return pypacker.Packet.bin(self)

	def __str__(self):
		if self.callback is not None and __needs_checksum_update():
			self.callback("calc_sum")
		return pypacker.Packet.__str__(self)
	####
	# <<<
	####

	def __needs_checksum_update(self):
		"""UDP-checksum needs to be updated if this layer itself or any
		upper layer changed. Changes to the IP-pseudoheader are handled
		by the IP-layer itself."""
		needs_update = False

		try:
			p_instance = self
			while type(p_instance) is not NoneType:
				if p_instance.packet_changed:
					needs_update = True
					# reset flag
					p_instance.packet_changed = False
				# one layer upwards
				if p_instance.last_bodytypename is not None:
					p_instance = getattr(self, p_instance.last_bodytypename)
				else:
					p_instance = None
		except:
			pass
		return needs_update

#pypacker.load_types(globals(), UDP, "UDP_PROTO_". ["layer5"])
