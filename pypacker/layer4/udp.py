# $Id: udp.py 23 2006-11-08 15:45:33Z dugsong $

"""User Datagram Protocol."""

import pypacker as pypacker
import struct

UDP_PORT_MAX	= 65535

class UDP(pypacker.Packet):
	__hdr__ = (
		('sport', 'H', 0xdead),
		('dport', 'H', 0),
		('ulen', 'H', 8),
		('sum', 'H', 0)
		)

	def __setattr__(self, k, v):
		"""Track changes to fields relevant for UDP-chcksum."""
		pypacker.Packet.__setattr__(self, k, v)
		# ANY changes to the UDP-layer or upper layers are relevant
		# TODO: lazy calculation
		if k in self.__hdr_fields__ or k is "data":
			self.__calc_sum()

	def __calc_sum(self):
		"""Recalculate the UDP-checksum."""
		# we need src/dst for checksum-calculation
		if self.callback is None:
			return

		object.__setattr__(self, "sum", 0)
		udp_bin = pypacker.Packet.bin(self)
		src, dst, changed = self.callback("ip_src_dst_changed")

		# IP-Pseudoheader
		s = struct.pack(">4s4sxBH",
			src,		# avoid reformating
			dst,		# avoid reformating
			17,		# TCP
			len(udp_bin))
		# Get the checksum of concatenated pseudoheader+TCP packet
		# fix: ip and tcp checksum together https://code.google.com/p/pypacker/issues/detail?id=54
		sum = pypacker.in_cksum(s + udp_bin)
		if sum == 0:
			sum = 0xffff    # RFC 768, p2

		object.__setattr__(self, "sum", sum)

	def bin(self):
		if self.__needs_checksum_update():
			self.__calc_sum()
		return pypacker.Packet.bin(self)

	def is_related(self, next):
		related_self = False
		try:
			ports = [ next.sport, next.dport ]
			related_self = self.sport in ports and self.dport in ports
		except:
			return False
		# delegate to super implementation for further checks
		return related_self and pypacker.Packet.is_related(self, next)

	def __needs_checksum_update(self):
		"""UDP-checkusm needs to be updated if this layer itself or any
		upper layer changed. Changes to the IP-pseudoheader lead to update
		of TCP-checksum."""
		if self.callback is None:
			return False
		# changes to IP-layer
		a, b, changed = self.callback("ip_src_dst_changed")
		if changed:
			return True
		# check upper layers
		needs_update = False

		try:
			p_instance = self
			while type(p_instance) is not NoneType:
				if p_instance.packet_changed:
					needs_update = True
					break
					# reset flag
					#p_instance.packet_changed = False
					# one layer upwards
				if p_instance.bodytypename is not None:
					p_instance = getattr(self, p_instance.bodytypename)
				else:
					p_instance = None
		except:
			pass
		return needs_update


#pypacker.load_types(globals(), UDP, "UDP_PROTO_". ["layer5"])
