"""Dynamic Trunking Protocol."""

from .. import pypacker

import struct

TRUNK_NAME	= 0x01
MAC_ADDR	= 0x04

class DTP(pypacker.Packet):
	__hdr__ = (
		("v", "B", 0),
		("tvs", None, pypacker.TriggerList)		
		)

	def _unpack(self, buf):
		off = 1
		dlen = len(buf)
		tvs = []

		while off < dlen:
			# length: inclusive header
			t, l = struct.unpack('>HH', buf[off : off+4])
			packet = TV(buf[off:off+l])
			tvs.append(packet)
			off += l

		self.tvs.extend(tvs)
		pypacker.Packet._unpack(self, buf)

class TV(pypacker.Packet):
	__hdr__ = (
		("t", "H", 0),
		("len", "H", 0)
		)
