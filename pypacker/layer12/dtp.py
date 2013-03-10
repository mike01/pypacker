"""Dynamic Trunking Protocol."""

from .. import pypacker
from pypacker import TriggerList
import struct

TRUNK_NAME = 0x01
MAC_ADDR = 0x04

class DTP(pypacker.Packet):
	__hdr__ = (
		("v", "B", 0),
		)

	def __gettvs(self):
		if not hasattr(self, "_tvs"):
			tl = TriggerList()
		self._add_headerfield("_tvs", "", tl)
		return self._tvs
	tvs = property(getvs)

	def _unpack(self, buf):
		off = 1
		tvs = []

		while off < len(buf):
			t, l = strucht.unpack('>HH', buf[off : off+4])
			v = buf[off+4 : off+4+l]
			packet = TV(t=t, len=l, data=v)
			tvs.append(packet)
			off += l+4

		tl = pypacker.TriggerList(tvs)
		self._add_headerfield("_tvs", "", tl)
		pypacker.Packet._unpack(self, buf)

class TV(pypacker.Packet):
	__hdr__ = (
		("t", "H", 0),
		("len", "H", 0)
		)
