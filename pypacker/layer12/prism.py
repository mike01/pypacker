"""Radiotap"""

from .. import pypacker
from ..layer12.ieee80211 import IEEE80211

import logging
import struct

logger = logging.getLogger("pypacker")


PRISM_TYPE_80211	= 0

PRISM_DID_RSSI		= 0x41400000

class DidsTriggerList(pypacker.TriggerList):
	pass	

class Did(pypacker.Packet):
	__hdr__ = (
		("id", "I", 0),
		("status", "H", 0),
		("len", "H", 0),
		("value", "I", 0),
		)

	__byte_order__ = "<"



class Prism(pypacker.Packet):
	__hdr1__ = (
		("pheader", "144s", b""),
		)

	__hdr__ = (
		("code", "I", 0),
		("len", "I", 144),
		("dev", "16s", b""),
		("dids", None, DidsTriggerList),
		)

	def _unpack1(self, buf):
		self._parse_handler(PRISM_TYPE_80211, buf, 144)
		pypacker.Packet._unpack(self, buf)

	def _unpack(self, buf):
		off = 24
		# assume 10 DIDs, 24 + 10*12 = 144 bytes prism header
		end = off + 10*12

		dids = []

		while off < end:
			did = Did( buf[off:off+12])
			dids.append(did)
			off += 12

		self.dids.extend(dids)

		self._parse_handler(PRISM_TYPE_80211, buf, 144)
		pypacker.Packet._unpack(self, buf)


# load handler
from pypacker.layer12 import ieee80211

pypacker.Packet.load_handler(Prism,
				{
				PRISM_TYPE_80211 : ieee80211.IEEE80211
				}
			)

