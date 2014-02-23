"""
Definition of a new protocol
RFC 133742
"""
from .. import pypacker
from .. import triggerlist

import logging

logger = logging.getLogger("pypacker")


class SubPacket(pypacker.Packet):
	"""Packet to be used in TriggerLists"""
	__hdr__ = (
	("static_field1", "B", 123),
	)


class DynamicField(triggerlist.TriggerList):
	"""Specialised TriggerList representing dynamic fields."""
	def _handle_mod(self, val):
		try:
			self.packet.subfield = self.hdr_len
		except:
			pass

	def _tuples_to_packets(self, tuple_list):
		"""Convert (ID_x, value) to SubPacket"""
		return [ SubPacket(t[0] + t[1]) for t in tuple_list ]

	def _pack():
		"""Assumes something like text based protos like HTTP"""
		return b"-->".join(self)


class NewProtocol(pypacker.Packet):
	__hdr__ = (
	("static_field0", "B", 123),
	("static_field1", "H", 456),
	("static_field2", "I", 789),
	("static_field3_src", "4s", b"\x00"*4),
	("static_field4_dst", "4s", b"\x00"*4),
	# standard dynamic field, no cascading changes needed on changes
	# to this header
	("dynamic_field0", None, triggerlist.TriggerList),
	# specialised dynamic field: update needed on change for subfield
	# (part of static_field1)
	("dynamic_field1", None, DynamicField),
	)

	## convenient access for static_field3_src and static_field4_dst: IP4 address
	src_s = pypacker.Packet._get_property_ip4("static_field3_src")
	dst_s = pypacker.Packet._get_property_ip4("static_field4_dst")

	## values smaller than 1 Byte
	def __get_v(self):
		return self.static_field1 >> 4

	def __set_v(self, value):
		self.static_field1 = (value << 4) | (self.static_field1 & 0xf)
	subfield = property(__get_v, __set_v)

	def _dissect(self, buf):
		# static part will be unpacked automaticall
		# skip 15 Bytes (= B + H + I + 4s + 4s)
		off = 15

		self.dynamic_field1.append( SubPacket(buf[off:off+12]) )
		off += 12
		self.dynamic_field1.append( SubPacket(buf[off:off+16]) )
		off += 16

		# last byte gives type in our "NewProtocol"
		type = buf[off-1]
		# try to set handler, raw bytes will be set if parsing fails
		self._parse_handler(type, buf[self.hdr_len:])

	def _direction(self, next):
		if self.static_field3_src == next.static_field3_src and \
			self.static_field4_dst == next.static_field4_dst:
			return pypacker.Packet.DIR_SAME
		elif self.static_field3_src == next.static_field4_dst and \
			self.static_field4_dst == next.static_field3_src:
			return pypacker.Packet.DIR_REV
		else:
			return pypacker.Packet.DIR_UNKNOWN

# these types have to be extracted in _dissect()
NEW_PROTO_UPPERTYPE_1	= 1
NEW_PROTO_UPPERTYPE_2	= 2
NEW_PROTO_UPPERTYPE_3	= 3

# load handler
from pypacker.layer3 import ip
from pypacker.layer4 import tcp
from pypacker.layer567 import http

pypacker.Packet.load_handler(NewProtocol,
	{
	NEW_PROTO_UPPERTYPE_1 : ip.IP,
	NEW_PROTO_UPPERTYPE_2 : tcp.TCP,
	NEW_PROTO_UPPERTYPE_3 : http.HTTP
	}
)
