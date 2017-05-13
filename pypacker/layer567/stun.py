"""
Simple Traversal of UDP through NAT (STUN).
RFC 3489
http://tools.ietf.org/html/rfc3489
"""
import struct
import logging

from pypacker.pypacker import Packet
from pypacker import triggerlist

unpack_H = struct.Struct(">H").unpack
logger = logging.getLogger("pypacker")

# Message Types
BINDING_REQUEST = 0x0001
BINDING_RESPONSE = 0x0101
BINDING_ERROR_RESPONSE = 0x0111
SHARED_SECRET_REQUEST = 0x0002
SHARED_SECRET_RESPONSE = 0x0102
SHARED_SECRET_ERROR_RESPONSE = 0x0112

# Message Attributes
MAPPED_ADDRESS = 0x0001
RESPONSE_ADDRESS = 0x0002
CHANGE_REQUEST = 0x0003
SOURCE_ADDRESS = 0x0004
CHANGED_ADDRESS = 0x0005
USERNAME = 0x0006
PASSWORD = 0x0007
MESSAGE_INTEGRITY = 0x0008
ERROR_CODE = 0x0009
UNKNOWN_ATTRIBUTES = 0x000a
REFLECTED_FROM = 0x000b


class StunAttr(Packet):
	__hdr__ = (
		("type", "H", 0),
		("len", "H", 0),
	)


class STUN(Packet):
	# 20 byte header followed by 0 or more attribute TLVs.
	__hdr__ = (
		("type", "H", 0),
		("len", "H", 0),
		("cookie", "I", 0),
		("xid", "12s", b"\x00" * 14),
		("attrs", None, triggerlist.TriggerList)
	)

	@staticmethod
	def __parse_attrs(buf):
		attributes = []
		off = 0

		# t:2 l:2 v:x
		while off < len(buf):
			l_content = unpack_H(buf[off + 2: off + 4])[0]
			padding = (4 - (l_content % 4)) % 4
			l_total = l_content + padding + 2 + 2
			#logger.debug("STUN attr l_content: %d, padding: %d, value: %s" %
			#	 (l_content, padding, buf[off : off + l_total]))
			attributes.append(StunAttr(buf[off: off + l_total]))
			off += l_total
		return attributes

	def _dissect(self, buf):
		# logger.debug("dissecting: %s" % buf)
		self._init_triggerlist("attrs", buf[20:], self.__parse_attrs)
		return len(buf)
