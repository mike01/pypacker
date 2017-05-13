"""
Diameter Base Protocol - RFC 3588
http://tools.ietf.org/html/rfc3588
"""
import logging

from pypacker import pypacker, triggerlist

logger = logging.getLogger("pypacker")

# Request/Answer Command Codes
ABORT_SESSION		= 274
ACCOUTING		= 271
CAPABILITIES_EXCHANGE	= 257
DEVICE_WATCHDOG		= 280
DISCONNECT_PEER		= 282
RE_AUTH			= 258
SESSION_TERMINATION	= 275


class Diameter(pypacker.Packet):
	__hdr__ = (
		("v", "B", 1),
		("len", "3s", b"\x00" * 3),
		("flags", "B", 0),
		("cmd", "3s", b"\x00" * 3),
		("app_id", "I", 0),
		("hop_id", "I", 0),
		("end_id", "I", 0),
		("avps", None, triggerlist.TriggerList)
	)

	def __get_r(self):
		return (self.flags >> 7) & 0x1

	def __set_r(self, r):
		self.flags = (self.flags & ~0x80) | ((r & 0x1) << 7)
	request_flag = property(__get_r, __set_r)

	def __get_p(self):
		return (self.flags >> 6) & 0x1

	def __set_p(self, p):
		self.flags = (self.flags & ~0x40) | ((p & 0x1) << 6)
	proxiable_flag = property(__get_p, __set_p)

	def __get_e(self):
		return (self.flags >> 5) & 0x1

	def __set_e(self, e):
		self.flags = (self.flags & ~0x20) | ((e & 0x1) << 5)
	error_flag = property(__get_e, __set_e)

	def __get_t(self):
		return (self.flags >> 4) & 0x1

	def __set_t(self, t):
		self.flags = (self.flags & ~0x10) | ((t & 0x1) << 4)
	retransmit_flag = property(__get_t, __set_t)

	def _dissect(self, buf):
		self._init_triggerlist("avps", buf[20:], self._parse_avps)
		return len(buf)

	def _parse_avps(self, buf):
		off = 0
		avps = []
		buflen = len(buf)

		# parse AVPs
		while off < buflen:
			avplen = int.from_bytes(buf[off + 5: off + 8], "big")
			# REAL length of AVP is multiple of 4 Bytes
			mod_len = avplen % 4
			if mod_len != 0:
				avplen += 4 - mod_len
			avp = AVP(buf[off: off + avplen])
			avps.append(avp)
			off += avplen
		return avps


class AVP(pypacker.Packet):
	__hdr__ = (
		("code", "I", 0),
		("flags", "B", 0),
		("len", "3s", b""),
	)

	def __get_v(self):
		return (self.flags >> 7) & 0x1

	def __set_v(self, v):
		self.flags = (self.flags & ~0x80) | ((v & 0x1) << 7)
	vendor_flag = property(__get_v, __set_v)

	def __get_m(self):
		return (self.flags >> 6) & 0x1

	def __set_m(self, m):
		self.flags = (self.flags & ~0x40) | ((m & 0x1) << 6)
	mandatory_flag = property(__get_m, __set_m)

	def __get_p(self):
		return (self.flags >> 5) & 0x1

	def __set_p(self, p):
		self.flags = (self.flags & ~0x20) | ((p & 0x1) << 5)
	protected_flag = property(__get_p, __set_p)
