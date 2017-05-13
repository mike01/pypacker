"""Network Time Protocol v4"""
import logging

from pypacker import pypacker

logger = logging.getLogger("pypacker")

# Leap Indicator (LI) Codes
NO_WARNING		= 0
LAST_MINUTE_61_SECONDS	= 1
LAST_MINUTE_59_SECONDS	= 2
ALARM_CONDITION		= 3

# Mode Codes
RESERVED		= 0
SYMMETRIC_ACTIVE	= 1
SYMMETRIC_PASSIVE	= 2
CLIENT			= 3
SERVER			= 4
BROADCAST		= 5
CONTROL_MESSAGE		= 6
PRIVATE			= 7


class NTP(pypacker.Packet):
	__hdr__ = (
		("flags", "B", 0x1c),		# li | v | mode
		("stratum", "B", 0x2),
		("interval", "B", 0x4),
		("precision", "B", 0xe9),
		("delay", "I", 0),
		("dispersion", "I", 0),
		("id", "4s", b"\x00\x01\x02\x03"),
		# timestamps: [seconds since 1.1.1900 | fraction of seconds]
		("update_time", "8s", b"\x00" * 8),
		("originate_time", "8s", b"" * 8),
		("receive_time", "8s", b"" * 8),
		("transmit_time", "8s", b"" * 8)
	)

	# li  v     mode [xx][xx x][xxx]
	def __get_v(self):
		return (self.flags >> 3) & 0x7

	def __set_v(self, value):
		self.flags = (self.flags & ~0x38) | ((value & 0x7) << 3)
	v = property(__get_v, __set_v)

	def __get_li(self):
		return (self.flags >> 6) & 0x3

	def __set_li(self, value):
		self.flags = (self.flags & ~0xc0) | ((value & 0x3) << 6)
	li = property(__get_li, __set_li)

	def __get_mode(self):
		return self.flags & 0x7

	def __set_mode(self, value):
		self.flags = (self.flags & ~0x7) | (value & 0x7)

	mode = property(__get_mode, __set_mode)
