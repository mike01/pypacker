# $Id: ntp.py 48 2008-05-27 17:31:15Z yardley $

"""Network Time Protocol."""

from . import pypacker

# NTP v4

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
		('flags', 'B', 0),
		('stratum', 'B', 0),
		('interval', 'B', 0),
		('precision', 'B', 0),
		('delay', 'I', 0),
		('dispersion', 'I', 0),
		('id', '4s', 0),
		('update_time', '8s', 0),
		('originate_time', '8s', 0),
		('receive_time', '8s', 0),
		('transmit_time', '8s', 0)
		)

	def _get_v(self):
		return (self.flags >> 3) & 0x7
	def _set_v(self, v):
		self.flags = (self.flags & ~0x38) | ((v & 0x7) << 3)
	v = property(_get_v, _set_v)

	def _get_li(self):
		return (self.flags >> 6) & 0x3
	def _set_li(self, li):
		self.flags = (self.flags & ~0xc0) | ((li & 0x3) << 6)
	li = property(_get_li, _set_li)

	def _get_mode(self):
		return (self.flags & 0x7)
	def _set_mode(self, mode):
		self.flags = (self.flags & ~0x7) | (mode & 0x7)
	mode = property(_get_mode, _set_mode)
