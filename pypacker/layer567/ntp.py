"""Network Time Protocol."""

from pypacker import Packet
import logging
logger = logging.getLogger("pypacker")

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

class NTP(Packet):
	__hdr__ = (
		("flags", "B", 0),		# li | v | mode
		("stratum", "B", 0),
		("interval", "B", 0),
		("precision", "B", 0),
		("delay", "I", 0),
		("dispersion", "I", 0),
		("id", "4s", 0),
		("update_time", "8s", 0),
		("originate_time", "8s", 0),
		("receive_time", "8s", 0),
		("transmit_time", "8s", 0)
		)

	# [xx][xx x][xxx]
	# li  v     mode
	#__m_switch_set = {"v":lambda flags,v: (flags & ~0x38) | ((v & 0x7) << 3),
	#		"li":lambda flags,li: (flags & ~0xc0) | ((li & 0x3) << 6),
	#		"mode":lambda flags,mode: (flags & ~0x7) | (mode & 0x7)
	#		}
	#__m_switch_get = {"v":lambda flags: (flags >> 3) & 0x7,
	#		"li":lambda flags: (flags >> 6) & 0x3,
	#		"mode":lambda flags: (flags & 0x7)
	#		}
	def getv(self):
                return (self.flags >> 3) & 0x7
	def setv(self, value):
                self.flags = (self.flags & ~0x38) | ((value & 0x7) << 3)
	v = property(getv, setv)
	def getli(self):
                return (self.flags >> 6) & 0x3
	def setli(self, value):
                self.flags = (self.flags & ~0xc0) | ((value & 0x3) << 6)
	li = property(getli, setli)
	def getmode(self):
                return (self.flags & 0x7)
	def setmode(self, value):
                self.flags = (self.flags & ~0x7) | (value & 0x7)
	mode = property(getmode, setmode)
