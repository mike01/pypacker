"""Network Time Protocol."""

import pypacker as pypacker
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

class NTP(pypacker.Packet):
	__hdr__ = (
		("flags", "B", 0),
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
	__m_switch_set = {"v":lambda flags,v: (flags & ~0x38) | ((v & 0x7) << 3),
			"li":lambda flags,li: (flags & ~0xc0) | ((li & 0x3) << 6),
			"mode":lambda flags,mode: (flags & ~0x7) | (mode & 0x7)
			}
	__m_switch_get = {"v":lambda flags: (flags >> 3) & 0x7,
			"li":lambda flags: (flags >> 6) & 0x3,
			"mode":lambda flags: (flags & 0x7)
			}

	def __setattr__(self, k, val):
		# handle values smaller than 1 Byte
		if k in NTP.__m_switch_set:
			flags = object.__getattribute__(self, "flags")
			#logger.debug("set: flag before %s=%s" % (k, val))
			val = NTP.__m_switch_set[k](flags, val)
			#logger.debug("set: flag after %s=%s" % (k, val))
			k = "flags"

		pypacker.Packet.__setattr__(self, k, val)

	def __getattribute__(self, k):
		val = None
		if k in NTP.__m_switch_get:
			val = object.__getattribute__(self, "flags")
			val = NTP.__m_switch_get[k](val)
			#logger.debug("get: flag after %s=%s" % (k, val))
		else:
			val = pypacker.Packet.__getattribute__(self, k)
		return val
