"""Real-Time Transport Protocol"""

import pypacker as pypacker

# version 1100 0000 0000 0000 ! 0xC000	14
# p		  0010 0000 0000 0000 ! 0x2000	13
# x		  0001 0000 0000 0000 ! 0x1000	12
# cc	  0000 1111 0000 0000 ! 0x0F00	 8
# m		  0000 0000 1000 0000 ! 0x0080	 7
# pt	  0000 0000 0111 1111 ! 0x007F	 0
#

_VERSION_MASK	= 0xC000
_P_MASK		= 0x2000
_X_MASK		= 0x1000
_CC_MASK	= 0x0F00
_M_MASK		= 0x0080
_PT_MASK	= 0x007F
_VERSION_SHIFT	=14
_P_SHIFT	= 13
_X_SHIFT	= 12
_CC_SHIFT	= 8
_M_SHIFT	= 7
_PT_SHIFT	= 0

VERSION = 2

class RTP(pypacker.Packet):
	__hdr__ = (
		("type", "H", 0x8000),
		("seq",	"H", 0),
		("ts",	"I", 0),
		("ssrc","I", 0),
	)

	__m_switch_set = {"version":lambda type,version: (version << _VERSION_SHIFT) | (type & ~_VERSION_MASK),
				"p":lambda type,p: (p << _P_SHIFT) | (type & ~_P_MASK),
				"x":lambda type,x: (x << _X_SHIFT) | (type & ~_X_MASK),
				"cc":lambda type,cc: (cc << _CC_SHIFT) | (type & ~_CC_MASK),
				"m":lambda type,m: (m << _M_SHIFT) | (type & ~_M_MASK),
				"pt":lambda type,pt: (m << _PT_SHIFT) | (type & ~_PT_MASK)
			}
	__m_switch_get = {"version":lambda type: (type & _VERSION_MASK) >> _VERSION_SHIFT,
				"p":lambda type: (type & _P_MASK) >> _P_SHIFT,
				"x":lambda type: (type & _X_MASK) >> _X_SHIFT,
				"cc":lambda type: (type & _CC_MASK) >> _CC_SHIFT,
				"m":lambda type: (type & _M_MASK) >> _M_SHIFT,
				"pt":lambda type: (type & _PT_MASK) >> _PT_SHIFT
			}

	def __setattr__(self, k, val):
		# handle values smaller than 1 Byte
		if k in RTP.__m_switch_set:
			type = object.__getattribute__(self, "type")
			val = RTP.__m_switch_set[k](type, val)
			k = "type"

		pypacker.Packet.__setattr__(self, k, val)

	def __getattribute__(self, k):
		val = None

		if k in RTP.__m_switch_get:
			type = object.__getattribute__(self, "type")
			val = RTP.__m_switch_get[k](type)
			#logger.debug("get: flag after %s=%s" % (k, val))
		else:
			val = pypacker.Packet.__getattribute__(self, k)
		return val
