"""Real-Time Transport Protocol"""

from pypacker import pypacker

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
_VERSION_SHIFT	= 14
_P_SHIFT	= 13
_X_SHIFT	= 12
_CC_SHIFT	= 8
_M_SHIFT	= 7
_PT_SHIFT	= 0

VERSION = 2


class RTP(pypacker.Packet):
	__hdr__ = (
		("type", "H", 0x8000),
		("seq", "H", 0),
		("ts", "I", 0),
		("ssrc", "I", 0)
	)

	def getversion(self):
		return (type & _VERSION_MASK) >> _VERSION_SHIFT

	def setversion(self, value):
		self.type = (value << _VERSION_SHIFT) | (self.type & ~_VERSION_MASK)
	version = property(getversion, setversion)

	def getp(self):
		return (self.type & _P_MASK) >> _P_SHIFT

	def setp(self, value):
		self.type = (value << _P_SHIFT) | (self.type & ~_P_MASK)
	p = property(getp, setp)

	def getx(self):
		return (self.type & _X_MASK) >> _X_SHIFT

	def setx(self, value):
		self.type = (value << _X_SHIFT) | (self.type & ~_X_MASK)
	x = property(getx, setx)

	def getcc(self):
		return (self.type & _CC_MASK) >> _CC_SHIFT

	def setcc(self, value):
		self.type = (value << _CC_SHIFT) | (self.type & ~_CC_MASK)
	cc = property(getcc, setcc)

	def getm(self):
		return (self.type & _M_MASK) >> _M_SHIFT

	def setm(self, value):
		self.type = (value << _M_SHIFT) | (self.type & ~_M_MASK)
	m = property(getm, setm)

	def getpt(self):
		return (self.type & _PT_MASK) >> _PT_SHIFT

	def setpt(self, value):
		self.type = (value << _PT_SHIFT) | (self.type & ~_PT_MASK)
	pt = property(getpt, setpt)
