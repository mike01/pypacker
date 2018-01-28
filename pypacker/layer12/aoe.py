"""
ATA over Ethernet
http://brantleycoilecompany.com/AoEr11.pdf
See https://en.wikipedia.org/wiki/ATA_over_Ethernet
"""

from pypacker import pypacker


class AOECFG(pypacker.Packet):
	__hdr__ = (
		("bufcnt", "H", 0),
		("fwver", "H", 0),
		("scnt", "B", 0),
		("aoeccmd", "B", 0),
		("cslen", "H", 0),
	)


ATA_DEVICE_IDENTIFY = 0xEC


class AOEATA(pypacker.Packet):
	__hdr__ = (
		("aflags", "B", 0),
		("errfeat", "B", 0),
		("scnt", "B", 0),
		("cmdstat", "B", ATA_DEVICE_IDENTIFY),
		("lba0", "B", 0),
		("lba1", "B", 0),
		("lba2", "B", 0),
		("lba3", "B", 0),
		("lba4", "B", 0),
		("lba5", "B", 0),
		("res", "H", 0)
	)


class AOE(pypacker.Packet):
	__hdr__ = (
		("ver_fl", "B", 0x10),
		("err", "B", 0),
		("maj", "H", 0),
		("min", "B", 0),
		("cmd", "B", 0),
		("tag", "I", 0)
	)

	def _get_ver(self):
		return self.ver_fl >> 4

	def _set_ver(self, ver):
		self.ver_fl = (ver << 4) | (self.ver_fl & 0xf)

	ver = property(_get_ver, _set_ver)

	def _get_fl(self):
		return self.ver_fl & 0xf

	def _set_fl(self, fl):
		self.ver_fl = (self.ver_fl & 0xf0) | fl

	fl = property(_get_fl, _set_fl)
