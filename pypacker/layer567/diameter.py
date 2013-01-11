# $Id: diameter.py 23 2006-11-08 15:45:33Z dugsong $

"""Diameter."""

import struct
from . import pypacker

# Diameter Base Protocol - RFC 3588
# http://tools.ietf.org/html/rfc3588

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
		('v', 'B', 1),
		('len', '3s', 0),
		('flags', 'B', 0),
		('cmd', '3s', 0),
		('app_id', 'I', 0),
		('hop_id', 'I', 0),
		('end_id', 'I', 0)
		)

	def _get_r(self):
		return (self.flags >> 7) & 0x1
	def _set_r(self, r):
		self.flags = (self.flags & ~0x80) | ((r & 0x1) << 7)
	request_flag = property(_get_r, _set_r)

	def _get_p(self):
		return (self.flags >> 6) & 0x1
	def _set_p(self, p):
		self.flags = (self.flags & ~0x40) | ((p & 0x1) << 6)
	proxiable_flag = property(_get_p, _set_p)

	def _get_e(self):
		return (self.flags >> 5) & 0x1
	def _set_e(self, e):
		self.flags = (self.flags & ~0x20) | ((e & 0x1) << 5)
	error_flag = property(_get_e, _set_e)

	def _get_t(self):
		return (self.flags >> 4) & 0x1
	def _set_t(self, t):
		self.flags = (self.flags & ~0x10) | ((t & 0x1) << 4)
	retransmit_flag = property(_get_t, _set_t)

	def unpack(self, buf):
		pypacker.Packet.unpack(self, buf)
		self.cmd = (ord(self.cmd[0]) << 16) | \
				(ord(self.cmd[1]) << 8) | \
				ord(self.cmd[2])
		self.len = (ord(self.len[0]) << 16) | \
				(ord(self.len[1]) << 8) | \
				ord(self.len[2])
		self.data = self.data[:self.len - self.__hdr_len__]

		l = []
		while self.data:
			avp = AVP(self.data)
			l.append(avp)
			self.data = self.data[len(avp):]
		self.data = self.avps = l

	def pack_hdr(self):
		self.len = chr((self.len >> 16) & 0xff) + \
				chr((self.len >> 8) & 0xff) + \
				chr(self.len & 0xff)
		self.cmd = chr((self.cmd >> 16) & 0xff) + \
				chr((self.cmd >> 8) & 0xff) + \
				chr(self.cmd & 0xff)
		return pypacker.Packet.pack_hdr(self)

	def __len__(self):
		return self.__hdr_len__ + \
			sum(map(len, self.data))

	def __str__(self):
		return self.pack_hdr() + \
			''.join(map(str, self.data))

class AVP(pypacker.Packet):
	__hdr__ = (
		('code', 'I', 0),
		('flags', 'B', 0),
		('len', '3s', 0),
		)

	def _get_v(self):
		return (self.flags >> 7) & 0x1
	def _set_v(self, v):
		self.flags = (self.flags & ~0x80) | ((v & 0x1) << 7)
	vendor_flag = property(_get_v, _set_v)

	def _get_m(self):
		return (self.flags >> 6) & 0x1
	def _set_m(self, m):
		self.flags = (self.flags & ~0x40) | ((m & 0x1) << 6)
	mandatory_flag = property(_get_m, _set_m)

	def _get_p(self):
		return (self.flags >> 5) & 0x1
	def _set_p(self, p):
		self.flags = (self.flags & ~0x20) | ((p & 0x1) << 5)
	protected_flag = property(_get_p, _set_p)

	def unpack(self, buf):
		pypacker.Packet.unpack(self, buf)
		self.len = (ord(self.len[0]) << 16) | \
				(ord(self.len[1]) << 8) | \
				ord(self.len[2])

		if self.vendor_flag:
			self.vendor = struct.unpack('>I', self.data[:4])[0]
			self.data = self.data[4:self.len - self.__hdr_len__]
		else:
			self.data = self.data[:self.len - self.__hdr_len__]

	def pack_hdr(self):
		self.len = chr((self.len >> 16) & 0xff) + \
				chr((self.len >> 8) & 0xff) + \
				chr(self.len & 0xff)
		data = pypacker.Packet.pack_hdr(self)
		if self.vendor_flag:
			data += struct.pack('>I', self.vendor)
		return data

	def __len__(self):
		length = self.__hdr_len__ + \
				 sum(map(len, self.data))
		if self.vendor_flag:
			length += 4
		return length
