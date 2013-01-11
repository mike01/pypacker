# $Id: sctp.py 23 2006-11-08 15:45:33Z dugsong $

"""Stream Control Transmission Protocol."""

from . import dpkt, crc32c

# Stream Control Transmission Protocol
# http://tools.ietf.org/html/rfc2960

# Chunk Types
DATA			= 0
INIT			= 1
INIT_ACK		= 2
SACK			= 3
HEARTBEAT		= 4
HEARTBEAT_ACK		= 5
ABORT			= 6
SHUTDOWN		= 7
SHUTDOWN_ACK		= 8
ERROR			= 9
COOKIE_ECHO		= 10
COOKIE_ACK		= 11
ECNE			= 12
CWR			= 13
SHUTDOWN_COMPLETE	= 14

class SCTP(dpkt.Packet):
	__hdr__ = (
		('sport', 'H', 0),
		('dport', 'H', 0),
		('vtag', 'I', 0),
		('sum', 'I', 0)
		)

	def unpack(self, buf):
		dpkt.Packet.unpack(self, buf)
		l = []
		while self.data:
			chunk = Chunk(self.data)
			l.append(chunk)
			self.data = self.data[len(chunk):]
		self.data = self.chunks = l

	def __len__(self):
		return self.__hdr_len__ + \
			sum(map(len, self.data))

	def __str__(self):
		if self.sum == 0:
			s = crc32c.add(0xffffffff, self.pack_hdr())
			for x in self.data:
				s = crc32c.add(s, x)
			self.sum = crc32c.done(s)
		#return self.pack_hdr() + ''.join(l)
		print("====")
		print(self.pack_hdr())
		print("====")
		print(self.data)
		print("====")
		l = [ chr(x) for x in self.data ]
		print(''.join(l))
		print("====<<<")
		return self.pack_hdr() + self.data

class Chunk(dpkt.Packet):
	__hdr__ = (
		('type', 'B', INIT),
		('flags', 'B', 0),
		('len', 'H', 0)
		)

	def unpack(self, buf):
		dpkt.Packet.unpack(self, buf)
		# fix: https://code.google.com/p/dpkt/issues/detail?id=47
		# The total length of a chunk MUST be a multiple of 4
		mod = self.len % 4
		self.pad = 0 if not mod else 4 - mod
		self.data = self.data[:self.len + self.pad - self.__hdr_len__]
