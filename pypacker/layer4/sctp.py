"""
Stream Control Transmission Protocol.
http://tools.ietf.org/html/rfc3286
http://tools.ietf.org/html/rfc2960
"""

from .. import pypacker
from .. import crc32c

import struct
import logging

logger = logging.getLogger("pypacker")

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

class SCTP(pypacker.Packet):
	__hdr__ = (
		("sport", "H", 0),
		("dport", "H", 0),
		("vtag", "I", 0),
		("_sum", "I", 0)	# _sum = sum
					# _chunks = chunks
		)

	def __get_sum(self):
		if self.__needs_checksum_update():
			self.__calc_sum()
		return self._sum
	def __set_sum(self, value):
		self._sum = value
		self._sum_ud = True
	sum = property(__get_sum, __set_sum)

	# öazy init of chunks
	def __get_chunks(self):
		if not hasattr(self, "_chunks"):
			chunks = SCTPTriggerList()
			self._add_headerfield("_chunks", "", chunks)
		return self._chunks
	chunks = property(__get_chunks)


	def _unpack(self, buf):
		l = []
		off = 12

		#logger.debug("SCTP: parsing chunks")

		while off+4 < len(buf):
			dlen = struct.unpack(">H", buf[off+2 : off+4])[0]
			chunk = Chunk(buf[off : off + dlen])
			#logger.debug("SCTP: Chunk; %s " % chunk)
			l.append(chunk)
			off += dlen

		#tl = TriggerList(l)
		tl = SCTPTriggerList(l)
		self._add_headerfield("_chunks", "", tl)
		pypacker.Packet._unpack(self, buf)

	def bin(self):
		if self.__needs_checksum_update():
			self.__calc_sum()
		return pypacker.Packet.bin(self)

	def __calc_sum(self):
		# mark as changed
		self._sum = 0
		s = crc32c.add(0xffffffff, self.pack_hdr())

		#for x in self.data:
		#	s = crc32c.add(s, x)
		s = crc32c.add(s, self.data)
		#s = crc32c.add(s, Packet.bin(self, False))
		sum = crc32c.done(s)
		#logger.debug("sum is: %d" % sum)
		self._sum = sum

	def __needs_checksum_update(self):
		if hasattr(self, "_sum_ud"):
			return False
		return self._changed()


	#def __str__(self):
	#	if self.sum == 0:
	#		s = crc32c.add(0xffffffff, self.pack_hdr())
	#		for x in self.data:
	#			s = crc32c.add(s, x)
	#		self.sum = crc32c.done(s)
	#	#return self.pack_hdr() + "".join(l)
	#	print("====")
	#	print(self.pack_hdr())
	#	print("====")
	#	print(self.data)
	#	print("====")
	#	l = [ chr(x) for x in self.data ]
	#	print("".join(l))
	#	print("====<<<")
	#	return self.pack_hdr() + self.data

class SCTPTriggerList(pypacker.TriggerList):
	"""SCTP-TriggerList to enable "chunks += [(SCTP_CHUNK_X, flags, b"xyz")], chunks[x] = (SCTP_CHUNK_X, flags, b"xyz")",
	length should be auto-calculated."""
	def _tuples_to_packets(self, tuple_list):
		"""convert [(SCTP_CHUNK_X, b""), ...] to [ChunkX_obj, ...]."""
		chunk_packets = []

		# parse tuples to SCTP-Chunk Packets
		for t in tuple_list:
			p = Chunk(type=t[0], flags=t[1], len=len(t[2]), data=t[2])
			chunk_packets.append(p)
		return chunk_packets

class Chunk(pypacker.Packet):
	__hdr__ = (
		("type", "B", INIT),
		("flags", "B", 0),
		("len", "H", 0)		# length of header + data = 4 + x Bytes
		)

	#def unpack(self, buf):
	#	pypacker.Packet.unpack(self, buf)
	#	# fix: https://code.google.com/p/pypacker/issues/detail?id=47
	#	# The total length of a chunk MUST be a multiple of 4
	#	mod = self.len % 4
	#	self.pad = 0 if not mod else 4 - mod
	#	self.data = self.data[:self.len + self.pad - self.__hdr_len__]
