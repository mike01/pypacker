"""
Stream Control Transmission Protocol.
http://tools.ietf.org/html/rfc3286
http://tools.ietf.org/html/rfc2960
"""

from pypacker import pypacker, triggerlist
from pypacker import crc32c

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


class Chunk(pypacker.Packet):
	__hdr__ = (
		("type", "B", INIT),
		("flags", "B", 0),
		("len", "H", 0)		# length of header + data = 4 + x Bytes
		)

class SCTPTriggerList(triggerlist.TriggerList):
	"""
	SCTP-TriggerList to enable "chunks += [(SCTP_CHUNK_X, flags, b"xyz")], chunks[x] = (SCTP_CHUNK_X, flags, b"xyz")",
	length should be auto-calculated.
	"""
	def _tuples_to_packets(self, tuple_list):
		"""convert [(SCTP_CHUNK_X, b""), ...] to [ChunkX_obj, ...]."""
		chunk_packets = []

		# parse tuples to SCTP-Chunk Packets
		for t in tuple_list:
			p = Chunk(type=t[0], flags=t[1], len=len(t[2]), data=t[2])
			chunk_packets.append(p)
		return chunk_packets


	#def unpack(self, buf):
	#	pypacker.Packet.unpack(self, buf)
	#	# fix: https://code.google.com/p/pypacker/issues/detail?id=47
	#	# The total length of a chunk MUST be a multiple of 4
	#	mod = self.len % 4
	#	self.pad = 0 if not mod else 4 - mod
	#	self.data = self.data[:self.len + self.pad - self._hdr_len]

class SCTP(pypacker.Packet):
	__hdr__ = (
		("sport", "H", 0),
		("dport", "H", 0),
		("vtag", "I", 0),
		("_sum", "I", 0),			# _sum = sum
		("chunks", None, SCTPTriggerList)
		)

	def __get_sum(self):
		if self.__needs_checksum_update():
			self.__calc_sum()
		return self._sum
	def __set_sum(self, value):
		self._sum = value
		self._sum_ud = True
	sum = property(__get_sum, __set_sum)

	# handle padding attribute
	def __get_padding(self):
		try:
			return self._padding
		except:
			return b""
	def __set_padding(self, padding):
		self._padding = padding
	padding = property(__get_padding, __set_padding)


	def _dissect(self, buf):
		# parse chunks
		chunks = []
		off = 12
		blen = len(buf)

		#logger.debug("SCTP: parsing chunks")
		type = -1

		while off+4 < blen:
			dlen = struct.unpack(">H", buf[off+2 : off+4])[0]
			# check for padding (this should be a data chunk)
			if off + dlen < blen:
				self.padding = buf[off+dlen:]
				#logger.debug("found padding: %s" % self.padding)

			chunk = Chunk(buf[off : off + dlen])
			#logger.debug("SCTP: Chunk; %s " % chunk)
			chunks.append(chunk)

			# get payload type from DATA chunks
			if chunk.type == 0:
				type = struct.unpack(">I",
						buf[off+chunk.hdr_len+8 : off+chunk.hdr_len+8+4]
						)
				#logger.debug("got DATA chunk, type: %d" % type)
				# remove data from chunk: use bytes for handler
				chunk.data = b""
				off += len(chunk)
				# assume DATA is the last chunk
				break

			off += dlen

		self.chunks.extend(chunks)
		self._parse_handler(type, buf[off:-len(self.padding)])

	def bin(self):
		if self.__needs_checksum_update():
			self.__calc_sum()
		return pypacker.Packet.bin(self) + self.padding

	def __calc_sum(self):
		# mark as changed
		self._sum = 0
		s = crc32c.add(0xffffffff, self.pack_hdr())

		#for x in self.data:
		#	s = crc32c.add(s, x)
		#s = crc32c.add(s, self.data + self.padding)
		padlen = len(self.padding)
		if padlen == 0:
			s = crc32c.add(s, self.data)
		else:
			#logger.debug("checksum with padding")
			s = crc32c.add(s, self.data[:-padlen])

		sum = crc32c.done(s)
		#logger.debug("sum is: %d" % sum)
		self._sum = sum

	def __needs_checksum_update(self):
		if hasattr(self, "_sum_ud"):
			return False
		return self._changed()



# load handler
#from pypacker.layer567 import diameter

#pypacker.Packet.load_handler(SCTP,
#                                {
#					123 : diameter.Diameter,
#				}
#				)

