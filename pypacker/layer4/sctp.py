"""
Stream Control Transmission Protocol.
http://tools.ietf.org/html/rfc3286
http://tools.ietf.org/html/rfc2960
"""

from pypacker import pypacker, triggerlist
from pypacker import checksum

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


class SCTP(pypacker.Packet):
	__hdr__ = (
		("sport", "H", 0),
		("dport", "H", 0),
		("vtag", "I", 0),
		("sum", "I", 0),
		("chunks", None, triggerlist.TriggerList)
	)

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

		while off + 4 < blen:
			dlen = struct.unpack(">H", buf[off + 2: off + 4])[0]
			# check for padding (this should be a data chunk)
			if off + dlen < blen:
				self.padding = buf[off + dlen:]
				#logger.debug("found padding: %s" % self.padding)

			chunk = Chunk(buf[off: off + dlen])
			#logger.debug("SCTP: Chunk; %s " % chunk)
			chunks.append(chunk)

			# get payload type from DATA chunks
			if chunk.type == 0:
				type = struct.unpack(">I",
						buf[off + chunk.hdr_len + 8: off + chunk.hdr_len + 8 + 4]
						)[0]
				#logger.debug("got DATA chunk, type: %d" % type)
				# remove data from chunk: use bytes for handler
				chunk.body_bytes = b""
				off += len(chunk)
				# assume DATA is the last chunk
				break

			off += dlen

		self.chunks.extend(chunks)

		type = struct.unpack(">H", buf[2: 4])[0]
		self._parse_handler(type, buf[off:-len(self.padding)])

	def bin(self, update_auto_fields=True):
		if update_auto_fields and self._changed():
			#logger.debug("updating checksum")
			self._calc_sum()
		return pypacker.Packet.bin(self, update_auto_fields=update_auto_fields) + self.padding

	def _calc_sum(self):
		# mark as changed
		self.sum = 0
		s = checksum.crc32_add(0xffffffff, self._pack_header())

		#for x in self.body_bytes:
		#	s = crc32c.add(s, x)
		#s = crc32c.add(s, self.body_bytes + self.padding)
		padlen = len(self.padding)
		if padlen == 0:
			s = checksum.crc32_add(s, self.body_bytes)
		else:
			#logger.debug("checksum with padding")
			s = checksum.crc32_add(s, self.body_bytes[:-padlen])

		sum = checksum.crc32_done(s)
		#logger.debug("sum is: %d" % sum)
		self.sum = sum

	def _direction(self, next):
		#logger.debug("checking direction: %s<->%s" % (self, next))
		if self.sport == next.sport and self.dport == next.dport:
			# consider packet to itself: can be DIR_REV
			return pypacker.Packet.DIR_SAME | pypacker.Packet.DIR_REV
		elif self.sport == next.dport and self.dport == next.sport:
			return pypacker.Packet.DIR_REV
		else:
			return pypacker.Packet.DIR_UNKNOWN

	def reverse_address(self):
		self.sport, self.dport = self.dport, self.sport

# load handler
from pypacker.layer567 import diameter

pypacker.Packet.load_handler(SCTP,
				{
					123: diameter.Diameter,
				}
)
