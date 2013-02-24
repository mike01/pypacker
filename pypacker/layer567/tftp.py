"""Trivial File Transfer Protocol."""

from .. import pypacker

import struct

# Opcodes
OP_RRQ	= 1	# read request
OP_WRQ	= 2	# write request
OP_DATA	= 3	# data packet
OP_ACK	= 4	# acknowledgment
OP_ERR	= 5	# error code

# Error codes
EUNDEF		= 0	# not defined
ENOTFOUND	= 1	# file not found
EACCESS		= 2	# access violation
ENOSPACE	= 3	# disk full or allocation exceeded
EBADOP		= 4	# illegal TFTP operation
EBADID		= 5	# unknown transfer ID
EEXISTS		= 6	# file already exists
ENOUSER		= 7	# no such user

class TFTP(pypacker.Packet):
	__hdr__ = (("opcode", "H", 1), )

	def unpack(self, buf):
		opcode = struct.unpack(">H", buf[0:2])

		if opcode in (OP_RRQ, OP_WRQ):
			l = self.data.split(b"\x00")
			self.filename = l[0]
			self.mode = l[1]
			#self.data = ""
		elif opcode in (OP_DATA, OP_ACK):
			self.block = struct.unpack(">H", self.data[:2])
			self.data = self.data[2:]
		elif opcode == OP_ERR:
			self.errcode = struct.unpack(">H", self.data[:2])
			self.errmsg = self.data[2:].split(b"\x00")[0]
			#self.data = ""
		pypacker.Packet.unpack(self, buf)
