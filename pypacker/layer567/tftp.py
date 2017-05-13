"""Trivial File Transfer Protocol (TFTP)"""

import struct
import re
import logging

from pypacker.pypacker import Packet

logger = logging.getLogger("pypacker")

unpack_H = struct.Struct(">H").unpack
PROG_SPLIT_NULLBYTE = re.compile(b"\x00")
split_nullbyte = PROG_SPLIT_NULLBYTE.split

# Opcodes
OP_RRQ = 1  # read request
OP_WRQ = 2  # write request
OP_DATA = 3  # data packet
OP_ACK = 4  # acknowledgment
OP_ERR = 5  # error code

OPCODES_READ_WRITE = {OP_RRQ, OP_WRQ}
OPCODES_DATA_ACK = {OP_DATA, OP_ACK}

# Error codes
EUNDEF = 0  # not defined
ENOTFOUND = 1  # file not found
EACCESS = 2  # access violation
ENOSPACE = 3  # disk full or allocation exceeded
EBADOP = 4  # illegal TFTP operation
EBADID = 5  # unknown transfer ID
EEXISTS = 6  # file already exists
ENOUSER = 7  # no such user


class TFTP(Packet):
	__hdr__ = (
		("opcode", "H", OP_RRQ),
		("file", None, None),
		("block", "H", 0),
		("ttype", None, None)
	)

	def _dissect(self, buf):
		hlen = 2
		opcode = unpack_H(buf[: 2])
		# logger.debug("opcode: %d" % opcode)

		if opcode in OPCODES_DATA_ACK:
			pass
		elif opcode in OPCODES_READ_WRITE:
			self.block = None
			file, ttype = split_nullbyte(buf[2:], maxsplit=2)
			# logger.debug("file/ttype = %r / %r" % (file, ttype))
			self.file = file + b"\x00"
			self.ttype = ttype + b"\x00"
			hlen = 2 + len(self.file) + len(self.ttype)
		elif opcode == OP_ERR:
			# TODO: update
			pass
		return hlen
