"""Ethernet Flow Control"""
import struct

from pypacker import pypacker, triggerlist


PAUSE_OPCODE	= 0x0001		# Pause frame IEEE 802.3x
PFC_OPCODE	= 0x0101		# Priority Flow Control IEEE 802.1Qbb

unpack_H = struct.Struct(">H").unpack
pack_H = struct.Struct(">H").pack


class FlowControl(pypacker.Packet):
	__hdr__ = (
		("opcode", "H", PAUSE_OPCODE),
	)

	def _dissect(self, buf):
		if buf[:2] == b"\x01\x01":
			self._init_handler(PFC_OPCODE, buf[2:])
		else:
			self._init_handler(PAUSE_OPCODE, buf[2:])
		return 2

	class Pause(pypacker.Packet):
		__hdr__ = (
			("ptime", "H", 0x0000),
		)

	class PFC(pypacker.Packet):
		__hdr__ = (
			("ms", "B", 0),  # most significant octet is reserved,set to zero
			("ls", "B", 0),  # least significant octet indicates time_vector parameter
			("time", None, triggerlist.TriggerList),
		)

		# Conveniant access to ls field(bit representation via list)
		# e.g. 221 == [1, 1, 0, 1, 1, 1, 0, 1]
		def __get_ls(self):
			return [(self.ls >> x) & 1 for x in reversed(range(8))]

		def __set_ls(self, value):
			self.ls = int("".join(map(str, value)), 2)
		ls_list = property(__get_ls, __set_ls)

		# Conveniant access to time field(decimal representation via list)
		def __get_time(self):
			return [unpack_H(x)[0] for x in self.time]

		def __set_time(self, value):
			self.time = [pack_H(x) for x in value]
		time_list = property(__get_time, __set_time)

		def _dissect(self, buf):
			for i in range(2, 18, 2):
				self.time.append(buf[i:i + 2])
			# TODO: find more efficient way, always correct?
			return 2 + len(self.time) * 2

	__handler__ = {
		PAUSE_OPCODE: Pause,
		PFC_OPCODE: PFC
	}
