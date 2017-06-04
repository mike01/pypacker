"""Precision Time Protocol v2, IEEE 1588-2008"""
import logging
import struct

from pypacker import pypacker

logger = logging.getLogger("pypacker")
unpack_Q = struct.Struct(">Q").unpack
pack_Q = struct.Struct(">Q").pack


PTPv2_TYPE_SYNC				= 0x0  # Flags: PTP_TWO_STEP = True
PTPv2_TYPE_DELAY_REQ			= 0x1
# IEEE802.1AS is the Audio-Visual Bridging (AVB) profile of the IEEE1588 Precision Time Protocol
PTPv2_TYPE_PATH_DELAY_REQ		= 0x2
PTPv2_TYPE_PATH_DELAY_RESP		= 0x3

PTPv2_TYPE_FOLLOW_UP			= 0x8
PTPv2_TYPE_DELAY_RESP			= 0x9
PTPv2_TYPE_PATH_DELAY_RESP_FOLLOWUP	= 0xA
PTPv2_TYPE_ANNOUNCE			= 0xB  # Flags: PTP_TIMESCALE = True
PTPv2_TYPE_SIGNALLING			= 0xC
PTPv2_TYPE_MGMT				= 0xD

CTRL_TYPE_SYNC				= 0x0
CTRL_TYPE_DELAY_REQ			= 0x1
CTRL_TYPE_FOLLOW_UP			= 0x2
CTRL_TYPE_DELAY_RESP			= 0x3
CTRL_TYPE_MGMT				= 0x4
CTRL_TYPE_OTHER				= 0x5


TYPES_TS_ACTIVATE = {PTPv2_TYPE_SYNC, PTPv2_TYPE_FOLLOW_UP, PTPv2_TYPE_ANNOUNCE,
		PTPv2_TYPE_PATH_DELAY_RESP}
TYPES_REQ_PORT_ACTIVATE = {PTPv2_TYPE_PATH_DELAY_RESP, PTPv2_TYPE_PATH_DELAY_RESP_FOLLOWUP}


class PTPv2(pypacker.Packet):
	__hdr__ = (
		("transport_id", "B", PTPv2_TYPE_DELAY_REQ),
		("version", "B", 2),
		("msglen", "H", 0),
		("subdomains", "B", 0),
		("rsv", "B", 0),
		("flags", "H", 0),
		("corr", "Q", 0),
		("rsv2", "I", 0),
		("clockid", "Q", 0),
		("srcport", "H", 0),
		("seqid", "H", 0),
		("ctrl", "B", 0),
		("log", "B", 0),
		("tssec_bts", "6s", None),
		("tsnano", "I", None),
		("reqclockid", "Q", None),
		("reqportid", "H", None)
	)

	def __get_transport(self):
		return (self.transport_id & 0xF0) >> 4

	def __set_transport(self, value):
		self.transport_id = ((value & 0xF) << 4) | (self.transport_id & 0xF)

	transport = property(__get_transport, __set_transport)

	def __get_id(self):
		return self.transport_id & 0xF

	def __set_id(self, value):
		self.transport_id = (self.transport_id & 0xF0) | (value & 0xF)

	id = property(__get_id, __set_id)

	def __get_tssec(self):
		return unpack_Q(b"\x00\x00" + self.tssec_bts)[0]

	def __set_tssec(self, value):
		self.tssec_bts = pack_Q(value)[2:]  # (8-2) bytes

	# allows setting tssec as integer in contrast to tssec_bts
	tssec = property(__get_tssec, __set_tssec)

	class Announce(pypacker.Packet):
		__hdr__ = (
			("utcoff", "H", 0),
			("prio1", "H", 0),
			("clockclass", "B", 0),
			("clockaccuracy", "B", 0),
			("clockvariance", "H", 0),
			("prio2", "B", 0),
			("clockid", "Q", 0),
			("stepsremoved", "H", 0),
			("timesource", "B", 0)
		)

	__handler__ = {
		PTPv2_TYPE_ANNOUNCE: Announce
	}

	def _dissect(self, buf):
		header_len = 34
		ptpv2_type = buf[0] & 0xF

		if ptpv2_type in TYPES_TS_ACTIVATE:
			#logger.debug("activating ts fields")
			self.tssec_bts = b"\x00" * 6
			self.tsnano = 0
			header_len += 10

		if ptpv2_type in TYPES_REQ_PORT_ACTIVATE:
			#logger.debug("activating req fields")
			self.reqclockid = 0
			self.reqportid = 0
			header_len += 10
		elif ptpv2_type == PTPv2_TYPE_ANNOUNCE:
			#logger.debug("got announce")
			self._init_handler(ptpv2_type, buf[header_len:])

		if len(buf) < header_len:
			logger.warning("not enough bytes for header: %d < %d", len(buf), header_len)

		return header_len
