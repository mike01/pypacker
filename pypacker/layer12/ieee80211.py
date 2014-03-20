"""IEEE 802.11"""

from pypacker import pypacker
from pypacker.triggerlist import TriggerList

import struct
import logging

logger = logging.getLogger("pypacker")

# Frame Types
MGMT_TYPE		= 0
CTL_TYPE		= 1
DATA_TYPE		= 2

# Frame Sub-Types
M_ASSOC_REQ		= 0
M_ASSOC_RESP		= 1
M_REASSOC_REQ		= 2
M_REASSOC_RESP		= 3
M_PROBE_REQ		= 4
M_PROBE_RESP		= 5
M_DISASSOC		= 10
M_AUTH			= 11
M_DEAUTH		= 12
M_BEACON		= 8
M_ATIM			= 9
C_BLOCK_ACK_REQ		= 8
C_BLOCK_ACK		= 9
C_PS_POLL		= 10
C_RTS			= 11
C_CTS			= 12
C_ACK			= 13
C_CF_END		= 14
C_CF_END_ACK		= 15
D_DATA			= 0
D_DATA_CF_ACK		= 1
D_DATA_CF_POLL		= 2
D_DATA_CF_ACK_POLL	= 3
D_NULL			= 4
D_CF_ACK		= 5
D_CF_POLL		= 6
D_CF_ACK_POLL		= 7
D_QOS_DATA		= 8
D_QOS_CF_ACK		= 9
D_QOS_CF_POLL		= 10
D_QOS_CF_ACK_POLL	= 11
D_QOS_NULL		= 12
D_QOS_CF_POLL_EMPTY	= 14

TO_DS_FLAG		= 10
FROM_DS_FLAG		= 1
INTER_DS_FLAG		= 11

# Bitshifts for Frame Control
_VERSION_MASK		= 0x0300
_TYPE_MASK		= 0x0c00
_SUBTYPE_MASK		= 0xf000
_TO_DS_MASK		= 0x0001
_FROM_DS_MASK		= 0x0002
_MORE_FRAG_MASK		= 0x0004
_RETRY_MASK		= 0x0008
_PWR_MGT_MASK		= 0x0010
_MORE_DATA_MASK		= 0x0020
_WEP_MASK		= 0x0040
_ORDER_MASK		= 0x0080
_VERSION_SHIFT		= 8
_TYPE_SHIFT		= 10
_SUBTYPE_SHIFT		= 12
_TO_DS_SHIFT		= 0
_FROM_DS_SHIFT		= 1
_MORE_FRAG_SHIFT	= 2
_RETRY_SHIFT		= 3
_PWR_MGT_SHIFT		= 4
_MORE_DATA_SHIFT	= 5
_WEP_SHIFT		= 6
_ORDER_SHIFT		= 7


class IEEE80211(pypacker.Packet):
	__hdr__ = (
		("framectl", "H", 0),
		("duration", "H", 0)
	)

	def _get_version(self):
		return (self.framectl & _VERSION_MASK) >> _VERSION_SHIFT

	def _set_version(self, val):
		self.framectl = (val << _VERSION_SHIFT) | (self.framectl & ~_VERSION_MASK)

	def _get_type(self):
		return (self.framectl & _TYPE_MASK) >> _TYPE_SHIFT

	def _set_type(self, val):
		self.framectl = (val << _TYPE_SHIFT) | (self.framectl & ~_TYPE_MASK)

	def _get_subtype(self):
		return (self.framectl & _SUBTYPE_MASK) >> _SUBTYPE_SHIFT

	def _set_subtype(self, val):
		self.framectl = (val << _SUBTYPE_SHIFT) | (self.framectl & ~_SUBTYPE_MASK)

	def _get_to_ds(self):
		return (self.framectl & _TO_DS_MASK) >> _TO_DS_SHIFT

	def _set_to_ds(self, val):
		self.framectl = (val << _TO_DS_SHIFT) | (self.framectl & ~_TO_DS_MASK)

	def _get_from_ds(self):
		return (self.framectl & _FROM_DS_MASK) >> _FROM_DS_SHIFT

	def _set_from_ds(self, val):
		self.framectl = (val << _FROM_DS_SHIFT) | (self.framectl & ~_FROM_DS_MASK)

	def _get_more_frag(self):
		return (self.framectl & _MORE_FRAG_MASK) >> _MORE_FRAG_SHIFT

	def _set_more_frag(self, val):
		self.framectl = (val << _MORE_FRAG_SHIFT) | (self.framectl & ~_MORE_FRAG_MASK)

	def _get_retry(self):
		return (self.framectl & _RETRY_MASK) >> _RETRY_SHIFT

	def _set_retry(self, val):
		self.framectl = (val << _RETRY_SHIFT) | (self.framectl & ~_RETRY_MASK)

	def _get_pwr_mgt(self):
		return (self.framectl & _PWR_MGT_MASK) >> _PWR_MGT_SHIFT

	def _set_pwr_mgt(self, val):
		self.framectl = (val << _PWR_MGT_SHIFT) | (self.framectl & ~_PWR_MGT_MASK)

	def _get_more_data(self):
		return (self.framectl & _MORE_DATA_MASK) >> _MORE_DATA_SHIFT

	def _set_more_data(self, val):
		self.framectl = (val << _MORE_DATA_SHIFT) | (self.framectl & ~_MORE_DATA_MASK)

	def _get_wep(self):
		return (self.framectl & _WEP_MASK) >> _WEP_SHIFT

	def _set_wep(self, val):
		self.framectl = (val << _WEP_SHIFT) | (self.framectl & ~_WEP_MASK)

	def _get_order(self):
		return (self.framectl & _ORDER_MASK) >> _ORDER_SHIFT

	def _set_order(self, val):
		self.framectl = (val << _ORDER_SHIFT) | (self.framectl & ~_ORDER_MASK)

	version = property(_get_version, _set_version)
	type = property(_get_type, _set_type)
	subtype = property(_get_subtype, _set_subtype)
	to_ds = property(_get_to_ds, _set_to_ds)
	from_ds = property(_get_from_ds, _set_from_ds)
	more_frag = property(_get_more_frag, _set_more_frag)
	retry = property(_get_retry, _set_retry)
	pwr_mgt = property(_get_pwr_mgt, _set_pwr_mgt)
	more_data = property(_get_more_data, _set_more_data)
	wep = property(_get_wep, _set_wep)
	order = property(_get_order, _set_order)

	def _dissect(self, buf):
		# packet structure:
		# Type info + [MGMT frame + subdata [+ IEs] | subdata]
		# unpack first field for this layer (avoid calling unpack)
		self.framectl = struct.unpack(">H", buf[0:2])[0]

		packet = self
		offset = 4

		#logger.debug("type/subtype: %d/%d" % (self.type, self.subtype))

		if self.type == MGMT_TYPE:
			mgmt = IEEE80211.MGMTFrame(buf[offset:offset + 20])
			packet._set_bodyhandler(mgmt)

			if self.subtype in [M_PROBE_REQ, M_ATIM]:
				return
			offset += 20
			# this will set the handler's handler on next calls to "_set_bodyhandler()"
			packet = mgmt

		try:
			parser = IEEE80211.decoder[self.type][self.subtype][1]
			parser_inst = None

			#name = decoder[self.type][self.subtype][0]
			if self.type == DATA_TYPE:
				# TODO: set handler in case of not encrypted data (ethernet etc)
				# need to grab the ToDS/FromDS info
				parser = parser[self.to_ds * 10 + self.from_ds]
				#logger.debug("parser for data is: %s" % parser)
				parser_inst = parser()
				# easier way than defining QoS packets for every single data-frame type
				if self.subtype == D_QOS_DATA:
					#logger.debug("adding QOS data")
					parser_inst._add_headerfield("qoscontrol", "H", 0)
				if self.wep == 1:
					#logger.debug("adding ccmp data")
					parser_inst._add_headerfield("ccmp", "Q", 0)
			else:
				parser_inst = parser(buf[offset:])

			self._set_bodyhandler( parser_inst )

		except KeyError:
			logger.debug("802.11: unknown type/subtype: %d/%d" % (self.type, self.subtype))

	class BlockAckReq(pypacker.Packet):
		__hdr__ = (
			("ctl", "H", 0),
			("seq", "H", 0),
		)

	class BlockAck(pypacker.Packet):
		__hdr__ = (
			("ctl", "H", 0),
			("seq", "H", 0),
			("bmp", "128s", b"\x00" * 128)
		)

	class RTS(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
			("src", "6s", b"\x00" * 6)
		)

		dst_s = pypacker.Packet._get_property_mac("dst")
		src_s = pypacker.Packet._get_property_mac("src")

	class CTS(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
		)
		dst_s = pypacker.Packet._get_property_mac("dst")

	class ACK(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
		)

	class MGMTFrame(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
			("src", "6s", b"\x00" * 6),
			("bssid", "6s", b"\x00" * 6),
			("frag_seq", "H", 0)
		)

		dst_s = pypacker.Packet._get_property_mac("dst")
		src_s = pypacker.Packet._get_property_mac("src")
		bssid_s = pypacker.Packet._get_property_mac("bssid")

		# TODO: make this accessible using properties
		#if self.type == MGMT_TYPE:
		#	self.ies = self.unpack_ies(field.data)
		#	if self.subtype == M_BEACON or self.subtype == M_ASSOC_RESP or\
		#		self.subtype == M_ASSOC_REQ or self.subtype == M_REASSOC_REQ:
		#		self.capability = self.Capability(socket.ntohs(field.capability))
		class Capability:
			def __init__(self, field):
				self.ess = field & 1
				self.ibss = (field >> 1) & 1
				self.cf_poll = (field >> 2) & 1
				self.cf_poll_req = (field >> 3) & 1
				self.privacy = (field >> 4) & 1
				self.short_preamble = (field >> 5) & 1
				self.pbcc = (field >> 6) & 1
				self.hopping = (field >> 7) & 1
				self.spec_mgmt = (field >> 8) & 1
				self.qos = (field >> 9) & 1
				self.short_slot = (field >> 10) & 1
				self.apsd = (field >> 11) & 1
				self.dsss = (field >> 13) & 1
				self.delayed_blk_ack = (field >> 14) & 1
				self.imm_blk_ack = (field >> 15) & 1

	def __unpack_ies(self, buf):
		"""Parse IEs and return them as Triggerlist."""
		# each IE starts with an ID and a length
		ies = []
		off = 0
		buflen = len(buf)

		while off < buflen:
			ie_id = buf[off]
			try:
				parser = IEEE80211.ie_decoder[ie_id][1]
			except KeyError:
				# some unknown tag, use standard format
				parser = self.IE

			dlen = buf[off + 1]
			#logger.debug("IE parser is: %d = %s = %s" % (ie_id, parser, buf[off: off+2+dlen]))
			ie = parser( buf[off: off + 2 + dlen])
			ies.append(ie)
			off += 2 + dlen

		return ies
	unpack_ies = classmethod(__unpack_ies)

	#
	# IEs for Mgmt-Frames
	#
	class IE(pypacker.Packet):
		__hdr__ = (
			("id", "B", 0),
			("len", "B", 0)
		)

	class FH(pypacker.Packet):
		__hdr__ = (
			("id", "B", 0),
			("len", "B", 0),
			("tu", "H", 0),
			("hopset", "B", 0),
			("hoppattern", "B", 0),
			("hopindex", "B", 0)
		)

	class DS(pypacker.Packet):
		__hdr__ = (
			("id", "B", 0),
			("len", "B", 0),
			("ch", "B", 0)
		)

	class CF(pypacker.Packet):
		__hdr__ = (
			("id", "B", 0),
			("len", "B", 0),
			("count", "B", 0),
			("period", "B", 0),
			("max", "H", 0),
			("dur", "H", 0)
		)

	class TIM(pypacker.Packet):
		__hdr__ = (
			("id", "B", 0),
			("len", "B", 0),
			("count", "B", 0),
			("period", "B", 0),
			("ctrl", "H", 0)
		)
		#def unpack(self, buf):
		#	pypacker.Packet.unpack(self, buf)
		#	self.bitmap = buf[5:self.len+ 2]

	class IBSS(pypacker.Packet):
		__hdr__ = (
			("id", "B", 0),
			("len", "B", 0),
			("atim", "H", 0)
		)

	# IEs
	IE_SSID			= 0
	IE_RATES		= 1
	IE_FH			= 2
	IE_DS			= 3
	IE_CF			= 4
	IE_TIM			= 5
	IE_IBSS			= 6
	IE_HT_CAPA		= 45
	IE_ESR			= 50
	IE_HT_INFO		= 61

	ie_decoder = {
		IE_SSID		: ("ssid", IE),
		IE_RATES	: ("rate", IE),
		IE_FH		: ("fh", FH),
		IE_DS		: ("ds", DS),
		IE_CF		: ("cf", CF),
		IE_TIM		: ("tim", TIM),
		IE_IBSS		: ("ibss", IBSS),
		IE_HT_CAPA	: ("ht_capa", IE),
		IE_ESR		: ("esr", IE),
		IE_HT_INFO	: ("ht_info", IE)
		}

	class Beacon(pypacker.Packet):
		__hdr__ = (
			("timestamp", "Q", 0),
			("interval", "H", 0),
			("capability", "H", 0),
			("ies", None, TriggerList)
		)

		def _dissect(self, buf):
			# TODO: test this and all other lazy dissects using "unpack_ies"
			self.ies.init_lazy_dissect(buf[12:], IEEE80211.unpack_ies)

	class Disassoc(pypacker.Packet):
		__hdr__ = (
			("reason", "H", 0),
		)

	class Assoc_Req(pypacker.Packet):
		__hdr__ = (
			("capability", "H", 0),
			("interval", "H", 0),
			("ies", None, TriggerList)
		)

		def _dissect(self, buf):
			self.ies.init_lazy_dissect(buf[4:], IEEE80211.unpack_ies)

	class Assoc_Resp(pypacker.Packet):
		__hdr__ = (
			("capability", "H", 0),
			("status", "H", 0),
			("aid", "H", 0),
			("ies", None, TriggerList)
		)

		def _dissect(self, buf):
			self.ies.init_lazy_dissect(buf[6:], IEEE80211.unpack_ies)

	class Reassoc_Req(pypacker.Packet):
		__hdr__ = (
			("capability", "H", 0),
			("interval", "H", 0),
			("current_ap", "6s", b"\x00" * 6)
		)

	# This obviously doesn't support any of AUTH frames that use encryption
	class Auth(pypacker.Packet):
		__hdr__ = (
			("algorithm", "H", 0),
			("auth_seq", "H", 0),
		)

	class Deauth(pypacker.Packet):
		__hdr__ = (
			("reason", "H", 0),
		)

	class DataFrame(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
			("src", "6s", b"\x00" * 6),
			("bssid", "6s", b"\x00" * 6),
			("frag_seq", "H", 0)
		)

		dst_s = pypacker.Packet._get_property_mac("dst")
		src_s = pypacker.Packet._get_property_mac("src")
		bssid_s = pypacker.Packet._get_property_mac("bssid")

	class DataFromDS(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
			("bssid", "6s", b"\x00" * 6),
			("src", "6s", b"\x00" * 6),
			("frag_seq", "H", 0)
		)

		dst_s = pypacker.Packet._get_property_mac("dst")
		bssid_s = pypacker.Packet._get_property_mac("bssid")
		src_s = pypacker.Packet._get_property_mac("src")

		# TODO: add TKIP data parsing
	class DataToDS(pypacker.Packet):
		__hdr__ = (
			("bssid", "6s", b"\x00" * 6),
			("src", "6s", b"\x00" * 6),
			("dst", "6s", b"\x00" * 6),
			("frag_seq", "H", 0)
		)

		bssid_s = pypacker.Packet._get_property_mac("bssid")
		src_s = pypacker.Packet._get_property_mac("src")
		dst_s = pypacker.Packet._get_property_mac("dst")

	class DataInterDS(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
			("src", "6s", b"\x00" * 6),
			("da", "6s", b"\x00" * 6),
			("frag_seq", "H", 0),
			("sa", "6s", b"\x00" * 6)
		)
		dst_s = pypacker.Packet._get_property_mac("dst")
		src_s = pypacker.Packet._get_property_mac("src")
		da_s = pypacker.Packet._get_property_mac("da")

	#class QoS_Data(pypacker.Packet):
	#	__hdr__ = (
	#		("control", "H", 0),
	#		)

	m_decoder = {
		M_BEACON	: ("beacon", Beacon),
		M_ASSOC_REQ	: ("assoc_req", Assoc_Req),
		M_ASSOC_RESP	: ("assoc_resp", Assoc_Resp),
		M_DISASSOC	: ("diassoc", Disassoc),
		M_REASSOC_REQ	: ("reassoc_req", Reassoc_Req),
		M_REASSOC_RESP	: ("reassoc_resp", Assoc_Resp),
		M_AUTH		: ("auth", Auth),
		M_PROBE_RESP	: ("probe_resp", Beacon),
		M_DEAUTH	: ("deauth", Deauth)
	}

	c_decoder = {
		C_RTS		: ("rts", RTS),
		C_CTS		: ("cts", CTS),
		C_ACK		: ("ack", ACK),
		C_BLOCK_ACK_REQ	: ("bar", BlockAckReq),
		C_BLOCK_ACK	: ("back", BlockAck)
	}

	d_dsData = {
		0		: DataFrame,
		FROM_DS_FLAG	: DataFromDS,
		TO_DS_FLAG	: DataToDS,
		INTER_DS_FLAG	: DataInterDS
	}

	# For now decode everything with DATA. Haven't checked about other QoS additions
	d_decoder = {
		# modified the decoder to consider the ToDS and FromDS flags
		# Omitting the 11 case for now
		D_DATA		: ("data_frame", d_dsData),
		D_NULL		: ("data_frame", d_dsData),
		D_QOS_DATA	: ("data_frame", d_dsData),
		D_QOS_NULL	: ("data_frame", d_dsData)
	}

	decoder = {
		MGMT_TYPE	: m_decoder,
		CTL_TYPE	: c_decoder,
		DATA_TYPE	: d_decoder
	}
