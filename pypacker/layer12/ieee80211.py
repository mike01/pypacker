"""IEEE 802.11"""

from pypacker import pypacker
from pypacker import triggerlist

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
M_ACTION		= 13
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

D_NORMAL		= 0
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
_PROTECTED_MASK		= 0x0040
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
_PROTECTED_SHIFT	= 6
_ORDER_SHIFT		= 7


# needed to distinguish subtypes via types
TYPE_FACTORS		= [16, 32, 64]
TYPE_FACTOR_PROTECTED	= 128


class IEEE80211(pypacker.Packet):
	__hdr__ = (
		# AAAABBCC | 00000000
		# AAAA = subtype BB = type CC = version
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

	def _get_from_to_ds(self):
		return (self.framectl & (_TO_DS_MASK | _FROM_DS_MASK))

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

	def _get_protected(self):
		return (self.framectl & _PROTECTED_MASK) >> _PROTECTED_SHIFT

	def _set_protected(self, val):
		self.framectl = (val << _PROTECTED_SHIFT) | (self.framectl & ~_PROTECTED_MASK)

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
	protected = property(_get_protected, _set_protected)
	order = property(_get_order, _set_order)
	from_to_ds = property(_get_from_to_ds)

	def _dissect(self, buf):
		self.framectl = struct.unpack(">H", buf[0:2])[0]

			#logger.debug("got protected packet, type/sub/prot: %d/%d/%d" %
			#	(TYPE_FACTORS[self.type], self.subtype, protected_factor))
		#logger.debug("ieee80211 type/subtype is: %d/%d" % (self.type, self.subtype))
		self._parse_handler(TYPE_FACTORS[self.type] + self.subtype, buf[4:])

	#
	# mgmt frames
	#
	class Beacon(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
			("bssid", "6s", b"\x00" * 6),
			("src", "6s", b"\x00" * 6),
			# 12 Bits: 0->4095 | 4 Bits
			# SF SS (LE)
			("seq_frag", "H", 0),
			# _ts (integer) is saved as LE
			("_ts", "Q", 0),
			("interval", "H", 0x6400),
			("capa", "H", 0x0100),
			("params", None, triggerlist.TriggerList)
		)

		def _get_seq(self):
			return (self.seq_frag & 0xFF) << 4 | (self.seq_frag >> 12)

		def _set_seq(self, val):
			self.seq_frag = (val & 0xF) << 12 | (val & 0xFF0) >> 4 | (self.seq_frag & 0x0F00)

		def _get_ts(self):
			# LE->BE: dirty but simple
			return struct.unpack("<Q", struct.pack(">Q", self._ts))[0]

		def _set_ts(self, val):
			self._ts = struct.unpack("<Q", struct.pack(">Q", val))[0]

		seq = property(_get_seq, _set_seq)
		ts = property(_get_ts, _set_ts)
		dst_s = pypacker.get_property_mac("dst")
		bssid_s = pypacker.get_property_mac("bssid")
		src_s = pypacker.get_property_mac("src")

		def _dissect(self, buf):
			self.params.init_lazy_dissect(buf[32:], IEEE80211._unpack_ies)

		def reverse_address(self):
			self.dst, self.src = self.src, self.dst

	class Action(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
			("src", "6s", b"\x00" * 6),
			("bssid", "6s", b"\x00" * 6),
			("seq_frag", "H", 0),
			("category", "B", 0),
			("code", "B", 0)
		)

		class BlockAckRequest(pypacker.Packet):
			__hdr__ = (
				("dialog", "B", 0),
				("parameters", "H", 0),
				("timeout", "H", 0),
				("starting_seq", "H", 0),
			)

		class BlockAckResponse(pypacker.Packet):
			__hdr__ = (
				("dialog", "B", 0),
				("status_code", "H", 0),
				("parameters", "H", 0),
				("timeout", "H", 0),
			)

		CATEGORY_BLOCK_ACK	= 3
		CODE_BLOCK_ACK_REQUEST	= 0
		CODE_BLOCK_ACK_RESPONSE	= 1

		dst_s = pypacker.get_property_mac("dst")
		src_s = pypacker.get_property_mac("src")
		bssid_s = pypacker.get_property_mac("bssid")

		def _dissect(self, buf):
			#logger.debug(">>>>>>>> ACTION!!!")
			# category: block ack, code: request or response
			self._parse_handler(buf[20] * 4 + buf[21], buf[22:])

		def reverse_address(self):
			self.dst, self.src = self.src, self.dst

	class ProbeReq(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
			("bssid", "6s", b"\x00" * 6),
			("src", "6s", b"\x00" * 6),
			("seq_frag", "H", 0),
			("params", None, triggerlist.TriggerList)
		)

		dst_s = pypacker.get_property_mac("dst")
		bssid_s = pypacker.get_property_mac("bssid")
		src_s = pypacker.get_property_mac("src")

		def _dissect(self, buf):
			self.params.init_lazy_dissect(buf[20:], IEEE80211._unpack_ies)

		def reverse_address(self):
			self.dst, self.src = self.src, self.dst

	class ProbeResp(Beacon):
		pass

	class AssocReq(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
			("bssid", "6s", b"\x00" * 6),
			("src", "6s", b"\x00" * 6),
			("seq_frag", "H", 0),
			("capa", "H", 0),
			("interval", "H", 0),
			("params", None, triggerlist.TriggerList)
		)

		dst_s = pypacker.get_property_mac("dst")
		bssid_s = pypacker.get_property_mac("bssid")
		src_s = pypacker.get_property_mac("src")

		def _dissect(self, buf):
			self.params.init_lazy_dissect(buf[24:], IEEE80211._unpack_ies)

		def reverse_address(self):
			self.dst, self.src = self.src, self.dst

	class AssocResp(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
			("bssid", "6s", b"\x00" * 6),
			("src", "6s", b"\x00" * 6),
			("seq_frag", "H", 0),
			("capa", "H", 0),
			("status", "H", 0),
			("aid", "H", 0),
			("params", None, triggerlist.TriggerList)
		)

		dst_s = pypacker.get_property_mac("dst")
		bssid_s = pypacker.get_property_mac("bssid")
		src_s = pypacker.get_property_mac("src")

		def _dissect(self, buf):
			self.params.init_lazy_dissect(buf[26:], IEEE80211._unpack_ies)

		def reverse_address(self):
			self.dst, self.src = self.src, self.dst

	class Disassoc(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
			("bssid", "6s", b"\x00" * 6),
			("src", "6s", b"\x00" * 6),
			("seq_frag", "H", 0),
			("reason", "H", 0),
		)

		dst_s = pypacker.get_property_mac("dst")
		bssid_s = pypacker.get_property_mac("bssid")
		src_s = pypacker.get_property_mac("src")

		def reverse_address(self):
			self.dst, self.src = self.src, self.dst

	class ReassocReq(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
			("bssid", "6s", b"\x00" * 6),
			("src", "6s", b"\x00" * 6),
			("seq_frag", "H", 0),
			("capa", "H", 0),
			("interval", "H", 0),
			("current_ap", "6s", b"\x00" * 6)
		)

		dst_s = pypacker.get_property_mac("dst")
		bssid_s = pypacker.get_property_mac("bssid")
		src_s = pypacker.get_property_mac("src")

		def reverse_address(self):
			self.dst, self.src = self.src, self.dst

	class Auth(pypacker.Packet):
		"""Authentication request."""
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
			("src", "6s", b"\x00" * 6),
			("bssid", "6s", b"\x00" * 6),
			("seq_frag", "H", 0),
			("algo", "H", 0),
			("seq", "H", 0x0100),
			("status", "H", 0)
		)

		dst_s = pypacker.get_property_mac("dst")
		bssid_s = pypacker.get_property_mac("bssid")
		src_s = pypacker.get_property_mac("src")

		def reverse_address(self):
			self.dst, self.src = self.src, self.dst

	class Deauth(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
			("bssid", "6s", b"\x00" * 6),
			("src", "6s", b"\x00" * 6),
			("seq_frag", "H", 0),
			("reason", "H", 0)
		)

		dst_s = pypacker.get_property_mac("dst")
		bssid_s = pypacker.get_property_mac("bssid")
		src_s = pypacker.get_property_mac("src")

		def reverse_address(self):
			self.dst, self.src = self.src, self.dst

	m_decoder = {
		M_BEACON	: Beacon,
		M_ACTION	: Action,
		M_ASSOC_REQ	: AssocReq,
		M_ASSOC_RESP	: AssocResp,
		M_DISASSOC	: Disassoc,
		M_REASSOC_REQ	: ReassocReq,
		M_REASSOC_RESP	: AssocResp,
		M_AUTH		: Auth,
		M_PROBE_REQ	: ProbeReq,
		M_PROBE_RESP	: ProbeResp,
		M_DEAUTH	: Deauth
	}

	#
	# Control frames: no need for extra layer: 802.11 Base data is enough
	#

	class RTS(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
			("src", "6s", b"\x00" * 6)
		)

		dst_s = pypacker.get_property_mac("dst")
		src_s = pypacker.get_property_mac("src")

		def reverse_address(self):
			self.dst, self.src = self.src, self.dst

	class CTS(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
		)

		dst_s = pypacker.get_property_mac("dst")

	class ACK(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
		)

		dst_s = pypacker.get_property_mac("dst")

	class BlockAckReq(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
			("src", "6s", b"\x00" * 6),
			("reqctrl", "H", 0),
			("seq", "H", 0)
		)

		dst_s = pypacker.get_property_mac("dst")
		src_s = pypacker.get_property_mac("src")

		def reverse_address(self):
			self.dst, self.src = self.src, self.dst

	class BlockAck(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
			("src", "6s", b"\x00" * 6),
			("reqctrl", "H", 0),
			("seq", "H", 0),
			("bitmap", "Q", 0)
		)

		dst_s = pypacker.get_property_mac("dst")
		src_s = pypacker.get_property_mac("src")

		def reverse_address(self):
			self.dst, self.src = self.src, self.dst

	class CFEnd(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
			("src", "6s", b"\x00" * 6),
		)

		dst_s = pypacker.get_property_mac("dst")
		src_s = pypacker.get_property_mac("src")

		def reverse_address(self):
			self.dst, self.src = self.src, self.dst

	c_decoder = {
		C_RTS		: RTS,
		C_CTS		: CTS,
		C_ACK		: ACK,
		C_BLOCK_ACK_REQ	: BlockAckReq,
		C_BLOCK_ACK	: BlockAck,
		C_CF_END	: CFEnd
	}

	#
	# data frames
	#
	class Dataframe(pypacker.Packet):
		"""
		DataFrames need special care: there are too many types of field combinations to create classes
		for everyone. Solution: initiate giving lower type via constructor.
		In order to use "src/dst/bssid" instead of addrX set from_to_ds to one of the following values:

		[Bit 0: from DS][Bit 1: to DS] = [order of fields]

		00 = 0 = dst, src, bssid
		01 = 1 = bssid, src, dst
		10 = 2 = dst, bssid, src
		11 = 3 = RA, TA, DA, SA
		"""
		def __init__(self, *arg, **kwargs):
			if len(arg) > 1:
				#logger.debug("extracting lower layer type: %r" % arg[1])
				self.dtype = arg[1]
			else:
				self.dtype = self
			super().__init__(*arg, **kwargs)

		__hdr__ = (
			("addr1", "6s", b"\x00" * 6),
			("addr2", "6s", b"\x00" * 6),
			("addr3", "6s", b"\x00" * 6),
			("seq_frag", "H", 0),
			("addr4", "6s", None),		# to/from-DS = 1
			("qos_ctrl", "H", 0),		# QoS
			("sec_param", "Q", 0)		# protected
		)

		def reverse_address(self):
			if self.dtype.from_to_ds == 0:
				self.addr1, self.addr2 = self.addr2, self.addr1
			elif self.dtype.from_to_ds == 1:
				self.addr2, self.addr3 = self.addr3, self.addr2
			elif self.dtype.from_to_ds == 2:
				self.addr1, self.addr3 = self.addr3, self.addr1

		# FromDs, ToDS
		# 00 = dst, src, bssid
		# 01 = bssid, src, dst
		# 10 = dst, bssid, src
		# 11 = RA, TA, DA, SA

		def __get_src(self):
			return self.addr2 if self.dtype.from_to_ds in [0, 1] else self.addr3

		def __set_src(self, src):
			if self.dtype.from_to_ds in [0, 1]:
				self.addr2 = src
			else:
				self.addr3 = src

		def __get_dst(self):
			return self.addr1 if self.dtype.from_to_ds in [0, 2] else self.addr3

		def __set_dst(self, dst):
			if self.dtype.from_to_ds in [0, 2]:
				self.addr1 = dst
			else:
				self.addr3 = dst

		def __get_bssid(self):
			dstype = self.dtype.from_to_ds

			if dstype == 0:
				return self.addr3
			elif dstype == 1:
				return self.addr1
			elif dstype == 2:
				return self.addr2

		def __set_bssid(self, bssid):
			dstype = self.dtype.from_to_ds
			if dstype == 0:
				self.addr3 = bssid
			elif dstype == 1:
				self.addr1 = bssid
			elif dstype == 2:
				self.addr2 = bssid

		src = property(__get_src, __set_src)
		src_s = pypacker.get_property_mac("src")
		dst = property(__get_dst, __set_dst)
		dst_s = pypacker.get_property_mac("dst")
		bssid = property(__get_bssid, __set_bssid)
		bssid_s = pypacker.get_property_mac("bssid")

		__QOS_SUBTYPES = set([8, 9, 10, 11, 12, 14, 15])

		def _dissect(self, buf):
			#logger.debug("starting dissecting, buflen: %r" % str(buf))

			try:
				is_qos = True if self.dtype.subtype in IEEE80211.Dataframe.__QOS_SUBTYPES else False
				is_protected = self.dtype.protected == 1
				is_bridge = True if self.dtype.from_ds == 1 and self.dtype.to_ds == 1 else False
			except Exception as e:
				#logger.debug(e)
				# default is fromds
				is_qos = False
				is_protected = False
				is_bridge = False

			#logger.debug("switching fields1")
			if not is_qos:
				self.qos_ctrl = None
			#logger.debug("switching fields2")
			if not is_protected:
				self.sec_param = None
			#logger.debug("switching fields3")
			if is_bridge:
				self.addr4 = b"\x00" * 6
			#logger.debug("format/length/len(bin): %s/%d/%d" % (self._hdr_fmtstr, self.hdr_len, len(self.bin())))
			#logger.debug("%r" % self)

	d_decoder = {
		D_NORMAL		: Dataframe,
		D_DATA_CF_ACK		: Dataframe,
		D_DATA_CF_POLL 		: Dataframe,
		D_DATA_CF_ACK_POLL 	: Dataframe,
		D_NULL			: Dataframe,
		D_CF_ACK		: Dataframe,
		D_CF_POLL		: Dataframe,
		D_CF_ACK_POLL		: Dataframe,
		D_QOS_DATA		: Dataframe,
		D_QOS_CF_ACK		: Dataframe,
		D_QOS_CF_POLL		: Dataframe,
		D_QOS_CF_ACK_POLL	: Dataframe,
		D_QOS_NULL		: Dataframe,
		D_QOS_CF_POLL_EMPTY	: Dataframe
	}

	#
	# IEs for Mgmt-Frames
	#
	def _unpack_ies(buf):
		"""Parse IEs and return them as Triggerlist."""
		# each IE starts with an ID and a length
		ies = []
		off = 0
		buflen = len(buf)
		#logger.debug("lazy dissecting: %s" % buf)

		while off < buflen:
			ie_id = buf[off]
			try:
				parser = IEEE80211.ie_decoder[ie_id]
			except KeyError:
				# some unknown tag, use standard format
				parser = IEEE80211.IE

			dlen = buf[off + 1]
			#logger.debug("IE parser is: %d = %s = %s" % (ie_id, parser, buf[off: off+2+dlen]))
			ie = parser(buf[off: off + 2 + dlen])
			ies.append(ie)
			off += 2 + dlen

		return ies

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
		IE_SSID		: IE,
		IE_RATES	: IE,
		IE_FH		: FH,
		IE_DS		: DS,
		IE_CF		: CF,
		IE_TIM		: TIM,
		IE_IBSS		: IBSS,
		IE_HT_CAPA	: IE,
		IE_ESR		: IE,
		IE_HT_INFO	: IE
	}


# handler for IEEE80211
# position in list = type-ID
dicts			= [IEEE80211.m_decoder, IEEE80211.c_decoder, IEEE80211.d_decoder]
decoder_dict_complete	= {}

for pos, dict in enumerate(dicts):
	for key, val in dict.items():
		# same subtype-ID for different typ-IDs, distinguish via "type_factor + subtype)"
		decoder_dict_complete[TYPE_FACTORS[pos] + key] = val

pypacker.Packet.load_handler(IEEE80211, decoder_dict_complete)

# handler for Action
CATEGORY_BLOCK_ACK_FACTOR = IEEE80211.Action.CATEGORY_BLOCK_ACK * 4
pypacker.Packet.load_handler(IEEE80211.Action,
	{
		CATEGORY_BLOCK_ACK_FACTOR + IEEE80211.Action.CODE_BLOCK_ACK_REQUEST: IEEE80211.Action.BlockAckRequest,
		CATEGORY_BLOCK_ACK_FACTOR + IEEE80211.Action.CODE_BLOCK_ACK_RESPONSE: IEEE80211.Action.BlockAckResponse
	}
)
