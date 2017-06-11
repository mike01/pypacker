"""IEEE 802.11"""
import struct
import logging

from pypacker import pypacker
from pypacker import triggerlist
from pypacker import utils

# avoid reverences for performance reasons
unpack_framectl = struct.Struct(">H").unpack
unpack_Q_le = struct.Struct("<Q").unpack
pack_Q_be = struct.Struct(">Q").pack

logger = logging.getLogger("pypacker")


# Frame Types
MGMT_TYPE		= 0
CTL_TYPE		= 1
DATA_TYPE		= 2

# Frame Sub-Types
# MGMT_TYPE
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

# CTL_TYPE
C_BLOCK_ACK_REQ		= 8
C_BLOCK_ACK		= 9
C_PS_POLL		= 10
C_RTS			= 11
C_CTS			= 12
C_ACK			= 13
C_CF_END		= 14
C_CF_END_ACK		= 15

# DATA_TYPE
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

TO_DS_FLAG		= 1
FROM_DS_FLAG		= 2
INTER_DS_FLAG		= 3


# name : (mask, offset)
_FRAMECTRL_SUBHEADERDATA = {
	"version": (0x0300, 8),
	"type": (0x0c00, 10),
	"subtype": (0xf000, 12),
	"to_ds": (0x0001, 0),
	"from_ds": (0x0002, 1),
	"more_frag": (0x0004, 2),
	"retry": (0x0008, 3),
	"pwr_mgt": (0x0010, 4),
	"more_data": (0x0020, 5),
	"protected": (0x0040, 6),
	"order": (0x0080, 7),
	"from_to_ds": (0x0002 | 0x0001, 0),
}

# needed to distinguish subtypes via types
TYPE_FACTORS		= [16, 32, 64]
TYPE_FACTOR_PROTECTED	= 128

_subheader_properties = []

IEEE_FIELDS_SRC_DST_BSSID = ["src", "dst", "bssid"]

# set properties to access flags
for subfield_name, mask_off in _FRAMECTRL_SUBHEADERDATA.items():
	# logger.debug("setting prop: %r, %X, %X" % (subfield_name, mask_off[0], mask_off[1]))
	subheader = [
		subfield_name,
		# lambda**2: avoid lexical closure, do not refer to value via reference
		(lambda mask, off:
			(lambda _obj: (_obj.framectl & mask) >> off))(mask_off[0], mask_off[1]),
		(lambda mask, off:
			(lambda _obj, _val: _obj.__setattr__("framectl",
				(_obj.framectl & ~mask) | (_val << off))))(mask_off[0], mask_off[1]),
	]
	_subheader_properties.append(subheader)


class IEEE80211(pypacker.Packet):
	__hdr__ = (
		# AAAABBCC | 00000000
		# AAAA = subtype BB = type CC = version
		("framectl", "H", 0),
		("duration", "H", 0x3a01)  # 314 microseconds
	)

	__hdr_sub__ = _subheader_properties

	def _dissect(self, buf):
		self.framectl = unpack_framectl(buf[0:2])[0]
		# logger.debug("ieee80211 bytes=%X, type/subtype is=%X/%X, handler=%r" %
		# 			(self.framectl, self.type, self.subtype,
		# 			 pypacker.Packet._id_handlerclass_dct[self.__class__][TYPE_FACTORS[self.type] + self.subtype]))
		self._init_handler(TYPE_FACTORS[self.type] + self.subtype, buf[4:])
		return 4

	def is_beacon(self):
		"""return -- True if packet is a beacon. Avoids parsing upper layer."""
		return self.type == MGMT_TYPE and self.subtype == M_BEACON

	def extract_client_macs(self):
		"""
		Extracts client MACs from upper layer if this is a data packet.

		return -- [mac_client1, ...] or [] if no client macs could be found
		"""
		macs_clients = []

		# data: client -> AP or client <- AP
		if self.type == DATA_TYPE:
			if self.from_ds == 1 and self.to_ds == 0:
				macs_clients.append(self.upper_layer.dst)
			elif self.from_ds == 0 and self.to_ds == 1:
				macs_clients.append(self.upper_layer.src)

		return [addr for addr in macs_clients if not utils.is_special_mac(addr)]

	#
	# mgmt frames
	#
	class Beacon(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
			("src", "6s", b"\x00" * 6),
			("bssid", "6s", b"\x00" * 6),
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
			return unpack_Q_le(pack_Q_be(self._ts))[0]

		def _set_ts(self, val):
			self._ts = unpack_Q_le(pack_Q_be(val))[0]

		seq = property(_get_seq, _set_seq)
		ts = property(_get_ts, _set_ts)
		dst_s = pypacker.get_property_mac("dst")
		bssid_s = pypacker.get_property_mac("bssid")
		src_s = pypacker.get_property_mac("src")

		def _dissect(self, buf):
			self._init_triggerlist("params", buf[32:], IEEE80211._unpack_ies)
			return len(buf)

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

		def _get_seq(self):
			return (self.seq_frag & 0xFF) << 4 | (self.seq_frag >> 12)

		def _set_seq(self, val):
			self.seq_frag = (val & 0xF) << 12 | (val & 0xFF0) >> 4 | (self.seq_frag & 0x0F00)

		seq = property(_get_seq, _set_seq)

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
			# logger.debug(">>>>>>>> ACTION!!!")
			# category: block ack, code: request or response
			self._init_handler(buf[20] * 4 + buf[21], buf[22:])
			return 22

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

		def _get_seq(self):
			return (self.seq_frag & 0xFF) << 4 | (self.seq_frag >> 12)

		def _set_seq(self, val):
			self.seq_frag = (val & 0xF) << 12 | (val & 0xFF0) >> 4 | (self.seq_frag & 0x0F00)

		seq = property(_get_seq, _set_seq)

		def _dissect(self, buf):
			self._init_triggerlist("params", buf[20:], IEEE80211._unpack_ies)
			return len(buf)

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

		def _get_seq(self):
			return (self.seq_frag & 0xFF) << 4 | (self.seq_frag >> 12)

		def _set_seq(self, val):
			self.seq_frag = (val & 0xF) << 12 | (val & 0xFF0) >> 4 | (self.seq_frag & 0x0F00)

		seq = property(_get_seq, _set_seq)

		def _dissect(self, buf):
			self._init_triggerlist("params", buf[24:], IEEE80211._unpack_ies)
			return len(buf)

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

		def _get_seq(self):
			return (self.seq_frag & 0xFF) << 4 | (self.seq_frag >> 12)

		def _set_seq(self, val):
			self.seq_frag = (val & 0xF) << 12 | (val & 0xFF0) >> 4 | (self.seq_frag & 0x0F00)

		seq = property(_get_seq, _set_seq)

		def _dissect(self, buf):
			self._init_triggerlist("params", buf[26:], IEEE80211._unpack_ies)
			return len(buf)

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

		def _get_seq(self):
			return (self.seq_frag & 0xFF) << 4 | (self.seq_frag >> 12)

		def _set_seq(self, val):
			self.seq_frag = (val & 0xF) << 12 | (val & 0xFF0) >> 4 | (self.seq_frag & 0x0F00)

		seq = property(_get_seq, _set_seq)

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

		def _get_seq(self):
			return (self.seq_frag & 0xFF) << 4 | (self.seq_frag >> 12)

		def _set_seq(self, val):
			self.seq_frag = (val & 0xF) << 12 | (val & 0xFF0) >> 4 | (self.seq_frag & 0x0F00)

		seq = property(_get_seq, _set_seq)

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
			("authseq", "H", 0x0100),
			("status", "H", 0)
		)

		dst_s = pypacker.get_property_mac("dst")
		bssid_s = pypacker.get_property_mac("bssid")
		src_s = pypacker.get_property_mac("src")

		def _get_seq(self):
			return (self.seq_frag & 0xFF) << 4 | (self.seq_frag >> 12)

		def _set_seq(self, val):
			self.seq_frag = (val & 0xF) << 12 | (val & 0xFF0) >> 4 | (self.seq_frag & 0x0F00)

		seq = property(_get_seq, _set_seq)

		def reverse_address(self):
			self.dst, self.src = self.src, self.dst

	class Deauth(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\xFF" * 6),
			("src", "6s", b"\x00" * 6),
			("bssid", "6s", b"\xFF" * 6),
			("seq_frag", "H", 0),
			("reason", "H", 0x0700)  # class 3 frame received from non associated client
		)

		dst_s = pypacker.get_property_mac("dst")
		bssid_s = pypacker.get_property_mac("bssid")
		src_s = pypacker.get_property_mac("src")

		def _get_seq(self):
			return (self.seq_frag & 0xFF) << 4 | (self.seq_frag >> 12)

		def _set_seq(self, val):
			self.seq_frag = (val & 0xF) << 12 | (val & 0xFF0) >> 4 | (self.seq_frag & 0x0F00)

		seq = property(_get_seq, _set_seq)

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
		DataFrames need special care: there are too many types of field combinations
		to create classes for every one. Solution: initiate giving lower type "subType"
		via constructor. In order to use "src/dst/bssid" instead of addrX set from_to_ds
		of "subType" to one of the following values:

		[Bit 0: from DS][Bit 1: to DS] = [order of fields]

		00 = 0 = dst, src, bssid
		01 = 1 = bssid, src, dst
		10 = 2 = dst, bssid, src
		11 = 3 = RA, TA, DA, SA
		"""
		def __init__(self, *arg, **kwargs):
			if len(arg) > 1:
				# logger.debug("extracting lower layer type: %r" % arg[1])
				self.dtype = arg[1]
			else:
				self.dtype = self
				self._from_to_ds_value = 0
			#logger.debug("dstype: %r" % self.dtype.from_to_ds)
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

		def _get_seq(self):
			return (self.seq_frag & 0xFF) << 4 | (self.seq_frag >> 12)

		def _set_seq(self, val):
			self.seq_frag = (val & 0xF) << 12 | (val & 0xFF0) >> 4 | (self.seq_frag & 0x0F00)

		seq = property(_get_seq, _set_seq)

		def reverse_address(self):
			if self.dtype.from_to_ds == 0:
				self.addr1, self.addr2 = self.addr2, self.addr1
			elif self.dtype.from_to_ds == 1:
				self.addr2, self.addr3 = self.addr3, self.addr2
			elif self.dtype.from_to_ds == 2:
				self.addr1, self.addr3 = self.addr3, self.addr1

		def _get_from_to_ds(self):
			return self._from_to_ds_value
		# same property structure as in IEEE80211 class
		from_to_ds = property(_get_from_to_ds)

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

		__QOS_SUBTYPES = {8, 9, 10, 11, 12, 14, 15}

		def _dissect(self, buf):
			# logger.debug("starting dissecting, buflen: %r" % str(buf))
			header_len = 30

			try:
				is_qos = True if self.dtype.subtype in IEEE80211.Dataframe.__QOS_SUBTYPES else False
				is_protected = self.dtype.protected == 1
				is_bridge = True if self.dtype.from_ds == 1 and self.dtype.to_ds == 1 else False
			except Exception:
				# logger.debug(e)
				# default is fromds
				is_qos = False
				is_protected = False
				is_bridge = False

			# logger.debug("switching fields1")
			if not is_qos:
				self.qos_ctrl = None
				header_len -= 2
			# logger.debug("switching fields2")
			if not is_protected:
				self.sec_param = None
				header_len -= 8
			# logger.debug("switching fields3")
			if is_bridge:
				self.addr4 = b"\x00" * 6
				header_len += 6
			# logger.debug("format/length/len(bin): %s/%d/%d" % (self._hdr_fmtstr, self.hdr_len, len(self.bin())))
			# logger.debug("%r" % self)
			return header_len

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
	@staticmethod
	def _unpack_ies(buf):
		"""Parse IEs and return them as Triggerlist."""
		# each IE starts with an ID and a length
		ies = []
		off = 0
		buflen = len(buf)
		# logger.debug("lazy dissecting: %s" % buf)

		while off < buflen:
			ie_id = buf[off]
			try:
				parser = IEEE80211.ie_decoder[ie_id]
			except KeyError:
				# some unknown tag, use standard format
				parser = IEEE80211.IE

			dlen = buf[off + 1]
			# logger.debug("IE parser is: %d = %s = %s" % (ie_id, parser, buf[off: off+2+dlen]))
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

for pos, decoder_dict in enumerate(dicts):
	for key_decoder, val_decoder in decoder_dict.items():
		# same subtype-ID for different type-IDs, distinguish via "type_factor + subtype"
		# not doing so would lead to eg: type:0 + subtype:1 == type:1 + subtype:0
		decoder_dict_complete[TYPE_FACTORS[pos] + key_decoder] = val_decoder

pypacker.Packet.load_handler(IEEE80211, decoder_dict_complete)

# handler for Action
CATEGORY_BLOCK_ACK_FACTOR = IEEE80211.Action.CATEGORY_BLOCK_ACK * 4
pypacker.Packet.load_handler(IEEE80211.Action,
	{
		CATEGORY_BLOCK_ACK_FACTOR + IEEE80211.Action.CODE_BLOCK_ACK_REQUEST: IEEE80211.Action.BlockAckRequest,
		CATEGORY_BLOCK_ACK_FACTOR + IEEE80211.Action.CODE_BLOCK_ACK_RESPONSE: IEEE80211.Action.BlockAckResponse
	}
)