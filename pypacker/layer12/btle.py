"""
Bluetooth Low Energy

https://www.bluetooth.com/specifications/adopted-specifications
https://developer.bluetooth.org/TechnologyOverview/Pages/BLE.aspx
https://developer.bluetooth.org/TechnologyOverview/Pages/LE-Security.aspx
"""
import struct
from binascii import hexlify
import logging

from pypacker import triggerlist
from pypacker import pypacker
from pypacker.checksum import crc_btle_check

logger = logging.getLogger("pypacker")

unpack_I = struct.Struct(">I").unpack

"""
flags as BE (in packet: as LE), 0x0001 becomes 0x0100
0x0001 indicates the LE Packet is de-whitened
0x0002 indicates the Signal Power field is valid
0x0004 indicates the Noise Power field is valid
0x0008 indicates the LE Packet is decrypted
0x0010 indicates the Reference Access Address is valid and led to this packet being captured
0x0020 indicates the Access Address Offenses field contains valid data
0x0040 indicates the RF Channel field is subject to aliasing
0x0400 indicates the CRC portion of the LE Packet was checked
0x0800 indicates the CRC portion of the LE Packet passed its check
0x1000 indicates the MIC portion of the decrypted LE Packet was checked
0x2000 indicates the MIC portion of the decrypted LE Packet passed its check
"""

_WHITE_MASK		= (0x0100, 8)
_SIG_MASK		= (0x0200, 9)
_NOISE_MASK		= (0x0400, 10)
_DECR_MASK		= (0x0800, 11)
_REF_ACC_MASK		= (0x1000, 12)
_OFFENSE_MASK		= (0x2000, 13)
_CHAN_ALIAS_MASK	= (0x4000, 14)
_CRC_CHECK_MASK		= (0x0004, 2)
_CRC_PASS_MASK		= (0x0008, 3)
_MIC_CHECK_MASK		= (0x0010, 4)
_MIC_PASS_MASK		= (0x0020, 5)

FLAGS_NAME_MASK = {
	"whitening": _WHITE_MASK,
	"sigvalid": _SIG_MASK,
	"noisevalid": _NOISE_MASK,
	"decrypted": _DECR_MASK,
	"refaavalid": _REF_ACC_MASK,
	"aaoffensesvalid": _OFFENSE_MASK,
	"chanalias": _CHAN_ALIAS_MASK,
	"crcchecked": _CRC_CHECK_MASK,
	"crcvalid": _CRC_PASS_MASK,
	"micchecked": _MIC_CHECK_MASK,
	"micvalid": _MIC_PASS_MASK
}

BTLE_HANDLE_TYPE	= 0
_subheader_properties = []

str_upper = str.upper
bytes_decode = bytes.decode


def reverse_bts(bts):
	return bytes(reversed(bytearray(bts)))


def reverse_bts_to_str(bts):
	bts_rev = reverse_bts(bts)
	return str_upper(bytes_decode(hexlify(bts_rev)))


# set properties to access flags
for name, mask_off in FLAGS_NAME_MASK.items():
	subheader = [
		name,
		(lambda mask, off: (lambda _obj: (_obj.flags & mask) >> off))(mask_off[0], mask_off[1]),
		(lambda mask, off: (lambda _obj, _val: _obj.__setattr__("flags", (_obj.flags & ~mask) | (_val << off)))
			)(mask_off[0], mask_off[1])
	]
	_subheader_properties.append(subheader)


class AdvData(pypacker.Packet):
	__hdr__ = (
		("len", "B", 0),
		("type", "B", 0)
	)


def parse_advdata(bts):
	off = 0
	ret = []

	while off < len(bts):
		alen = bts[off]
		pkt = AdvData(len=alen, type=bts[off + 1], body_bytes=bts[off + 2: off + 1 + alen])
		ret.append(pkt)
		off += 1 + alen
	return ret


#
# Sub header
#


class AdvInd(pypacker.Packet):
	__hdr__ = (
		("adv_addr", "6s", b"\xFF" * 6),
		("adv_data", None, triggerlist.TriggerList),
	)

	def _dissect(self, buf):
		self._init_triggerlist("adv_data", buf[6:], parse_advdata)
		return len(buf)

	adv_addr_s = property(lambda obj: reverse_bts_to_str(obj.adv_addr))
	adv_data_s = property(lambda obj: reverse_bts_to_str(obj.adv_data))


class AdvNonconnInd(pypacker.Packet):
	__hdr__ = (
		("adv_addr", "6s", b"\xFF" * 6),
		("adv_data", None, triggerlist.TriggerList)
	)

	def _dissect(self, buf):
		self._init_triggerlist("adv_data", buf[6:], parse_advdata)
		return len(buf)

	adv_addr_s = property(lambda obj: reverse_bts_to_str(obj.adv_addr))
	adv_data_s = property(lambda obj: reverse_bts_to_str(obj.adv_data))


class ScanRequest(pypacker.Packet):
	__hdr__ = (
		("scan_addr", "6s", b"\xFF" * 6),
		("adv_addr", "6s", b"\xFF" * 6),
	)

	scan_addr_s = property(lambda obj: reverse_bts_to_str(obj.scan_addr))
	adv_addr_s = property(lambda obj: reverse_bts_to_str(obj.adv_addr))


class ScanResponse(pypacker.Packet):
	__hdr__ = (
		("adv_addr", "6s", b"\xFF" * 6),
		("adv_data", None, triggerlist.TriggerList)
	)

	def _dissect(self, buf):
		self._init_triggerlist("adv_data", buf[6:], parse_advdata)
		return len(buf)

	adv_addr_s = property(lambda obj: reverse_bts_to_str(obj.adv_addr))
	adv_data_s = property(lambda obj: reverse_bts_to_str(obj.adv_data))


class ConnRequest(pypacker.Packet):
	__hdr__ = (
		("init_addr", "6s", b"\xFF" * 6),
		("adv_addr", "6s", b"\xFF" * 6),
		("access_addr", "4s", b"\xFF" * 6),
		("crcinit", "3s", b"\xFF" * 3),
		("winsize", "B", 0),
		("winoff", "H", 0),
		("interval", "H", 0),
		("latency", "H", 0),
		("timeout", "H", 0),
		("chanmap", "5s", b"\xFF" * 5),
		("hop_sleep", "B", 0)
	)

	init_addr_s = property(lambda obj: reverse_bts_to_str(obj.init_addr))
	adv_addr_s = property(lambda obj: reverse_bts_to_str(obj.adv_addr))
	access_addr_s = property(lambda obj: reverse_bts_to_str(obj.access_addr))
	crcinit_s = property(lambda obj: reverse_bts_to_str(obj.crcinit))
	crcinit_rev = property(lambda obj: reverse_bts(obj.crcinit))

	def get_active_channels(self):
		"""
		return -- Complete mapping of all channels as list
			including mapping incactive -> active like (1, 2, 3, ...)
		"""
		data_channels_ret = []
		data_channels_active = []
		channel_current = 0
		active_total = 0

		for bt in self.chanmap:
			bit = 1
			for _ in range(8):
				if bt & bit != 0:
					data_channels_ret.append(channel_current)
					data_channels_active.append(channel_current)
					active_total += 1
				else:
					data_channels_ret.append(None)
				bit <<= 1
				channel_current += 1

				if channel_current >= 37:
					break

		for idx, channel in enumerate(data_channels_ret):
			if channel is None:
				data_channels_ret[idx] = data_channels_active[idx % active_total]
		return data_channels_ret

	def __get_crcinit_int(self):
		return unpack_I(b"\x00" + self.crcinit)[0]

	crcinit_int = property(__get_crcinit_int)

	def __get_crcinit_rev_int(self):
		return unpack_I(b"\x00" + self.crcinit_rev)[0]

	crcinit_rev_int = property(__get_crcinit_rev_int)

#
# Data packets
#


class DataLLID0(pypacker.Packet):
	pass


class DataLLID1(pypacker.Packet):
	pass


class DataLLID2(pypacker.Packet):
	pass


# LLX-packets
class LLTerminateInd(pypacker.Packet):
	pass


class LLEncReq(pypacker.Packet):
	__hdr__ = (
		("rand", "8s", b"\x00" * 8),
		("encrdiv", "H", 0),
		("masterdiv", "Q", 0),
		("masterinit", "I", 0)
	)


class LLEncResp(pypacker.Packet):
	__hdr__ = (
		("slavediv", "8s", b"\x00" * 8),
		("slaveinit", "I", 0)
	)


class LLStartEnc(pypacker.Packet):
	pass


class LLVersionInd(pypacker.Packet):
	__hdr__ = (
		("version", "B", 0),
		("company", "H", 0),
		("subcompany", "H", 0)
	)


class LLFeatureReq(pypacker.Packet):
	pass


class LLRejectInd(pypacker.Packet):
	pass


LLID3_TERMINATEIND	= 0x2
LLID3_ENCREQ		= 0x3
LLID3_ENCRESP		= 0x4
LLID3_STARTENC		= 0x5
LLID3_FEATUREREQ	= 0x8
LLID3_VERSIONIND	= 0xC
LLID3_REJECTIND		= 0xD


class DataLLID3(pypacker.Packet):
	__hdr__ = (
		("opcode", "B", 0),
	)

	__handler__ = {
		LLID3_TERMINATEIND: LLTerminateInd,
		LLID3_ENCREQ: LLEncReq,
		LLID3_ENCRESP: LLEncResp,
		LLID3_STARTENC: LLStartEnc,
		LLID3_VERSIONIND: LLVersionInd,
		LLID3_FEATUREREQ: LLFeatureReq,
		LLID3_REJECTIND: LLRejectInd
	}

	def _dissect(self, buf):
		self._init_handler(buf[0], buf[1:])
		return 1


#
# Base header
#


"""
Spec 4.0, p2203

0000 ADV_IND
0001 ADV_DIRECT_IND
0010 ADV_NONCONN_IND
0011 SCAN_REQ
0100 SCAN_RSP
0101 CONNECT_REQ
0110 ADV_SCAN_IND
0111-1111 Reserved

"""
PDU_TYPE_ADV_IND			= 0
PDU_TYPE_ADV_DIRECT_IND			= 1
PDU_TYPE_ADV_NONCONN_IND		= 2
PDU_TYPE_SCAN_REQ			= 3
PDU_TYPE_SCAN_RSP			= 4
PDU_TYPE_CONNECT_REQ			= 5
PDU_TYPE_ADV_SCAN_IND			= 6

# unknown
PDU_TYPE_DATA_LLID0			= 0
# Cont frag of L2CAP msg or empty PDU
PDU_TYPE_DATA_LLID1			= 1
# Start of L2CAP msg or complete L2CAP w/o frag
PDU_TYPE_DATA_LLID2			= 2
# Ctrl PDU
PDU_TYPE_DATA_LLID3			= 3


def _get_property_subtype_get(obj):
	if obj.access_addr == b"\xD6\xBE\x89\x8E":
		return obj.info & 0x0F
	else:
		return obj.info & 0x03


def _get_property_subtype_set(obj, val):
	if obj.access_addr == b"\xD6\xBE\x89\x8E":
		obj.info = (obj.info & ~0x0F) | val
	else:
		obj.info = (obj.info & ~0x03) | val

# TODO: update
_subheader_btle_properties = [
	["pdutype",
	lambda _obj: _get_property_subtype_get(_obj),
	lambda _obj, _val: _get_property_subtype_set(_obj, _val)],
	["random_rx",
	lambda _obj: (_obj.info & 0x80) >> 7,
	lambda _obj, _val: (_obj.info & ~0x80) | (_val << 7)],
	["random_tx",
	lambda _obj: (_obj.info & 0x40) >> 6,
	lambda _obj, _val: (_obj.info & ~0x40) | (_val << 6)],
	["llid",
	lambda _obj: _obj.info & 0x03,
	lambda _obj, _val: (_obj.info & ~0x03) | _val],
	["is_adv",
	lambda _obj: _obj.access_addr == b"\xD6\xBE\x89\x8E"]
]


class BTLE(pypacker.Packet):
	__hdr__ = (
		("access_addr", "4s", b"\xff" * 4),
		("info", "B", 0),
		("len", "B", 0),
	)

	__hdr_sub__ = _subheader_btle_properties

	__handler__ = {
		PDU_TYPE_ADV_IND: AdvInd,
		PDU_TYPE_ADV_SCAN_IND: ScanRequest,
		PDU_TYPE_ADV_NONCONN_IND: AdvNonconnInd,
		PDU_TYPE_SCAN_REQ: ScanRequest,
		PDU_TYPE_SCAN_RSP: ScanResponse,
		PDU_TYPE_CONNECT_REQ: ConnRequest,
		(PDU_TYPE_DATA_LLID0 + 1) << 8: DataLLID0,
		(PDU_TYPE_DATA_LLID1 + 1) << 8: DataLLID1,
		(PDU_TYPE_DATA_LLID2 + 1) << 8: DataLLID2,
		(PDU_TYPE_DATA_LLID3 + 1) << 8: DataLLID3,
	}

	def _dissect(self, buf):
		hlen = 6
		#logger.debug("buf: %r" % buf)

		if buf[: 4] == b"\xD6\xBE\x89\x8E":
			#logger.debug("got ADV... packet")
			btle_type = buf[4] & 0x0F
		else:
			#logger.debug("got data packet")
			# max value is 15, shift to avoid collision with ADV... packets
			btle_type = ((buf[4] & 0x03) + 1) << 8
		#logger.warning("unpacked type: %r" % btle_type)
		self._init_handler(btle_type, buf[hlen: -3])

		self._crc = buf[-3:]
		return hlen

	def bin(self, update_auto_fields=True):
		"""Custom bin(): handle crc for BTLE."""
		return pypacker.Packet.bin(self, update_auto_fields=update_auto_fields) + self.crc

	def __len__(self):
		return super().__len__() + len(self.crc)

	# handle crc attribute
	def __get_crc(self):
		try:
			return self._crc
		except AttributeError:
			return b""

	def __set_crc(self, crc):
		self._crc = crc

	crc = property(__get_crc, __set_crc)

	def is_crc_ok(self, crc_init=0xAAAAAA):
		return crc_btle_check(self.bin(), crc_init)

	crc_ok = property(is_crc_ok)


# BTLE packet header
# http://www.tcpdump.org/linktypes.html -> LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR
class BTLEHdr(pypacker.Packet):
	__hdr__ = (
		("channel", "B", 0),
		("signal", "B", 0),
		("noise", "B", 0),
		("aaoffense", "B", 0),
		("refaddr", "4s", b"\xFF" * 4),
		("flags", "H", 0),
	)

	__hdr_sub__ = _subheader_properties

	__handler__ = {
		BTLE_HANDLE_TYPE: BTLE
	}

	def _dissect(self, buf):
		self._init_handler(BTLE_HANDLE_TYPE, buf[10:])
		#logger.debug("BTLE header: %r" % buf[:10])
		#logger.debug(adding %d flags" % len(self.flags))
		return 10
