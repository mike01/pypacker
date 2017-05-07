"""
Link Layer Discovery Protocol
IEEE 802.1AB
DCB eXchange protocol
IEEE 802.1Qaz
"""
import struct

from pypacker import pypacker, triggerlist
from pypacker.pypacker import (mac_str_to_bytes, mac_bytes_to_str,
								ip4_str_to_bytes, ip4_bytes_to_str,
								ip6_str_to_bytes, ip6_bytes_to_str)
from pypacker.pypacker import FIELD_FLAG_AUTOUPDATE

# avoid unneeded references for performance reasons
unpack_H = struct.Struct(">H").unpack
unpack_I = struct.Struct(">I").unpack
unpack_B = struct.Struct(">B").unpack
pack_B = struct.Struct(">B").pack


# Mandatory TLV fields length in bytes
# of two field type(7-bit) and length(9-bit)
TLV_HEADER_LEN = 2
TYPE_FIELD_BITS = 7
LENGTH_FIELD_BITS = 9
TYPE_MASK = 0xFE00
LENGTH_MASK = 0x01FF

# Organizationally specific TLV fields length in bytes
# of two field OUI(24-bit) and subtype(8-bit)
ORG_SPEC_TYPE = 127
ORG_SPEC_HEADER_LEN = 4
OUI_MASK = 0xFFFFFF00
# length of TLV Subtype field
SUBTYPE_LEN_BYTE = 1
SUBTYPE_LEN_BITS = 8
SUBTYPE_MASK = 0x000000FF


# Convenient access for value field in Chassis TLV
GET_CHASSIS_TLV_SUBTYPES = {4: mac_bytes_to_str, 5: ip4_bytes_to_str}
SET_CHASSIS_TLV_SUBTYPES = {4: mac_str_to_bytes, 5: ip4_str_to_bytes}
# Convenient access for value field in Port TLV
GET_PORT_TLV_SUBTYPES = {3: mac_bytes_to_str, 4: ip4_bytes_to_str}
SET_PORT_TLV_SUBTYPES = {3: mac_str_to_bytes, 4: ip4_str_to_bytes}
# Convenient access for Management Address
GET_ADDRESS_SUBTYPE = {1: ip4_bytes_to_str, 2: ip6_bytes_to_str, 6: mac_bytes_to_str}
SET_ADDRESS_SUBTYPE = {1: ip4_str_to_bytes, 2: ip6_str_to_bytes, 6: mac_str_to_bytes}


def get_property_tlv_type():
	"""Create a get/set-property for type field."""
	return property(
		lambda obj: (obj.type_len & TYPE_MASK) >> LENGTH_FIELD_BITS,
		lambda obj, val: obj.__setattr__("type_len",
			(obj.type_len & ~TYPE_MASK) | (val << LENGTH_FIELD_BITS)),
	)


def get_property_tlv_len():
	"""Create a get/set-property for length field."""
	return property(
		lambda obj: obj.type_len & LENGTH_MASK,
		lambda obj, val: obj.__setattr__("type_len", (obj.type_len & TYPE_MASK) | val)
	)


def get_property_tlv_oui():
	"""Create a get/set-property for OUI field."""
	return property(
		lambda obj: (obj.oui_subtype & OUI_MASK) >> 8,
		lambda obj, val: obj.__setattr__("oui_subtype", (obj.oui_subtype & ~OUI_MASK) | (val << 8))
	)


def get_property_tlv_subtype():
	"""Create a get/set-property for subtype field."""
	return property(
		lambda obj: obj.oui_subtype & SUBTYPE_MASK,
		lambda obj, val: obj.__setattr__("oui_subtype",
			(obj.oui_subtype & OUI_MASK) | val),
	)


def get_property_to_convert_8_bytes_to_list(var):
	"""Create a get/set-property to convert 8 bytes field to list(decimal representation)."""
	return property(
		lambda obj: [unpack_B(x)[0] for x in obj.__getattribute__(var)],
		lambda obj, val: obj.__setattr__(var, [pack_B(x) for x in val]),
	)


def get_property_to_convert_4_bytes_to_list(var):
	"""Create a get/set-property to convert 4 bytes field to list(decimal representation)."""
	return property(
		lambda obj: [(obj.__getattribute__(var) >> x) & 0xF for x in reversed(range(0, 32, 4))],
		lambda obj, val: obj.__setattr__(var,
			sum([item << bits for item, bits in zip(val, reversed(range(0, 32, 4)))])),
	)


def get_property_to_convert_1_byte_to_list(var):
	"""Create a get/set-property to convert 1 byte field to list(bit representation)."""
	return property(
		lambda obj: [(obj.__getattribute__(var) >> x) & 1 for x in reversed(range(8))],
		lambda obj, val: obj.__setattr__(var, int("".join(map(str, val)), 2)),
	)


class LLDP(pypacker.Packet):
	__hdr__ = (
		("tlvlist", None, triggerlist.TriggerList),
	)

	def _dissect(self, buf):
		self._init_triggerlist("tlvlist", buf, self.__parse_tlv)
		return len(buf)

	@staticmethod
	def __parse_tlv(buf):
		"""Parse LLDP TLVs and return them as list."""
		_, clz_bts_list = count_and_dissect_tlvs(buf)
		tlvlist = []

		for clz, bts in clz_bts_list:
			tlvlist.append(clz(bts))

		return tlvlist


class LLDPGeneric(pypacker.Packet):
	__hdr__ = (
		("type_len", "H", 0, FIELD_FLAG_AUTOUPDATE),
		("value", None, b""),
	)

	tlv_type = get_property_tlv_type()
	tlv_len = get_property_tlv_len()

	def _dissect(self, buf):
		self.value = buf[TLV_HEADER_LEN:]
		return len(buf)

	def bin(self, update_auto_fields=True):
		if update_auto_fields and self._changed() and self.type_len_au_active:
			self.tlv_len = len(self) - TLV_HEADER_LEN
		return pypacker.Packet.bin(self, update_auto_fields=update_auto_fields)


class LLDPDUEnd(pypacker.Packet):
	__hdr__ = (
		("tlv_type", "B", 0),
		("tlv_len", "B", 0),
	)


class LLDPChassisId(pypacker.Packet):
	__hdr__ = (
		("type_len", "H", 512, FIELD_FLAG_AUTOUPDATE),  # type(1)
		("subtype", "B", 0),
		("value", None, b""),
	)
	tlv_type = get_property_tlv_type()
	tlv_len = get_property_tlv_len()

	def __get_value(self):
		if self.subtype not in GET_CHASSIS_TLV_SUBTYPES.keys():
			return self.value
		return GET_CHASSIS_TLV_SUBTYPES.get(self.subtype)(self.value)

	def __set_value(self, value):
		if self.subtype not in SET_CHASSIS_TLV_SUBTYPES.keys():
			self.value = value
		else:
			self.value = SET_CHASSIS_TLV_SUBTYPES.get(self.subtype)(value)
	value_s = property(__get_value, __set_value)

	def _dissect(self, buf):
		self.value = buf[TLV_HEADER_LEN + SUBTYPE_LEN_BYTE:]
		return len(buf)

	def bin(self, update_auto_fields=True):
		if update_auto_fields and self._changed() and self.type_len_au_active:
			self.tlv_len = len(self) - TLV_HEADER_LEN
		return pypacker.Packet.bin(self, update_auto_fields=update_auto_fields)


class LLDPPortId(pypacker.Packet):
	__hdr__ = (
		("type_len", "H", 1024, FIELD_FLAG_AUTOUPDATE),  # type(2)
		("subtype", "B", 0),
		("value", None, b""),
	)
	tlv_type = get_property_tlv_type()
	tlv_len = get_property_tlv_len()

	def __get_value(self):
		if self.subtype not in GET_PORT_TLV_SUBTYPES.keys():
			return self.value
		return GET_PORT_TLV_SUBTYPES.get(self.subtype)(self.value)

	def __set_value(self, value):
		if self.subtype not in SET_PORT_TLV_SUBTYPES.keys():
			self.value = value
		else:
			self.value = SET_PORT_TLV_SUBTYPES.get(self.subtype)(value)
	value_s = property(__get_value, __set_value)

	def _dissect(self, buf):
		self.value = buf[TLV_HEADER_LEN + SUBTYPE_LEN_BYTE:]
		return len(buf)

	def bin(self, update_auto_fields=True):
		if update_auto_fields and self._changed() and self.type_len_au_active:
			self.tlv_len = len(self) - TLV_HEADER_LEN
		return pypacker.Packet.bin(self, update_auto_fields=update_auto_fields)


class LLDPTTL(pypacker.Packet):
	__hdr__ = (
		("type_len", "H", 1538),  # type(3), length(2)
		("seconds", "H", 0),
	)
	tlv_type = get_property_tlv_type()
	tlv_len = get_property_tlv_len()


class LLDPPortDescription(pypacker.Packet):
	__hdr__ = (
		("type_len", "H", 2048, FIELD_FLAG_AUTOUPDATE),  # type(4)
		("value", None, b""),
	)

	tlv_type = get_property_tlv_type()
	tlv_len = get_property_tlv_len()

	def _dissect(self, buf):
		self.value = buf[TLV_HEADER_LEN:]
		return len(buf)

	def bin(self, update_auto_fields=True):
		if update_auto_fields and self._changed() and self.type_len_au_active:
			self.tlv_len = len(self) - TLV_HEADER_LEN
		return pypacker.Packet.bin(self, update_auto_fields=update_auto_fields)


class LLDPSystemName(pypacker.Packet):
	__hdr__ = (
		("type_len", "H", 2560, FIELD_FLAG_AUTOUPDATE),  # type(5)
		("value", None, b""),
	)

	tlv_type = get_property_tlv_type()
	tlv_len = get_property_tlv_len()

	def _dissect(self, buf):
		self.value = buf[TLV_HEADER_LEN:]
		return len(buf)

	def bin(self, update_auto_fields=True):
		if update_auto_fields and self._changed() and self.type_len_au_active:
			self.tlv_len = len(self) - TLV_HEADER_LEN
		return pypacker.Packet.bin(self, update_auto_fields=update_auto_fields)


class LLDPSystemDescription(pypacker.Packet):
	__hdr__ = (
		("type_len", "H", 3072, FIELD_FLAG_AUTOUPDATE),  # type(6)
		("value", None, b""),
	)

	tlv_type = get_property_tlv_type()
	tlv_len = get_property_tlv_len()

	def _dissect(self, buf):
		self.value = buf[TLV_HEADER_LEN:]
		return len(buf)

	def bin(self, update_auto_fields=True):
		if update_auto_fields and self._changed() and self.type_len_au_active:
			self.tlv_len = len(self) - TLV_HEADER_LEN
		return pypacker.Packet.bin(self, update_auto_fields=update_auto_fields)


class LLDPSystemCapabilities(pypacker.Packet):
	__hdr__ = (
		("type_len", "H", 3588),  # type(7), length(4)
		("capabilities", "H", 0),
		("enabled", "H", 0),
	)
	tlv_type = get_property_tlv_type()
	tlv_len = get_property_tlv_len()


class LLDPManagementAddress(pypacker.Packet):
	__hdr__ = (
		("type_len", "H", 4096, FIELD_FLAG_AUTOUPDATE),
		# contains the length of the addrsubtype(1 byte) + addrval(1-31 bytes) fields
		("addrlen", "B", 2, FIELD_FLAG_AUTOUPDATE),
		("addrsubtype", "B", 0),
		("addrval", None, b"\x00"),
		# contains one of subtypes {1: "Unknown", 2: "ifIndex", 3: "System Port Number"}
		("ifsubtype", "B", 1),
		("ifnumber", "I", 0),
		("oidlen", "B", 0, FIELD_FLAG_AUTOUPDATE),
		("oid", None, b""),
	)

	tlv_type = get_property_tlv_type()
	tlv_len = get_property_tlv_len()

	def __get_addrval(self):
		if self.addrsubtype not in GET_ADDRESS_SUBTYPE.keys():
			return self.addrval
		return GET_ADDRESS_SUBTYPE.get(self.addrsubtype)(self.addrval)

	def __set_addrval(self, value):
		if self.addrsubtype not in SET_ADDRESS_SUBTYPE.keys():
			self.addrval = value
		else:
			self.addrval = SET_ADDRESS_SUBTYPE.get(self.addrsubtype)(value)
	addrval_s = property(__get_addrval, __set_addrval)

	def _dissect(self, buf):
		addrlen = unpack_B(buf[TLV_HEADER_LEN: TLV_HEADER_LEN + 1])[0]
		addrval_position = TLV_HEADER_LEN + 2
		self.addrval = buf[addrval_position: addrval_position + addrlen - 1]
		oidlen_postion = addrval_position + addrlen + 4
		oidlen = unpack_B(buf[oidlen_postion: oidlen_postion + 1])[0]
		if oidlen:
			self.oid = buf[oidlen_postion + 1: oidlen_postion + 1 + oidlen]
		return len(buf)

	def bin(self, update_auto_fields=True):
		if update_auto_fields and self._changed():
			if self.type_len_au_active:
				self.tlv_len = len(self) - TLV_HEADER_LEN
			if self.addrlen_au_active:
				self.addrlen = len(self.addrval) + SUBTYPE_LEN_BYTE
			if self.oidlen_au_active:
				self.oidlen = len(self.oid)
		return pypacker.Packet.bin(self, update_auto_fields=update_auto_fields)


class LLDPOrgSpecGeneric(pypacker.Packet):
	__hdr__ = (
		("type_len", "H", 65024, FIELD_FLAG_AUTOUPDATE),  # type(127)
		("oui_subtype", "I", 0),
		("value", None, b""),
	)

	tlv_type = get_property_tlv_type()
	tlv_len = get_property_tlv_len()
	oui = get_property_tlv_oui()
	subtype = get_property_tlv_subtype()

	def _dissect(self, buf):
		self.value = buf[TLV_HEADER_LEN + ORG_SPEC_HEADER_LEN:]
		return len(buf)

	def bin(self, update_auto_fields=True):
		if update_auto_fields and self._changed() and self.type_len_au_active:
			self.tlv_len = len(self) - TLV_HEADER_LEN
		return pypacker.Packet.bin(self, update_auto_fields=update_auto_fields)


class LLDPDot1PortVlanId(pypacker.Packet):
	__hdr__ = (
		("type_len", "H", 65030),  # type(127), length(6)
		("oui_subtype", "I", 8438273),  # OUI(00-80-C2), subtype(0x01)
		("vlan", "H", 1),
	)

	tlv_type = get_property_tlv_type()
	tlv_len = get_property_tlv_len()
	oui = get_property_tlv_oui()
	subtype = get_property_tlv_subtype()


class DCBXCongestionNotification(pypacker.Packet):
	__hdr__ = (
		("type_len", "H", 65030),  # type(127), length(6)
		("oui_subtype", "I", 8438280),  # OUI(00-80-C2), subtype(0x08)
		("cnpv", "B", 0),
		("ready", "B", 0),
	)

	tlv_type = get_property_tlv_type()
	tlv_len = get_property_tlv_len()
	oui = get_property_tlv_oui()
	subtype = get_property_tlv_subtype()
	cnpv_list = get_property_to_convert_1_byte_to_list("cnpv")
	ready_list = get_property_to_convert_1_byte_to_list("ready")


class DCBXConfiguration(pypacker.Packet):
	__hdr__ = (
		("type_len", "H", 65049),  # type(127), length(25)
		("oui_subtype", "I", 8438281),  # OUI(00-80-C2), subtype(0x09)
		("w_cbs_maxtc", "B", 0),  # Field contains Willing-1bit, CBS-1bit, Reserved-3bit,  Max TCs-3bit
		("priority", "I", 0),  # Field represents list of 8 items where one item = 4 bits
		("tcbandwith", None, triggerlist.TriggerList),
		("tsaassigment", None, triggerlist.TriggerList),
	)

	tlv_type = get_property_tlv_type()
	tlv_len = get_property_tlv_len()
	oui = get_property_tlv_oui()
	subtype = get_property_tlv_subtype()
	tcbandwith_list = get_property_to_convert_8_bytes_to_list("tcbandwith")
	tsaassigment_list = get_property_to_convert_8_bytes_to_list("tsaassigment")
	priority_list = get_property_to_convert_4_bytes_to_list("priority")

	def __get_w(self):
		return (self.w_cbs_maxtc & 0x80) >> 7

	def __set_w(self, value):
		self.w_cbs_maxtc = (self.w_cbs_maxtc & ~0x80) | (value << 7)
	willing = property(__get_w, __set_w)

	def __get_cbs(self):
		return (self.w_cbs_maxtc & 0x40) >> 6

	def __set_cbs(self, value):
		self.w_cbs_maxtc = (self.w_cbs_maxtc & ~0x40) | (value << 6)
	cbs = property(__get_cbs, __set_cbs)

	def __get_maxtcs(self):
		return self.w_cbs_maxtc & 0x07

	def __set_maxtcs(self, value):
		self.w_cbs_maxtc = self.w_cbs_maxtc & 0xF8 | value
	maxtcs = property(__get_maxtcs, __set_maxtcs)

	def _dissect(self, buf):
		for i in range(11, 19):
			self.tcbandwith.append(buf[i:i + 1])
		for i in range(19, 27):
			self.tsaassigment.append(buf[i:i + 1])
		return len(self)


class DCBXRecommendation(pypacker.Packet):
	__hdr__ = (
		("type_len", "H", 65049),  # type(127), length(25)
		("oui_subtype", "I", 8438282),  # OUI(00-80-C2), subtype(0x10)
		("reserved", "B", 0),
		("priority", "I", 0),  # Field represents list of 8 items where one item = 4 bits
		("tcbandwith", None, triggerlist.TriggerList),
		("tsaassigment", None, triggerlist.TriggerList),
	)

	tlv_type = get_property_tlv_type()
	tlv_len = get_property_tlv_len()
	oui = get_property_tlv_oui()
	subtype = get_property_tlv_subtype()
	tcbandwith_list = get_property_to_convert_8_bytes_to_list("tcbandwith")
	tsaassigment_list = get_property_to_convert_8_bytes_to_list("tsaassigment")
	priority_list = get_property_to_convert_4_bytes_to_list("priority")

	def _dissect(self, buf):
		# start from TLV_HEADER_LEN + ORG_SPEC_HEADER_LEN +
		# 1 byte(reserved) + 4 bytes(priority)
		for i in range(11, 19):
			self.tcbandwith.append(buf[i:i + 1])
		for i in range(19, 27):
			self.tsaassigment.append(buf[i:i + 1])
		return len(self)


class DCBXPriorityBasedFlowControlConfiguration(pypacker.Packet):
	__hdr__ = (
		("type_len", "H", 65030),  # type(127), length(6)
		("oui_subtype", "I", 8438283),  # OUI(00-80-C2), subtype(0x11)
		("w_mbc_pfc", "B", 0),  # Field contains Willing-1bit, MBC-1bit, Reserved-2bit,  PFC cap TCs-4bit
		("pfcenable", "B", 0),
	)

	tlv_type = get_property_tlv_type()
	tlv_len = get_property_tlv_len()
	oui = get_property_tlv_oui()
	subtype = get_property_tlv_subtype()
	pfcenable_list = get_property_to_convert_1_byte_to_list("pfcenable")

	def __get_w(self):
		return (self.w_mbc_pfc & 0x80) >> 7

	def __set_w(self, value):
		self.w_mbc_pfc = (self.w_mbc_pfc & ~0x80) | (value << 7)
	willing = property(__get_w, __set_w)

	def __get_mbc(self):
		return (self.w_mbc_pfc & 0x40) >> 6

	def __set_mbc(self, value):
		self.w_mbc_pfc = (self.w_mbc_pfc & ~0x40) | (value << 6)
	mbc = property(__get_mbc, __set_mbc)

	def __get_pfccap(self):
		return self.w_mbc_pfc & 0x0F

	def __set_pfccap(self, value):
		self.w_mbc_pfc = self.w_mbc_pfc & 0xF0 | value
	pfccap = property(__get_pfccap, __set_pfccap)


class DCBXApplicationPriority(pypacker.Packet):
	__hdr__ = (
		("type_len", "H", 65024, FIELD_FLAG_AUTOUPDATE),  # type(127)
		("oui_subtype", "I", 8438284),  # OUI(00-80-C2), subtype(0x12)
		("reserved", "B", 0),
		("apppriotable", None, triggerlist.TriggerList),
	)

	tlv_type = get_property_tlv_type()
	tlv_len = get_property_tlv_len()
	oui = get_property_tlv_oui()
	subtype = get_property_tlv_subtype()

	def _dissect(self, buf):
		# start from TLV_HEADER_LEN + ORG_SPEC_HEADER_LEN + 1 byte(reserved)
		for i in range(7, len(buf), 3):
			self.apppriotable.append(DCBXApplicationPriorityTable(buf[i:i + 3]))
		return len(self)

	def bin(self, update_auto_fields=True):
		if update_auto_fields and self._changed() and self.type_len_au_active:
			self.tlv_len = len(self) - TLV_HEADER_LEN
		return pypacker.Packet.bin(self, update_auto_fields=update_auto_fields)


class DCBXApplicationPriorityTable(pypacker.Packet):
	__hdr__ = (
		("priority_sel", "B", 0),  # Field contains Priority-3bits, Reserved-2bits,  Sel-3bits)
		("protocolid", "H", 0),
	)

	def __get_prio(self):
		return (self.priority_sel & 0xE0) >> 5

	def __set_prio(self, value):
		self.priority_sel = (self.priority_sel & ~0xE0) | (value << 5)
	priority = property(__get_prio, __set_prio)

	def __get_sel(self):
		return self.priority_sel & 0x07

	def __set_sel(self, value):
		self.priority_sel = (self.priority_sel & 0xF8) | value
	sel = property(__get_sel, __set_sel)


LLDP_TLV_CLS = {
	0: LLDPDUEnd,
	1: LLDPChassisId,
	2: LLDPPortId,
	3: LLDPTTL,
	4: LLDPPortDescription,
	5: LLDPSystemName,
	6: LLDPSystemDescription,
	7: LLDPSystemCapabilities,
	8: LLDPManagementAddress
}

LLDP_ORG_SPEC_TLV_CLS = {
	(0x0080c2, 0x01): LLDPDot1PortVlanId,
	(0x0080c2, 0x08): DCBXCongestionNotification,
	(0x0080c2, 0x09): DCBXConfiguration,
	(0x0080c2, 0x0a): DCBXRecommendation,
	(0x0080c2, 0x0b): DCBXPriorityBasedFlowControlConfiguration,
	(0x0080c2, 0x0c): DCBXApplicationPriority,
}


def count_and_dissect_tlvs(buf):
	"""
	Count and dissect TLVs. Return length of LLDP layer

	buf -- buffer to dissect
	return -- parsed_bytes_total, [(clz, bts), ...]
	"""
	shift = 0
	tlv_type, tlv_len = 1, 1
	clz_bts_list = []

	while (tlv_type | tlv_len) != 0:
		type_and_len = unpack_H(buf[shift:shift + TLV_HEADER_LEN])[0]
		# get tlv length and type
		tlv_type = (type_and_len & TYPE_MASK) >> LENGTH_FIELD_BITS
		tlv_len = type_and_len & LENGTH_MASK

		if tlv_type != ORG_SPEC_TYPE:
			clz = LLDP_TLV_CLS.get(tlv_type, LLDPGeneric)
		else:
			oui_subtype = unpack_I(buf[shift + TLV_HEADER_LEN:shift + ORG_SPEC_HEADER_LEN + TLV_HEADER_LEN])[0]
			oui = (oui_subtype & OUI_MASK) >> SUBTYPE_LEN_BITS
			subtype = oui_subtype & SUBTYPE_MASK
			clz = LLDP_ORG_SPEC_TLV_CLS.get((oui, subtype), LLDPOrgSpecGeneric)
		# get body bytes
		tlv_body = buf[shift: tlv_len + shift + TLV_HEADER_LEN]
		# update shift to begin of next TLV (TLV_HEADER_LEN:2 + content:x)
		shift += TLV_HEADER_LEN + tlv_len
		clz_bts_list.append((clz, tlv_body))

	return shift, clz_bts_list
