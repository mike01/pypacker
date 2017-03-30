"""
Link Aggregation Control Protocol
IEEE 802.3ad
"""
import struct

from pypacker import pypacker, triggerlist

# avoid unneeded references for performance reasons
unpack_BB = struct.Struct(">BB").unpack

# TLVs length in bytes
LACP_HEADER_LEN = 2
LACP_ACTOR_LEN = 20
LACP_PARTNER_LEN = 20
LACP_COLLECTOR_LEN = 16
LACP_TERMINATOR_LEN = 2
LACP_RESERVED_LEN = 50
# TLV types
ACTOR_TYPE = 1
PARTNER_TYPE = 2
COLLECTOR_TYPE = 3
TERMINATOR_TYPE = 0
DEFAULT_PRIORITY = 0x8000

# Bit encoding of the Actor_State and Partner_State fields
STATE_FIELD_BIT_ORDERING = {
	"expired": (0x80, 7),
	"defaulted": (0x40, 6),
	"distribute": (0x20, 5),
	"collect": (0x10, 4),
	"synch": (0x08, 3),
	"aggregate": (0x04, 2),
	"timeout": (0x02, 1),
	"activity": (0x01, 0),
}


def get_property_of_state_field(varname):
	"""Create a get/set-property for bits encoding of state field in Actor and Partner TLVs."""
	mask = STATE_FIELD_BIT_ORDERING.get(varname)[0]
	bit_order = STATE_FIELD_BIT_ORDERING.get(varname)[1]
	return property(
		lambda obj: (obj.state & mask) >> bit_order,
		lambda obj, val: obj.__setattr__("state",
			(obj.state & ~mask) | (val << bit_order)),
	)


class LACP(pypacker.Packet):
	__hdr__ = (
		("subtype", "B", 1),
		("version", "B", 1),
		("tlvlist", None, triggerlist.TriggerList),
	)

	def _dissect(self, buf):
		self._init_triggerlist("tlvlist", buf[LACP_HEADER_LEN:], self.__parse_tlv)
		return len(buf)

	@staticmethod
	def __parse_tlv(buf):
		"""Parse LACP TLVs and return them as list."""
		tlvlist = []
		shift = 0
		tlv_type, tlv_len = 1, 1
		while (tlv_type | tlv_len) != 0:
			tlv_type, tlv_len = unpack_BB(buf[shift:shift + 2])
			clz = LACP_TLV_CLS.get(tlv_type)
			if not clz == LACP_TLV_CLS.get(0):
				tlv_body = buf[shift: tlv_len + shift]
				shift += tlv_len
			else:
				tlv_body = buf[shift: LACP_TERMINATOR_LEN + shift]
				shift += LACP_TERMINATOR_LEN
			tlvlist.append(clz(tlv_body))
		tlvlist.append(LACPReserved(buf[shift: shift + LACP_RESERVED_LEN]))
		return tlvlist


class LACPActorInfoTlv(pypacker.Packet):
	__hdr__ = (
		("type", "B", ACTOR_TYPE),
		("len", "B", LACP_ACTOR_LEN),
		("sysprio", "H", DEFAULT_PRIORITY),
		("sys", "6s", b"\x00" * 6),
		("key", "H", 0),
		("portprio", "H", DEFAULT_PRIORITY),
		("port", "H", 1),
		("state", "B", 0),
		("reserved", "3s", b"\x00" * 3),
	)

	sys_s = pypacker.get_property_mac("sys")
	expired = get_property_of_state_field("expired")
	defaulted = get_property_of_state_field("defaulted")
	distribute = get_property_of_state_field("distribute")
	collect = get_property_of_state_field("collect")
	synch = get_property_of_state_field("synch")
	aggregate = get_property_of_state_field("aggregate")
	timeout = get_property_of_state_field("timeout")
	activity = get_property_of_state_field("activity")


class LACPPartnerInfoTlv(pypacker.Packet):
	__hdr__ = (
		("type", "B", PARTNER_TYPE),
		("len", "B", LACP_PARTNER_LEN),
		("sysprio", "H", DEFAULT_PRIORITY),
		("sys", "6s", b"\x00" * 6),
		("key", "H", 0),
		("portprio", "H", DEFAULT_PRIORITY),
		("port", "H", 1),
		("state", "B", 0),
		("reserved", "3s", b"\x00" * 3),
	)

	sys_s = pypacker.get_property_mac("sys")
	expired = get_property_of_state_field("expired")
	defaulted = get_property_of_state_field("defaulted")
	distribute = get_property_of_state_field("distribute")
	collect = get_property_of_state_field("collect")
	synch = get_property_of_state_field("synch")
	aggregate = get_property_of_state_field("aggregate")
	timeout = get_property_of_state_field("timeout")
	activity = get_property_of_state_field("activity")


class LACPCollectorInfoTlv(pypacker.Packet):
	__hdr__ = (
		("type", "B", COLLECTOR_TYPE),
		("len", "B", LACP_COLLECTOR_LEN),
		("maxdelay", "H", 10),
		("reserved", "12s", b"\x00" * 12),
	)


class LACPTerminatorTlv(pypacker.Packet):
	__hdr__ = (
		("type", "B", TERMINATOR_TYPE),
		("len", "B", 0),
	)


class LACPReserved(pypacker.Packet):
	__hdr__ = (
		("reserved", "50s", b"\x00" * 50),
	)


LACP_TLV_CLS = {
	ACTOR_TYPE: LACPActorInfoTlv,
	PARTNER_TYPE: LACPPartnerInfoTlv,
	COLLECTOR_TYPE: LACPCollectorInfoTlv,
	TERMINATOR_TYPE: LACPTerminatorTlv,
}
