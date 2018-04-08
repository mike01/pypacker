"""
Example definition of a new protocol called "NewProtocol" (RFC -1).
New modules are placed into to appropriate layerXYZ-directory.
Last but not least: every protocol needs a testcase in tests/test_pypacker.py
"""
import logging

from pypacker import pypacker, triggerlist
from pypacker.pypacker_meta import FIELD_FLAG_AUTOUPDATE, FIELD_FLAG_IS_TYPEFIELD
from pypacker.layer3 import ip
from pypacker.layer4 import tcp
from pypacker.structcbs import *

logger = logging.getLogger("pypacker")

TYPE_VALUE_IP = 0x66


class Option(pypacker.Packet):
	"""Packet used for options field. See NewProtocol below."""
	__hdr__ = (
		("some_value", "B", 0x00),
	)


class NewProtocol(pypacker.Packet):
	"""
	New protocols are subclassing Packet class and represent a layer in a multi-layer
	network Packet like 'NewProtocol | IP | TCP ...'.
	The whole structure is oriented	at the ISO/OSI protocol layers where
	every layer contains a reference to the next upper layer. As an example this layer
	'NewProtocol', when parsing from raw bytes, will have a reference to the next upper
	layer 'IP' which can be access via '.' like 'newprotoinstance.ip' (access name is the
	lower case name of the class). Even higher layers can be accessed via
	'newprot# oinstance.ip.tcp' (when available) or via the '[]' notation like 'newprotoinstance[TCP]'."""

	# The protocol header is basically defined by the static field
	# "__hdr__" (see layer12/ethernet.Ethernet). See code documentation
	# for classes "MetaPacket" and "Packet" in pypacker/pypacker.py for
	# deeper information.
	__hdr__ = (
		# Simple constant fields: fixed format, not changing length
		# marked as type field: defines type of next upper layer, here: IP. See __handler__
		("type", "B", TYPE_VALUE_IP, FIELD_FLAG_IS_TYPEFIELD),
		("src", "4s", b"\xff" * 4),
		("dst", "4s", b"\xff" * 4),
		# Simple constant field, marked for auto update, see _update_fields(...).
		#  Stores the full header length inclusive options.
		("hlen", "H", 14, FIELD_FLAG_AUTOUPDATE),
		# Simple constant field, deactivated (see Ethernet -> vlan)
		# Switching between active/inactive should be avoided because of performance penalty :/
		("idk", "H", None),
		# Again a simple constant field
		("flags", "B", 0),
		# Dynamic field: bytestring format, *can* change in length, see dns.DNS
		# Field type should be avoided because of performance penalty :/
		("yolo", None, b"1234"),
		# TriggerList field: variable length, can contain: raw bytes, key/value-tuples (see HTTP) and Packets (see IP)
		# Here TriggerList will contain key/value Tuples like (b"\x00", b"1")
		("options", None, triggerlist.TriggerList)
	)

	# Conveniant access should be enabled using properties eg using pypacker.get_property_xxx(...)
	src_s = pypacker.get_property_ip4("src")
	dst_s = pypacker.get_property_ip4("dst")
	# xxx_s = pypacker.get_property_mac("xxx")
	# xxx_s = pypacker.get_property_dnsname("xxx")

	# Setting/getting values smaller then 1 Byte should be enabled using properties (see layer3/ip.IP -> v, hl)
	def __get_flag_fluxcapacitor(self):
		return (self.flags & 0x80) >> 15

	def __set_flag_fluxcapacitor(self, value):
		value_shift = (value & 1) << 15
		self.flags = (self.flags & ~0x80) | value_shift

	flag_fluxcapacitor = property(__get_flag_fluxcapacitor, __set_flag_fluxcapacitor)

	@staticmethod
	def _parse_options(buf):
		"""
		Callback to parse contents for TriggerList-field options,
		see _dissec(...) -> _init_triggerlist(...).
		return -- [Option(), ...]
		"""
		ret = []
		off = 0

		while off < len(buf):
			ret.append(Option(buf[off: off + 2]))
			off += 2
		return ret

	def _dissect(self, buf):
		"""
		_dissect(...) must be overwritten if the header format can change
		from its original format. This is generally the case when
		- using TriggerLists (see ip.IP)
		- simple fields can get deactivated (see ethernet.Ethernet)
		- using dynamic fields (see dns.DNS)

		In NewProtocol idk can get deactivated, options is a TriggerList
		and yolo is a dynamic field so _dissect(...) needs to be defined.
		"""
		# Header fields are not yet accessible in _dissect(...) so basic information
		# (type info, header length, bytes of dynamic content etc) has to be parsed manually.
		upper_layer_type = buf[0]  # extract type information of next layer, here it can only be 0x66 but we extract it anyway
		# logger.debug("Found type: 0x%X" % upper_layer_type)
		total_header_length = unpack_H(buf[9: 11])[0]
		yolo_len = 4 if upper_layer_type == TYPE_VALUE_IP else 5  # length of yolo is derived from type
		# logger.debug("Found length: %d, yolo=%d" % (total_header_length, yolo_len))
		tl_bts = buf[12 + yolo_len: total_header_length]  # options are the the end of the header
		# logger.debug("Bytes for TriggerList: %r" % tl_bts)
		# self._init_triggerlist(...) should be called to initiate TriggerLists,
		# otherwise the list will be empty. _parse_options(...) is a callback returning a list
		# of [raw bytes | key/value tuples | Packets] parsed from tl_bts.
		self._init_triggerlist("options", tl_bts, NewProtocol._parse_options)

		# self._init_handler(...) must be called to initiate the handler of the next
		# upper layer and makes it accessible (eg "ip" in "ethernet" via "ethernet.ip" or ethernet[ip.IP]).
		# Which handler to be initialized generally depends on the type information (here upper_layer_type)
		# found in the current layer (see layer12/ethernet.Ethernet -> type).
		# Here upper_layer_type can become the value 0x66 (defined by __handler__ field) and
		# as a result ip.IP will be created as upper layer using the bytes given by "buf[total_header_length:]".
		self._init_handler(upper_layer_type, buf[total_header_length:])
		return total_header_length

	# Handler can be registered by defining the static dictionary
	# __handler__ where the key is extracted from raw bytes in _dissect(...) and
	# given to _init_handler(...) and the value is the Packet class used to
	# create the next upper layer (here ip.IP). Add the "FIELD_FLAG_IS_TYPEFIELD"
	# to the corresponding type field in __hdr__.
	__handler__ = {TYPE_VALUE_IP: ip.IP}  # just 1 possible upper layer

	def _update_fields(self):
		"""
		_update_fields(...) should be overwritten to update fields which depend on the state
		of the packet like lengths, checksums etc (see layer3/ip.IP -> len, sum)
		aka auto-update fields.	The variable XXX_au_active indicates
		if the field XXX should be updated (True) or not
		(see layer3/ip.IP.bin() -> len_au_active). XXX_au_active is
		available if the field has the flag "FIELD_FLAG_AUTOUPDATE" in __hdr__,
		default value is True. _update_fields(...) is implicitly called by bin(...).
		"""
		if self._changed() and self.hlen_au_active:
			self.hlen = self.header_len

	def bin(self, update_auto_fields=True):
		"""
		bin(...)  should only be overwritten to allow more complex assemblation eg adding padding
		at the end of all layers instead of the current layer (see ethernet.Ethernet -> padding).
		The variable update_auto_fields indicates if fields should be updated in general.
		"""
		return pypacker.Packet.bin(self, update_auto_fields=update_auto_fields) + b"somepadding"

	def direction(self, other):
		"""
		direction(...) should be overwritten to be able to check directions to an other packet
		(see layer12/ethernet.Ethernet)
		"""
		direction = 0

		if self.src == other.src and self.dst == other.dst:
			direction |= pypacker.Packet.DIR_SAME
		if self.src == other.dst and self.dst == other.src:
			direction |= pypacker.Packet.DIR_REV

		if direction == 0:
			direction = pypacker.Packet.DIR_UNKNOWN
		return direction

	def reverse_address(self):
		"""
		reverse_a# ddress(...) should be overwritten to be able to reverse
		source/destination addresses (see ethernet.Ethernet)
		"""
		self.src, self.dst = self.dst, self.src


# Parse from raw bytes
# First layer (Layer 2)
newproto_bytes = b"\x66" + b"AAAA" + b"BBBB" + b"\x00\x16" + b"\x00" + b"1234" + b"\x00A\x01B\x02C"
# Next upper layer (Layer 3)
ip_bytes = ip.IP().bin()
# Layer above upper layer (Layer 4)
tcp_bytes = tcp.TCP().bin()
newproto_pkt = NewProtocol(newproto_bytes + ip_bytes + tcp_bytes)

print()
print(">>> Layers of packet:")
print("Output all layers: %s" % newproto_pkt)
print("Access some fields: 0x%X %s %s" % (newproto_pkt.type, newproto_pkt.src, newproto_pkt.dst))
print("Access next upper layer (IP): %s" % newproto_pkt.ip)
print("A layer above IP: %s" % newproto_pkt.ip.tcp)
print("Same as above: %s" % newproto_pkt[tcp.TCP])


# Create new Packet by defining every single header and adding higher layers
newproto_pkt = NewProtocol(
	type=0x66, src=b"AAAA", dst=b"BBBB", hlen=0x11, yolo=b"1234", options=[b"\x00A\x01B\x02C"]) +\
	ip.IP() +\
	tcp.TCP()

print()
print(">>> Layers of packet:")
print("Output all layers: %s" % newproto_pkt)
print("Access some fields: 0x%X %s %s" % (newproto_pkt.type, newproto_pkt.src, newproto_pkt.dst))
print("Access next upper layer (IP): %s" % newproto_pkt.ip)
print("A layer above IP: %s" % newproto_pkt.ip.tcp)
print("Same as above: %s" % newproto_pkt[tcp.TCP])
