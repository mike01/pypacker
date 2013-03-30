"""Address Resolution Protocol."""

from .. import pypacker
# Hardware address format
ARP_HRD_ETH	= 0x0001	# ethernet hardware
ARP_HRD_IEEE802	= 0x0006	# IEEE 802 hardware

# Protocol address format
ARP_PRO_IP	= 0x0800	# IP protocol

# ARP operation
ARP_OP_REQUEST		= 1	# request to resolve ha given pa
ARP_OP_REPLY		= 2	# response giving hardware address
ARP_OP_REVREQUEST	= 3	# request to resolve pa given ha
ARP_OP_REVREPLY		= 4	# response giving protocol address

class ARP(pypacker.Packet):
	__hdr__ = (
		("hrd", "H", ARP_HRD_ETH),
		("pro", "H", ARP_PRO_IP),
		("hln", "B", 6),	# hardware address length
		("pln", "B", 4),	# protocol address length
		("op", "H", ARP_OP_REQUEST),
		("sha", "6s", b""),	# sender mac
		("spa", "4s", b""),	# sender ip
		("tha", "6s", b""),	# target mac
		("tpa", "4s", b"")	# target ip
		)

	## convenient access
	def __get_sha_s(self):
		return pypacker.mac_bytes_to_str(self.sha)
	def __set_sha_s(self, value):
		self.sha = pypacker.mac_str_to_bytes(value)
	sha_s = property(__get_sha_s, __set_sha_s)
	def __get_spa_s(self):
		return pypacker.ip4_bytes_to_str(self.spa)
	def __set_spa_s(self, value):
		self.spa = pypacker.ip4_str_to_bytes(value)
	spa_s = property(__get_spa_s, __set_spa_s)
	def __get_tha_s(self):
		return pypacker.mac_bytes_to_str(tha)
	def __set_tha_s(self, value):
		self.tha = pypacker.mac_str_to_bytes(value)
	tha_s = property(__get_tha_s, __set_tha_s)
	def __get_tpa_s(self):
		return pypacker.ip4_bytes_to_str(self.tpa)
	def __set_tpa_s(self, value):
		self.tpa = pypacker.ip4_str_to_bytes(value)
	tpa_s = property(__get_tpa_s, __set_tpa_s)

