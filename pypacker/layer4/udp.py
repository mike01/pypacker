"""User Datagram Protocol."""

from .. import pypacker
import struct
import logging
logger = logging.getLogger("pypacker")

UDP_PORT_MAX	= 65535

class UDP(pypacker.Packet):
	__hdr__ = (
		("sport", "H", 0xdead),
		("dport", "H", 0),
		("_ulen", "H", 8),	# _ulen = ulen
		("_sum", "H", 0)	# _sum = sum
		)

	def __get_sum(self):
		if self.__needs_checksum_update():
			self.__calc_sum()
		return self._sum
	def __set_sum(self, value):
		self._sum = value
		self._sum_ud = True
	sum = property(__get_sum, __set_sum)

	def __get_ulen(self):
		if self.body_changed:
			self._ulen = struct.pack(">H", len(self))
		return self._ulen
	def __set_ulen(self, value):
		self._ulen = value
	ulen = property(__get_ulen, __set_ulen)

	def _dissect(self, buf):
		ports = [ struct.unpack(">H", buf[0:2])[0], struct.unpack(">H", buf[2:4])[0] ]

		try:
			# source or destination port should match
			type = [ x for x in ports if x in pypacker.Packet._handler[UDP.__name__]][0]
			self._parse_handler(type, buf, self.__hdr_len__)
		# no type found
		except:
			pass

	def bin(self):
		if self.body_changed:
			self._ulen = len(self)
			#logger.debug("UDP: updated length: %s" % self._ulen)

		if self.__needs_checksum_update():
			self.__calc_sum()
		return pypacker.Packet.bin(self)

	def __calc_sum(self):
		"""Recalculate the UDP-checksum."""
		# mark as achanged
		self._sum = 0
		udp_bin = self.pack_hdr() + self.data
		src, dst, changed = self._callback("ip_src_dst_changed")

		#logger.debug("UDP sum recalc: %s/%s/%s" % (src, dst, changed))

                # IP-pseudoheader, check if version 4 or 6
		if len(src) == 4:
			s = struct.pack(">4s4sxBH",
				src,
				dst,
				17,		# UDP
				len(udp_bin))
		else:
			s = struct.pack(">16s16sxBH",
				src,
				dst,
				17,		# UDP
				len(udp_bin))

		sum = pypacker.in_cksum(s + udp_bin)
		if sum == 0:
			sum = 0xffff    # RFC 768, p2

		# get the checksum of concatenated pseudoheader+TCP packet
		self._sum = sum

	def direction(self, next, last_packet=None):
		#logger.debug("checking direction: %s<->%s" % (self, next))
		try:
			if self.sport == next.sport and self.dport == next.dport:
				direction = pypacker.Packet.DIR_SAME
			elif self.sport == next.dport and self.dport == next.sport:
				direction = pypacker.Packet.DIR_REV
			else:
				direction = pypacker.Packet.DIR_BOTH
		except:
			return pypacker.Packet.DIR_NONE
                # delegate to super implementation for further checks
		return direction | pypacker.Packet.direction(self, next, last_packet)

	def __needs_checksum_update(self):
		"""
		UDP-checksum needs to be updated on one of the following:
		- this layer itself or any upper layer changed
		- changes to the IP-pseudoheader
		There is no update on user-set checksums.
		"""
		# don't change user defined sum, LBYL: this is unlikely
		if hasattr(self, "_sum_ud"):
			return False

		try:
			# changes to IP-layer
			a, b, changed = self._callback("ip_src_dst_changed")
			if changed:
				# change to IP-pseudoheader
				return True
		except TypeError:
			#logger.debug("no callback found for checksum")
			# no callback to IP: we can't calculate the checksum
			return False

		#logger.debug("UDP: update needed: %s" % self._changed())
		# pseudoheader didn't change, further check for changes in layers
		return self._changed()

UDP_PROTO_TELNET= 23
UDP_PROTO_DNS	= 53
UDP_PROTO_DHCP	= (67, 68)
UDP_PROTO_TFTP	= 69
UDP_PROTO_NTP	= 123
UDP_PROTO_RTP	= (5004, 5005)
UDP_PROTO_SIP	= (5060, 5061)

# load handler
from pypacker.layer567 import telnet, dns, dhcp, tftp, ntp, rtp, sip

pypacker.Packet.load_handler(UDP,
				{
				UDP_PROTO_TELNET : telnet.Telnet,
				UDP_PROTO_DNS : dns.DNS,
				UDP_PROTO_DHCP : dhcp.DHCP,
				UDP_PROTO_TFTP : tftp.TFTP,
				UDP_PROTO_NTP : ntp.NTP,
				UDP_PROTO_RTP : rtp.RTP,
				UDP_PROTO_SIP : sip.SIP
                                }
                                )
