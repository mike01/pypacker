"""
User Datagram Protocol (UDP)

RFC 768 - User Datagram Protocol
RFC 2460 - Internet Protocol, Version 6 (IPv6) Specification
RFC 2675 - IPv6 Jumbograms
RFC 4113 - Management Information Base for the UDP
RFC 5405 - Unicast UDP Usage Guidelines for Application Designers
"""
import struct
import logging

from pypacker import pypacker, checksum
from pypacker.pypacker import FIELD_FLAG_AUTOUPDATE
# handler
from pypacker.layer567 import telnet, tftp, dns, dhcp, ntp, rtp, sip, pmap, radius, stun

# avoid references for performance reasons
unpack_H = struct.Struct(">H").unpack
pack_ipv4 = struct.Struct(">4s4sxBH").pack
pack_ipv6 = struct.Struct(">16s16sxBH").pack

logger = logging.getLogger("pypacker")

UDP_PORT_MAX	= 65535


UDP_PROTO_TELNET	= 23
UDP_PROTO_DNS		= (53, 5353)
UDP_PROTO_DHCP		= (67, 68)
UDP_PROTO_TFTP		= 69
UDP_PROTO_PMAP		= 111
UDP_PROTO_NTP		= 123
UDP_PROTO_RADIUS	= (1812, 1813, 1645, 1646)
UDP_PROTO_STUN		= 3478
UDP_PROTO_RTP		= (5004, 5005)
UDP_PROTO_SIP		= (5060, 5061)


class UDP(pypacker.Packet):
	__hdr__ = (
		("sport", "H", 0xdead),
		("dport", "H", 0),
		("ulen", "H", 8, FIELD_FLAG_AUTOUPDATE),
		("sum", "H", 0, FIELD_FLAG_AUTOUPDATE)
	)

	__handler__ = {
		UDP_PROTO_TELNET: telnet.Telnet,
		UDP_PROTO_TFTP: tftp.TFTP,
		UDP_PROTO_DNS: dns.DNS,
		UDP_PROTO_DHCP: dhcp.DHCP,
		UDP_PROTO_PMAP: pmap.Pmap,
		UDP_PROTO_NTP: ntp.NTP,
		UDP_PROTO_RADIUS: radius.Radius,
		UDP_PROTO_RTP: rtp.RTP,
		UDP_PROTO_SIP: sip.SIP,
		UDP_PROTO_STUN: stun.STUN
	}

	def bin(self, update_auto_fields=True):
		if update_auto_fields:
			"""
			UDP-checksum needs to be updated on one of the following:
			- this layer itself or any upper layer changed
			- changes to the IP-pseudoheader
			There is no update on user-set checksums.
			"""
			changed = self._changed()
			update = True

			if changed and self.ulen_au_active:
				self.ulen = len(self)

			try:
				# changes to IP-layer, don't mind if this isn't IP
				if not self._lower_layer._header_changed:
					# lower layer doesn't need update, check for changes in present and upper layer
					# logger.debug("lower layer did NOT change!")
					update = changed
			except AttributeError:
				# assume not an IP packet: we can't calculate the checksum
				update = False

			if update and self.sum_au_active:
				self._calc_sum()

		return pypacker.Packet.bin(self, update_auto_fields=update_auto_fields)

	def _dissect(self, buf):
		ports = [unpack_H(buf[0:2])[0], unpack_H(buf[2:4])[0]]

		try:
			# source or destination port should match
			htype = [x for x in ports if x in pypacker.Packet._id_handlerclass_dct[UDP]][0]
			self._init_handler(htype, buf[8:])
		except:
			# no type found
			# logger.debug("could not parse type: %d because: %s" % (type, e))
			pass
		return 8

	def _calc_sum(self):
		"""Recalculate the UDP-checksum."""
		# TCP and underwriting are freaky bitches: we need the IP pseudoheader to calculate their checksum
		# logger.debug("UDP sum recalc: %s/%s/%s" % (src, dst, changed))
		try:
			# we need src/dst for checksum-calculation
			src, dst = self._lower_layer.src, self._lower_layer.dst
			# logger.debug(src + b" / "+ dst)
			self.sum = 0
			udp_bin = self.header_bytes + self.body_bytes

			# IP-pseudoheader, check if version 4 or 6
			if len(src) == 4:
				s = pack_ipv4(src, dst, 17, len(udp_bin))  # 17 = UDP
			else:
				s = pack_ipv6(src, dst, 17, len(udp_bin))  # 17 = UDP

			csum = checksum.in_cksum(s + udp_bin)

			if csum == 0:
				csum = 0xffff    # RFC 768, p2

			# get the checksum of concatenated pseudoheader+TCP packet
			# assign via non-shadowed variable to trigger re-packing
			self.sum = csum
		except (AttributeError, struct.error):
			# not an IP packet as lower layer (src, dst not present) or invalid src/dst
			pass

	def direction(self, other):
		# logger.debug("checking direction: %s<->%s" % (self, other))
		if self.sport == other.sport and self.dport == other.dport:
			# consider packet to itself: can be DIR_REV
			return pypacker.Packet.DIR_SAME | pypacker.Packet.DIR_REV
		elif self.sport == other.dport and self.dport == other.sport:
			return pypacker.Packet.DIR_REV
		else:
			return pypacker.Packet.DIR_UNKNOWN

	def reverse_address(self):
		self.sport, self.dport = self.dport, self.sport
