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
		("ulen", "H", 8),	# _ulen = ulen
		("_sum", "H", 0)	# _sum = sum
		)

	def getsum(self):
		if self.__needs_checksum_update():
			self.__calc_sum()
		return self._sum
	def setsum(self, value):
		self._sum = value
	sum = property(getsum, setsum)
	def getulen(self):
		if self._changed():
			self._ulen = struct.pack(">H", len(self))
		return self._ulen
	def setulen(self, value):
		self._ulen = value
	ulen = property(getulen, setulen)

	def _unpack(self, buf):
		ports = [ struct.unpack(">H", buf[0:2])[0], struct.unpack(">H", buf[2:4])[0] ]

		try:
			# source or destination port should match
			type = [ x for x in ports if x in pypacker.Packet._handler[UDP.__name__]][0]
			#logger.debug("UDP: trying to set handler, type: %d = %s" % (type, Packet._handler[UDP.__name__][type]))
			#logger.debug("UDP: trying to set handler, type: %d = %s" % (type, self._handler))
			type_instance = pypacker.Packet._handler[UDP.__name__][type](buf[self.__hdr_len__:])
			self._set_bodyhandler(type_instance)
		# any exception will lead to: body = raw bytes
		except Exception as ex:
			logger.debug(">>> UDP: couldn't set handler: %d -> %s" % (type, ex))
			pass

		pypacker.Packet._unpack(self, buf)

	def bin(self):
		if self._changed():
			self.ulen = struct.pack(">H", len(self))[0]
		if self.__needs_checksum_update():
			self.__calc_sum()
		return pypacker.Packet.bin(self)

	def __calc_sum(self):
		"""Recalculate the UDP-checksum."""
		# we need src/dst for checksum-calculation
		if self.callback is None:
			return

		# mark as achanged
		#object.__setattr__(self, "sum", 0)
		self.sum = 0
		udp_bin = self.pack_hdr() + self.data
		src, dst, changed = self.callback("ip_src_dst_changed")

		logger.debug("UDP sum recalc: %s/%s/%s" % (src, dst, changed))

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

		# Get the checksum of concatenated pseudoheader+TCP packet
		# fix: ip and tcp checksum together https://code.google.com/p/pypacker/issues/detail?id=54
		sum = pypacker.in_cksum(s + udp_bin)
		if sum == 0:
			sum = 0xffff    # RFC 768, p2

		logger.debug("new tcp sum: %d" % sum)
		object.__setattr__(self, "_sum", sum)

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
		"""UDP-checkusm needs to be updated if this layer itself or any
		upper layer changed. Changes to the IP-pseudoheader lead to update
		of TCP-checksum."""
		if self.callback is None:
			return False
		# changes to IP-layer
		a, b, changed = self.callback("ip_src_dst_changed")
		if changed:
			return True
		# check upper layers
		return self._changed()

UDP_PROTO_TELNET= 23
UDP_PROTO_DNS	= 53
UDP_PROTO_DHCP	= [67, 68]
UDP_PROTO_TFTP	= 69
UDP_PROTO_NTP	= 123
UDP_PROTO_RTP	= [5004, 5005]
UDP_PROTO_SIP	= [5060, 5061]

pypacker.Packet.load_handler(globals(), UDP, "UDP_PROTO_", ["layer567"])
