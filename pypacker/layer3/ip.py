"""Internet Protocol version 4."""

from .. import pypacker
from .ip_shared import *

import copy
import logging
import re
import struct

logger = logging.getLogger("pypacker")

class IP(pypacker.Packet):
	"""Convenient access for: src[_s], dst[_s]"""
	__hdr__ = (
		("v_hl", "B", (4 << 4) | (20 >> 2)),
		("tos", "B", 0),
		("_len", "H", 20),		# _len = len
		("id", "H", 0),
		("off", "H", 0),
		("ttl", "B", 64),
		("p", "B", 0),
		("_sum", "H", 0),		# _sum = sum
		("src", "4s", b"\x00" * 4),
		("dst", "4s", b"\x00" * 4)
						# _opts = opts
		)

	def getv(self):
		return self.v_hl >> 4
	def setv(self, value):
		self.v_hl = (value << 4) | (self.v_hl & 0xf)
	v = property(getv, setv)
	def gethl(self):
		return self.v_hl & 0xf
	def sethl(self, value):
		self.v_hl = (self.v_hl & 0xf0) | value
	hl = property(gethl, sethl)
	## update length on changes
	def getlen(self):
		if self._changed():
	 		self._len = len(self)
		return self._len
	def setlen(self, value):
		self._len = value
	len = property(getlen, setlen)
	def getsum(self):
		if self.header_changed:
		# change to header = we need a checksum update
		#if self._header_cached is None:
			self.__calc_sum()
		return self._sum
	def setsum(self, value):
		self._sum = value
	sum = property(getsum, setsum)
	## convenient access
	def getsrc_s(self):
		return "%d.%d.%d.%d" % struct.unpack("BBBB", self.src)
	def setsrc_s(self, value):
		ips = [ int(x) for x in value.split(".")]
		value = struct.pack("BBBB", ips[0], ips[1], ips[2], ips[3])
		self.src = value
	src_s = property(getsrc_s, setsrc_s)
	def getdst_s(self):
		return "%d.%d.%d.%d" % struct.unpack("BBBB", self.dst)
	def setdst_s(self, value):
		ips = [ int(x) for x in value.split(".")]
		value = struct.pack("BBBB", ips[0], ips[1], ips[2], ips[3])
		self.dst = value
	dst_s = property(getdst_s, setdst_s)
	## lazy init of dynamic header
	def getopts(self):
		if not hasattr(self, "_opts"):
			tl = IPTriggerList()
			self._add_headerfield("_opts", "", tl)
		return self._opts
	#def setopts(self, value):
	#	self._opts = value
	#opts = property(getopts, setopts)
	opts = property(getopts)

	def _unpack(self, buf):
		ol = ((buf[0] & 0xf) << 2) - 20	# total IHL - standard IP-len = options length
		if ol < 0:
			raise UnpackError("IP: invalid header length: %d" % ol)
		elif ol > 0:
			opts = buf[20 : 20 + ol]
			# IP opts: make them accessible via ip.options using Packets
			tl_opts = self.__parse_opts(opts)
			#logger.debug("got some IP options: %s" % tl_opts)
			#for o in tl_opts:
			#	logger.debug("%s, len: %d, data: %s" % (o, len(o), o.data))
			self._add_headerfield("_opts", "", tl_opts)

		# now we know the real header length
		buf_data = buf[self.__hdr_len__:]

		try:
			type = buf[9]
			# fix: https://code.google.com/p/pypacker/issues/attachmentText?id=75
			#if self.off & 0x1fff > 0:
			#	raise KeyError
			#logger.debug(">>> IP: trying to set handler, type: %d = %s" % (123, pypacker.Packet._handler[IP.__name__][type]))
			#logger.debug(">>> IP: trying to set handler, type: %d = %s" % (123, pypacker.Packet._handler[IP.__name__]))
			type_instance = self._handler[IP.__name__][type](buf_data)
			# set callback to calculate checksum
			type_instance.callback = self.callback_impl
			self._set_bodyhandler(type_instance)
		# any exception will lead to: body = raw bytes
		except Exception as ex:
			logger.debug(">>> IPv4: couldn't set handler: %d -> %s" % (type, ex))
			pass

		pypacker.Packet._unpack(self, buf)

	def __parse_opts(self, buf):
		"""Parse IP options and return them as TriggerList."""
		optlist = []
		i = 0
		p = None

		while i < len(buf):
			#logger.debug("got IP-option type %s" % buf[i])
			if buf[i] in [IP_OPT_EOOL, IP_OPT_NOP]:
				p = IPOptSingle(type=buf[i])
				i += 1
			else:
				olen = buf[i + 1]
				p = IPOptMulti(type=buf[i], len=olen, data=buf[ i+2 : i+olen ])
				i += olen	# typefield + lenfield + data-len
			optlist.append(p)

		return IPTriggerList(optlist)

	def bin(self):
		if self._changed():
			#logger.debug(">>> IP: updating length because of changes")
			if self.header_changed:
				self.__calc_sum()
			# update length on changes
			object.__setattr__(self, "_len", len(self))
			#self.len = len(self)
		# on changes this will return a fresh length
		return pypacker.Packet.bin(self)

	def __calc_sum(self):
		"""Recalculate checksum."""
		#logger.debug("calculating sum")
		# reset checksum for recalculation
		#logger.debug("header is: %s" % self.pack_hdr(cached=False))
		object.__setattr__(self, "_sum", 0)
		object.__setattr__(self, "_sum", pypacker.in_cksum(self.pack_hdr()) )

	def direction(self, next, last_packet=None):
		#logger.debug("checking direction: %s<->%s" % (self, next))

		if self.src == next.src and self.dst == next.dst:
			direction = pypacker.Packet.DIR_SAME
		elif self.src == next.dst and self.dst == next.src:
			direction = pypacker.Packet.DIR_REV
		else:
			direction = pypacker.Packet.DIR_BOTH
		# delegate to super implementation for further checks
		return direction | pypacker.Packet.direction(self, next, last_packet)

	def callback_impl(self, id):
		"""Callback to get data needed for checksum-computation. Used id: 'ip_src_dst_changed'"""
		# TCP and underwriting are freaky bitches: we need the IP pseudoheader to calculate
		# their checksum. A TCP (6) or UDP (17)layer uses a callback to IP get the needed information.
		if id == "ip_src_dst_changed":
			return self.src, self.dst, self.header_changed


class IPTriggerList(pypacker.TriggerList):
	def _handle_mod(self, val, add_listener=True):
		"""Update header length. NOTE: needs to be a multiple of 4 Bytes."""
		# packet should be already present after adding this TriggerList as field.
		# we need to update format prior to get the correct header length: this
		# should have already happened
		try:
			# TODO: options length need to be multiple of 4 Bytes, allow different lengths?
			hdr_len_off = int(self.packet.__hdr_len__ / 4) & 0xf
			self.packet.hl = hdr_len_off
		except Exception as e:
			logger.warning("IP: couldn't update header length: %s" % e)

		pypacker.TriggerList._handle_mod(self, val, add_listener=add_listener)

	def _tuples_to_packets(self, tuple_list):
		"""Convert [(IP_OPT_X, b""), ...] to [IPOptX_obj, ...]."""
		opt_packets = []

		# parse tuples to IP-option Packets
		for opt in tuple_list:
			p = None
			if opt[0] in [IP_OPT_EOOL, IP_OPT_NOP]:
				p = IPOptSingle(type=opt[0])
			else:
				p = IPOptMulti(type=opt[0], len=len(opt[1])+2, data=opt[1])
			opt_packets.append(p)
		return opt_packets


class IPOptSingle(pypacker.Packet):
	__hdr__ = (
		("type", "B", 0),
		)

class IPOptMulti(pypacker.Packet):
	__hdr__ = (
		("type", "B", 0),
		("len", "B", 0),
		)

# Type of service (ip_tos), RFC 1349 ("obsoleted by RFC 2474")
IP_TOS_DEFAULT			= 0x00	# default
IP_TOS_LOWDELAY			= 0x10	# low delay
IP_TOS_THROUGHPUT		= 0x08	# high throughput
IP_TOS_RELIABILITY		= 0x04	# high reliability
IP_TOS_LOWCOST			= 0x02	# low monetary cost - XXX
IP_TOS_ECT			= 0x02	# ECN-capable transport
IP_TOS_CE			= 0x01	# congestion experienced

# IP precedence (high 3 bits of ip_tos), hopefully unused
IP_TOS_PREC_ROUTINE		= 0x00
IP_TOS_PREC_PRIORITY		= 0x20
IP_TOS_PREC_IMMEDIATE		= 0x40
IP_TOS_PREC_FLASH		= 0x60
IP_TOS_PREC_FLASHOVERRIDE	= 0x80
IP_TOS_PREC_CRITIC_ECP		= 0xa0
IP_TOS_PREC_INTERNETCONTROL	= 0xc0
IP_TOS_PREC_NETCONTROL		= 0xe0

# Fragmentation flags (ip_off)
IP_RF				= 0x8000	# reserved
IP_DF				= 0x4000	# don't fragment
IP_MF				= 0x2000	# more fragments (not last frag)
IP_OFFMASK			= 0x1fff	# mask for fragment offset

# Time-to-live (ip_ttl), seconds
IP_TTL_DEFAULT			= 64		# default ttl, RFC 1122, RFC 1340
IP_TTL_MAX			= 255		# maximum ttl

# IP options
# http://www.iana.org/assignments/ip-parameters/ip-parameters.xml
IP_OPT_EOOL			= 0
IP_OPT_NOP			= 1
IP_OPT_SEC			= 2
IP_OPT_LSR			= 3
IP_OPT_TS			= 4
IP_OPT_ESEC			= 5
IP_OPT_CIPSO			= 6
IP_OPT_RR			= 7
IP_OPT_SID			= 8
IP_OPT_SSR			= 9
IP_OPT_ZSU			= 10
IP_OPT_MTUP			= 11
IP_OPT_MTUR			= 12
IP_OPT_FINN			= 13
IP_OPT_VISA			= 14
IP_OPT_ENCODE			= 15
IP_OPT_IMITD			= 16
IP_OPT_EIP			= 17
IP_OPT_TR			= 18
IP_OPT_ADDEXT			= 19
IP_OPT_RTRALT			= 20
IP_OPT_SDB			= 21
IP_OPT_UNASSGNIED		= 22
IP_OPT_DPS			= 23
IP_OPT_UMP			= 24
IP_OPT_QS			= 25
IP_OPT_EXP			= 30

pypacker.Packet.load_handler(globals(), IP, "IP_PROTO_", ["layer3", "layer4"])
