# $Id: netflow.py 23 2006-11-08 15:45:33Z dugsong $

"""Cisco Netflow."""

import itertools, struct
from . import pypacker

class NetflowBase(pypacker.Packet):
	"""Base class for Cisco Netflow packets."""

	__hdr__ = (
		('version', 'H', 1),
		('count', 'H', 0),
		('sys_uptime', 'I', 0),
		('unix_sec', 'I', 0),
		('unix_nsec', 'I', 0)
	)

	def __len__(self):
		return self.__hdr_len__ + (len(self.data[0]) * self.count)

	def __str__(self):
		# for now, don't try to enforce any size limits
		# fix: https://code.google.com/p/pypacker/issues/detail?id=61
		self.count = len(self.data) / 48
		return self.pack_hdr() + ''.join(map(str, self.data))

	def unpack(self, buf):
		pypacker.Packet.unpack(self, buf)
		buf = self.data
		l = []
		while buf:
			flow = self.NetflowRecord(buf)
			l.append(flow)
			buf = buf[len(flow):]
		self.data = l

	class NetflowRecordBase(pypacker.Packet):
		"""Base class for netflow v1-v7 netflow records."""

		# performance optimizations
		def __len__(self):
			# don't bother with data
			return self.__hdr_len__

		def __str__(self):
			# don't bother with data
			return self.pack_hdr()

		def unpack(self, buf):
			# don't bother with data
			for k, v in zip(self.__hdr_fields__,
				struct.unpack(self.__hdr_fmt__, buf[:self.__hdr_len__])):
				setattr(self, k, v)
			self.data = ""


class Netflow1(NetflowBase):
	"""Netflow Version 1."""

	class NetflowRecord(NetflowBase.NetflowRecordBase):
		"""Netflow v1 flow record."""
		__hdr__ = (
			('src_addr', 'I', 0),
			('dst_addr', 'I', 0),
			('next_hop', 'I', 0),
			('input_iface', 'H', 0),
			('output_iface', 'H', 0),
			('pkts_sent', 'I', 0),
			('bytes_sent', 'I', 0),
			('start_time', 'I', 0),
			('end_time', 'I', 0),
			('src_port', 'H', 0),
			('dst_port', 'H', 0),
			('pad1', 'H', 0),
			('ip_proto', 'B', 0),
			('tos', 'B', 0),
			('tcp_flags', 'B', 0),
			('pad2', 'B', 0),
			('pad3', 'H', 0),
			('reserved', 'I', 0)
		)

# FYI, versions 2-4 don't appear to have ever seen the light of day.

class Netflow5(NetflowBase):
	"""Netflow Version 5."""
	__hdr__ = NetflowBase.__hdr__ + (
		('flow_sequence', 'I', 0),
		('engine_type', 'B', 0),
		('engine_id', 'B', 0),
		('reserved', 'H', 0),
	)

	class NetflowRecord(NetflowBase.NetflowRecordBase):
		"""Netflow v5 flow record."""
		__hdr__ = (
			('src_addr', 'I', 0),
			('dst_addr', 'I', 0),
			('next_hop', 'I', 0),
			('input_iface', 'H', 0),
			('output_iface', 'H', 0),
			('pkts_sent', 'I', 0),
			('bytes_sent', 'I', 0),
			('start_time', 'I', 0),
			('end_time', 'I', 0),
			('src_port', 'H', 0),
			('dst_port', 'H', 0),
			('pad1', 'B', 0),
			('tcp_flags', 'B', 0),
			('ip_proto', 'B', 0),
			('tos', 'B', 0),
			('src_as', 'H', 0),
			('dst_as', 'H', 0),
			('src_mask', 'B', 0),
			('dst_mask', 'B', 0),
			('pad2', 'H', 0),
		)

class Netflow6(NetflowBase):
	"""Netflow Version 6.
	XXX - unsupported by Cisco, but may be found in the field.
	"""
	__hdr__ = Netflow5.__hdr__

	class NetflowRecord(NetflowBase.NetflowRecordBase):
		"""Netflow v6 flow record."""
		__hdr__ = (
			('src_addr', 'I', 0),
			('dst_addr', 'I', 0),
			('next_hop', 'I', 0),
			('input_iface', 'H', 0),
			('output_iface', 'H', 0),
			('pkts_sent', 'I', 0),
			('bytes_sent', 'I', 0),
			('start_time', 'I', 0),
			('end_time', 'I', 0),
			('src_port', 'H', 0),
			('dst_port', 'H', 0),
			('pad1', 'B', 0),
			('tcp_flags', 'B', 0),
			('ip_proto', 'B', 0),
			('tos', 'B', 0),
			('src_as', 'H', 0),
			('dst_as', 'H', 0),
			('src_mask', 'B', 0),
			('dst_mask', 'B', 0),
			('in_encaps', 'B', 0),
			('out_encaps', 'B', 0),
			('peer_nexthop', 'I', 0),
		)

class Netflow7(NetflowBase):
	"""Netflow Version 7."""
	__hdr__ = NetflowBase.__hdr__ + (
		('flow_sequence', 'I', 0),
		('reserved', 'I', 0),
	)

	class NetflowRecord(NetflowBase.NetflowRecordBase):
		"""Netflow v7 flow record."""
		__hdr__ = (
			('src_addr', 'I', 0),
			('dst_addr', 'I', 0),
			('next_hop', 'I', 0),
			('input_iface', 'H', 0),
			('output_iface', 'H', 0),
			('pkts_sent', 'I', 0),
			('bytes_sent', 'I', 0),
			('start_time', 'I', 0),
			('end_time', 'I', 0),
			('src_port', 'H', 0),
			('dst_port', 'H', 0),
			('flags', 'B', 0),
			('tcp_flags', 'B', 0),
			('ip_proto', 'B', 0),
			('tos', 'B', 0),
			('src_as', 'H', 0),
			('dst_as', 'H', 0),
			('src_mask', 'B', 0),
			('dst_mask', 'B', 0),
			('pad2', 'H', 0),
			('router_sc', 'I', 0),
			)

# No support for v8 or v9 yet.
