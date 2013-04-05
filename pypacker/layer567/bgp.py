"""
Border Gateway Protocol.
"""

from .. import pypacker

import struct
import socket
import logging

# Border Gateway Protocol 4 - RFC 4271
# Communities Attribute - RFC 1997
# Capabilities - RFC 3392
# Route Refresh - RFC 2918
# Route Reflection - RFC 4456
# Confederations - RFC 3065
# Cease Subcodes - RFC 4486
# NOPEER Community - RFC 3765
# Multiprotocol Extensions - 2858

# Message Types
OPEN				= 1
UPDATE				= 2
NOTIFICATION			= 3
KEEPALIVE			= 4
ROUTE_REFRESH			= 5

# Attribute Types
ORIGIN				= 1
AS_PATH				= 2
NEXT_HOP			= 3
MULTI_EXIT_DISC			= 4
LOCAL_PREF			= 5
ATOMIC_AGGREGATE		= 6
AGGREGATOR			= 7
COMMUNITIES			= 8
ORIGINATOR_ID			= 9
CLUSTER_LIST			= 10
MP_REACH_NLRI			= 14
MP_UNREACH_NLRI			= 15

# Origin Types
ORIGIN_IGP			= 0
ORIGIN_EGP			= 1
INCOMPLETE			= 2

# AS Path Types
AS_SET				= 1
AS_SEQUENCE			= 2
AS_CONFED_SEQUENCE		= 3
AS_CONFED_SET			= 4

# Reserved Communities Types
NO_EXPORT			= 0xffffff01
NO_ADVERTISE			= 0xffffff02
NO_EXPORT_SUBCONFED		= 0xffffff03
NO_PEER				= 0xffffff04

# Common AFI types
AFI_IPV4			= 1
AFI_IPV6			= 2

# Multiprotocol SAFI types
SAFI_UNICAST			= 1
SAFI_MULTICAST			= 2
SAFI_UNICAST_MULTICAST		= 3

# OPEN Message Optional Parameters
AUTHENTICATION			= 1
CAPABILITY			= 2

# Capability Types
CAP_MULTIPROTOCOL		= 1
CAP_ROUTE_REFRESH		= 2

# NOTIFICATION Error Codes
MESSAGE_HEADER_ERROR		= 1
OPEN_MESSAGE_ERROR		= 2
UPDATE_MESSAGE_ERROR		= 3
HOLD_TIMER_EXPIRED		= 4
FSM_ERROR			= 5
CEASE				= 6

# Message Header Error Subcodes
CONNECTION_NOT_SYNCHRONIZED	= 1
BAD_MESSAGE_LENGTH		= 2
BAD_MESSAGE_TYPE		= 3

# OPEN Message Error Subcodes
UNSUPPORTED_VERSION_NUMBER	= 1
BAD_PEER_AS			= 2
BAD_BGP_IDENTIFIER		= 3
UNSUPPORTED_OPTIONAL_PARAMETER	= 4
AUTHENTICATION_FAILURE		= 5
UNACCEPTABLE_HOLD_TIME		= 6
UNSUPPORTED_CAPABILITY		= 7

# UPDATE Message Error Subcodes
MALFORMED_ATTRIBUTE_LIST	= 1
UNRECOGNIZED_ATTRIBUTE		= 2
MISSING_ATTRIBUTE		= 3
ATTRIBUTE_FLAGS_ERROR		= 4
ATTRIBUTE_LENGTH_ERROR		= 5
INVALID_ORIGIN_ATTRIBUTE	= 6
AS_ROUTING_LOOP			= 7
INVALID_NEXT_HOP_ATTRIBUTE	= 8
OPTIONAL_ATTRIBUTE_ERROR	= 9
INVALID_NETWORK_FIELD		= 10
MALFORMED_AS_PATH		= 11

# Cease Error Subcodes
MAX_NUMBER_OF_PREFIXES_REACHED	= 1
ADMINISTRATIVE_SHUTDOWN		= 2
PEER_DECONFIGURED		= 3
ADMINISTRATIVE_RESET		= 4
CONNECTION_REJECTED		= 5
OTHER_CONFIGURATION_CHANGE	= 6
CONNECTION_COLLISION_RESOLUTION	= 7
OUT_OF_RESOURCES		= 8


class BGP(pypacker.Packet):
	__hdr__ = (
		("marker", "16s", b"\xff" * 16),
		("len", "H", 0),
		("type", "B", OPEN)
		)

	def _unpack(self, buf):
		type = buf[18]
		#self.data = self.data[:self.len - self.__hdr_len__]

		try:
			type_instance = self._handler[BGP.__name__][type](buf[self.__hdr_len__)
			self._set_bodyhandler(type_instance)
			# any exception will lead to: body = raw bytes
                except Exception as e:
			logger.debug("BGP: failed to set handler: %s" % e)
			pass

		pypacker.Packet._unpack(self, buf)

	class Open(pypacker.Packet):
		__hdr__ = (
			("v", "B", 4),
			("asn", "H", 0),
			("holdtime", "H", 0),
			("identifier", "I", 0),
			("param_len", "B", 0)
			)

		def __get_params(self):
			if not hasattr(self, "_params"):
				tl = pypacker.TriggerList()
				self._add_headerfield("_params", "", tl)
			return self._params
		params = property(__get_params)

		def _unpack(self, buf):
			params = []
			pcount = buf[9]
			off = self.__hdr_len__

			while pcount > 0:
				plen = buf[off+2]
				param = self.Parameter( buf[off:off+plen] )
				params.append(param)
				pcount -= 1
				# TODO: check if len-value is UNCLUSIVE type/len field
				off += plen

			tl = pypacker.TriggerList(params)
			self.params.extend(tl)

			pypacker.Packet._unpack(self, buf)

		class Parameter(pypacker.Packet):
			__hdr__ = (
				("type", "B", 0),
				("len", "B", 0)
				)


	class Update(pypacker.Packet):
		def _unpack(self, buf):
			routes = []

			# Withdrawn Routes
			off = 2
			wlen = struct.unpack(">H", self.data[:off])[0]

			while wlen > 0:
				route = Route(buf[off:])
				wlen -= len(route)
				routes.append(route)
				off += len(route)
			self.withdrawn = l

			# Path Attributes
			plen = struct.unpack(">H", self.data[off:off+2])[0]
			attrs = []
			while plen > 0:
				attr = self.Attribute(self.data)
				plen -= len(attr)
				attrs.append(attr)
				off += len(attr)
			self.attributes = l

			# Announced Routes
			annc = []

			while self.data:
				route = Route(self.data)
				self.data = self.data[len(route):]
				annc.append(route)
			self.announced = l


		class Attribute(pypacker.Packet):
			__hdr__ = (
				("flags", "B", 0),
				("type", "B", 0)
				)

			def __get_o(self):
				return (self.flags >> 7) & 0x1
			def __set_o(self, o):
				self.flags = (self.flags & ~0x80) | ((o & 0x1) << 7)
			optional = property(__get_o, __set_o)

			def __get_t(self):
				return (self.flags >> 6) & 0x1
			def __set_t(self, t):
				self.flags = (self.flags & ~0x40) | ((t & 0x1) << 6)
			transitive = property(__get_t, __set_t)

			def __get_p(self):
				return (self.flags >> 5) & 0x1
			def __set_p(self, p):
				self.flags = (self.flags & ~0x20) | ((p & 0x1) << 5)
			partial = property(__get_p, __set_p)

			def __get_e(self):
				return (self.flags >> 4) & 0x1
			def __set_e(self, e):
				self.flags = (self.flags & ~0x10) | ((e & 0x1) << 4)
			extended_length = property(__get_e, __set_e)


			def _unpack(self, buf):
				# temporary unpack to parse flags
				pypacker.Packet._unpack(self, buf[:2])

				off = 0
				len = 0

				if self.extended_length:
					off = 2
					len = struct.unpack(">H", self.data[:2])[0]
				else:
					off = 1
					len = struct.unpack("B", self.data[:1])[0]

				try:
					type_instance = Attribute.__switch_type[type](buf[off:len)
					self._set_bodyhandler(type_instance)
					# any exception will lead to: body = raw bytes
				except Exception as e:
					logger.debug("BGP > Update > Attribute failed to set handler: %s" % e)
					pass

				# call to reset changed status
				pypacker.Packet._unpack(self, buf)

			class Origin(pypacker.Packet):
				__hdr__ = (
					("type", "B", ORIGIN_IGP),
				)

			class ASPath(pypacker.Packet):

				def __get_segments(self):
					if not hasattr(self, "_segments"):
						tl = TriggerList()
						self._add_headerfield("_segments", None, tl)
					return self._segments
				segments = property(__get_segments)

				def _unpack(self, buf):
					segs = []
					off = 1
					buflen = len(buf)

					while off < buflen:
						seglen = buf[off+2]
						seg = self.ASPathSegment(buf[off+1:seglen])
						segs.append(seg)
						off += seglen

					self.segments.extend(segs)
					pypacker.Packet._unpack(self, buf)

				class ASPathSegment(pypacker.Packet):
					__hdr__ = (
						("type", "B", 0),
						("len", "B", 0)
						)
					# TODO: auto-set length


			class NextHop(pypacker.Packet):
				__hdr__ = (
					("ip", "I", 0),
				)

			class MultiExitDisc(pypacker.Packet):
				__hdr__ = (
					("value", "I", 0),
				)

			class LocalPref(pypacker.Packet):
				__hdr__ = (
					("value", "I", 0),
				)

			class AtomicAggregate(pypacker.Packet):
				def _unpack(self, buf):
					pass


			class Aggregator(pypacker.Packet):
				__hdr__ = (
					("asn", "H", 0),
					("ip", "I", 0)
				)

			class Communities(pypacker.Packet):

				def _unpack(self, buf):
					l = []

					while self.data:
						val = struct.unpack(">I", self.data[:4])[0]
						if (val >= 0x00000000 and val <= 0x0000ffff) or \
							(val >= 0xffff0000 and val <= 0xffffffff):
							comm = self.ReservedCommunity(self.data[:4])
						else:
							comm = self.Community(self.data[:4])
						self.data = self.data[len(comm):]
						l.append(comm)
					
					pypacker.Packet._unpack(self, buf)

				class Community(pypacker.Packet):
					__hdr__ = (
						("asn", "H", 0),
						("value", "H", 0)
					)

				class ReservedCommunity(pypacker.Packet):
					__hdr__ = (
						("value", "I", 0),
					)

			class OriginatorID(pypacker.Packet):
				__hdr__ = (
					("value", "I", 0),
				)

			class ClusterList(pypacker.Packet):

				def _unpack(self, buf):
					l = []

					while self.data:
						id = struct.unpack(">I", self.data[:4])[0]
						self.data = self.data[4:]

					pypacker.Packet._unpack(self, buf)


			class MPReachNLRI(pypacker.Packet):
				__hdr__ = (
					("afi", "H", AFI_IPV4),
					("safi", "B", SAFI_UNICAST),
				)

				def _unpack(self, buf):
					# Next Hop
					nlen = struct.unpack("B", self.data[:1])[0]
					self.data = self.data[1:]
					self.next_hop = self.data[:nlen]
					self.data = self.data[nlen:]

					# SNPAs
					l = []
					num_snpas = struct.unpack("B", self.data[:1])[0]
					self.data = self.data[1:]
					for i in range(num_snpas):
						snpa = self.SNPA(self.data)
						self.data = self.data[len(snpa):]
						l.append(snpa)
					self.snpas = l

					# Announced Routes
					l = []
					while self.data:
						route = Route(self.data)
						self.data = self.data[len(route):]
						l.append(route)
					self.data = self.announced = l

					pypacker.Packet._unpack(self, buf)

				class SNPA:
					__hdr__ = (
						("len", "B", 0),
						)

			class MPUnreachNLRI(pypacker.Packet):
				__hdr__ = (
					("afi", "H", AFI_IPV4),
					("safi", "B", SAFI_UNICAST),
				)

				def _unpack(self, buf):
					pypacker.Packet._unpack(self, buf[:3])

					# Withdrawn Routes
					l = []
					while self.data:
						route = Route(self.data)
						self.data = self.data[len(route):]
						l.append(route)

					pypacker.Packet._unpack(self, buf)

			__switch_type_attribute = {
							ORIGIN : Origin,
							AS_PATH : AsPath,
							NEXT_HOP : NextHop,
							MULTI_EXIT_DISC : MultiExitDisc,
							LOCAL_PREF : LocalPref,
							ATOMIC_AGGREGATE : AtomicAggregate,
							AGGREGATOR : Aggregator,
							COMMUNITIES : Communities,
							ORIGINATOR_ID : OriginatorId,
							CLUSTER_LIST : ClusterList,
							MP_REACH_NLRI : MpReachNLRI,
							MP_UNREACH_NLRI MpUnreachNLRI: 
						}

	class Notification(pypacker.Packet):
		__hdr__ = (
			("code", "B", 0),
			("subcode", "B", 0),
			)

	class Keepalive(pypacker.Packet):
		pass

	class RouteRefresh(pypacker.Packet):
		__hdr__ = (
			("afi", "H", AFI_IPV4),
			("rsvd", "B", 0),
			("safi", "B", SAFI_UNICAST)
			) 


class Route(pypacker.Packet):
	__hdr__ = (
		("len", "B", 0),
		)

# load handler
pypacker.Packet.load_handler(BGP,
				{
				OPEN : BGP.Open,
				UPDATE : BGP.Update,
				NOTIFICATION : BGP.Notification,
				KEEPALIVE : BGP.Keepalive,
				ROUTE_REFRESH : BGP.RouteRefresh
				}
				)
