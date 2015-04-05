"""Internet Control Message Protocol for IPv6."""

from pypacker import pypacker

import logging

logger = logging.getLogger("pypacker")

ICMP6_DST_UNREACH		= 1		# dest unreachable, codes:
ICMP6_PACKET_TOO_BIG		= 2		# packet too big
ICMP6_TIME_EXCEEDED		= 3		# time exceeded, code:
ICMP6_PARAM_PROB		= 4		# ip6 header bad

ICMP6_ECHO_REQUEST		= 128		# echo service
ICMP6_ECHO_REPLY		= 129		# echo reply
MLD_LISTENER_QUERY		= 130		# multicast listener query
MLD_LISTENER_REPORT		= 131		# multicast listener report
MLD_LISTENER_DONE		= 132		# multicast listener done

# RFC2292 decls
ICMP6_MEMBERSHIP_QUERY		= 130		# group membership query
ICMP6_MEMBERSHIP_REPORT		= 131		# group membership report
ICMP6_MEMBERSHIP_REDUCTION	= 132		# group membership termination

ND_ROUTER_SOLICIT		= 133		# router solicitation
ND_ROUTER_ADVERT		= 134		# router advertisment
ND_NEIGHBOR_SOLICIT		= 135		# neighbor solicitation
ND_NEIGHBOR_ADVERT		= 136		# neighbor advertisment
ND_REDIRECT			= 137		# redirect

ICMP6_ROUTER_RENUMBERING	= 138		# router renumbering

ICMP6_WRUREQUEST		= 139		# who are you request
ICMP6_WRUREPLY			= 140		# who are you reply
ICMP6_FQDN_QUERY		= 139		# FQDN query
ICMP6_FQDN_REPLY		= 140		# FQDN reply
ICMP6_NI_QUERY			= 139		# node information request
ICMP6_NI_REPLY			= 140		# node information reply

ICMP6_MAXTYPE			= 201


class ICMP6(pypacker.Packet):
	__hdr__ = (
		("type", "B", 0),
		("code", "B", 0),
		("sum", "H", 0)
	)

	def _dissect(self, buf):
		self._init_handler(buf[0], buf[4:])
		return 4

	class Error(pypacker.Packet):
		__hdr__ = (("pad", "I", 0), )

	class Unreach(Error):
		pass

	class TooBig(Error):
		__hdr__ = (("mtu", "I", 1232), )

	class TimeExceed(Error):
		pass

	class ParamProb(Error):
		__hdr__ = (("ptr", "I", 0), )

	class Echo(pypacker.Packet):
		__hdr__ = (
			("id", "H", 0),
			("seq", "H", 0)
		)

pypacker.Packet.load_handler(ICMP6,
	{
		1: ICMP6.Unreach,
		2: ICMP6.TooBig,
		3: ICMP6.TimeExceed,
		4: ICMP6.ParamProb,
		128: ICMP6.Echo,
		129: ICMP6.Echo
	}
)
