"""Dynamic Host Configuration Protocol."""
import logging

from pypacker import pypacker, triggerlist
from pypacker.layer12 import arp

logger = logging.getLogger("pypacker")


DHCP_OP_REQUEST		= 1
DHCP_OP_REPLY		= 2

DHCP_MAGIC		= 0x63825363

# DHCP option codes
DHCP_OPT_NETMASK		= 1		# I: subnet mask
DHCP_OPT_TIMEOFFSET		= 2
DHCP_OPT_ROUTER			= 3		# s: list of router ips
DHCP_OPT_TIMESERVER		= 4
DHCP_OPT_NAMESERVER		= 5
DHCP_OPT_DNS_SVRS		= 6		# s: list of DNS servers
DHCP_OPT_LOGSERV		= 7
DHCP_OPT_COOKIESERV		= 8
DHCP_OPT_LPRSERV		= 9
DHCP_OPT_IMPSERV		= 10
DHCP_OPT_RESSERV		= 11
DHCP_OPT_HOSTNAME		= 12		# s: client hostname
DHCP_OPT_BOOTFILESIZE		= 13
DHCP_OPT_DUMPFILE		= 14
DHCP_OPT_DOMAIN			= 15		# s: domain name
DHCP_OPT_SWAPSERV		= 16
DHCP_OPT_ROOTPATH		= 17
DHCP_OPT_EXTENPATH		= 18
DHCP_OPT_IPFORWARD		= 19
DHCP_OPT_SRCROUTE		= 20
DHCP_OPT_POLICYFILTER		= 21
DHCP_OPT_MAXASMSIZE		= 22
DHCP_OPT_IPTTL			= 23
DHCP_OPT_MTUTIMEOUT		= 24
DHCP_OPT_MTUTABLE		= 25
DHCP_OPT_MTUSIZE		= 26
DHCP_OPT_LOCALSUBNETS		= 27
DHCP_OPT_BROADCASTADDR		= 28
DHCP_OPT_DOMASKDISCOV		= 29
DHCP_OPT_MASKSUPPLY		= 30
DHCP_OPT_DOROUTEDISC		= 31
DHCP_OPT_ROUTERSOLICIT		= 32
DHCP_OPT_STATICROUTE		= 33
DHCP_OPT_TRAILERENCAP		= 34
DHCP_OPT_ARPTIMEOUT		= 35
DHCP_OPT_ETHERENCAP		= 36
DHCP_OPT_TCPTTL			= 37
DHCP_OPT_TCPKEEPALIVE		= 38
DHCP_OPT_TCPALIVEGARBAGE	= 39
DHCP_OPT_NISDOMAIN		= 40
DHCP_OPT_NISSERVERS		= 41
DHCP_OPT_NISTIMESERV		= 42
DHCP_OPT_VENDSPECIFIC		= 43
DHCP_OPT_NBNS			= 44
DHCP_OPT_NBDD			= 45
DHCP_OPT_NBTCPIP		= 46
DHCP_OPT_NBTCPSCOPE		= 47
DHCP_OPT_XFONT			= 48
DHCP_OPT_XDISPLAYMGR		= 49
DHCP_OPT_REQ_IP			= 50		# I: IP address
DHCP_OPT_LEASE_SEC		= 51		# I: lease seconds
DHCP_OPT_OPTIONOVERLOAD		= 52
DHCP_OPT_MSGTYPE		= 53		# B: message type
DHCP_OPT_SERVER_ID		= 54		# I: server IP address
DHCP_OPT_PARAM_REQ		= 55		# s: list of option codes
DHCP_OPT_MESSAGE		= 56
DHCP_OPT_MAXMSGSIZE		= 57
DHCP_OPT_RENEWTIME		= 58
DHCP_OPT_REBINDTIME		= 59
DHCP_OPT_VENDOR_ID		= 60		# s: vendor class id
DHCP_OPT_CLIENT_ID		= 61		# Bs: idtype, id (idtype 0: FQDN, idtype 1: M
DHCP_OPT_NISPLUSDOMAIN		= 64
DHCP_OPT_NISPLUSSERVERS		= 65
DHCP_OPT_MOBILEIPAGENT		= 68
DHCP_OPT_SMTPSERVER		= 69
DHCP_OPT_POP3SERVER		= 70
DHCP_OPT_NNTPSERVER		= 71
DHCP_OPT_WWWSERVER		= 72
DHCP_OPT_FINGERSERVER		= 73
DHCP_OPT_IRCSERVER		= 74
DHCP_OPT_STSERVER		= 75
DHCP_OPT_STDASERVER		= 76

# DHCP message type values
DHCPDISCOVER			= 1
DHCPOFFER			= 2
DHCPREQUEST			= 3
DHCPDECLINE			= 4
DHCPACK				= 5
DHCPNAK				= 6
DHCPRELEASE			= 7
DHCPINFORM			= 8


class DHCP(pypacker.Packet):
	__hdr__ = (
		("op", "B", DHCP_OP_REQUEST),
		("hrd", "B", arp.ARP_HRD_ETH),		# just like ARP.hrd
		("hln", "B", 6),			# and ARP.hln
		("hops", "B", 0),
		("xid", "I", 0xdeadbeef),
		("secs", "H", 0),
		("flags", "H", 0),
		("ciaddr", "4s", b"\x00" * 4),
		("yiaddr", "4s", b"\x00" * 4),
		("siaddr", "4s", b"\x00" * 4),
		("giaddr", "4s", b"\x00" * 4),
		# MAC + padding
		("chaddr", "16s", b"\x00" * 6 + b"\x00" * 10),
		("sname", "64s", b"\x00" * 64),
		("file", "128s", b"\x00" * 128),
		("magic", "I", DHCP_MAGIC),
		("opts", None, triggerlist.TriggerList)
	)

	ciaddr_s = pypacker.get_property_ip4("ciaddr")
	yiaddr_s = pypacker.get_property_ip4("yiaddr")
	siaddr_s = pypacker.get_property_ip4("siaddr")
	giaddr_s = pypacker.get_property_ip4("giaddr")

	def _dissect(self, buf):
		# logger.debug("DHCP: parsing options, buflen: %d" % len(buf))
		self._init_triggerlist("opts", buf[28 + 16 + 64 + 128 + 4:], DHCP.__get_opts)
		# logger.debug(buf[28+16+64+128+4:])
		# logger.debug("amount of options after parsing: %d" % len(self.opts))
		return len(buf)

	@staticmethod
	def __get_opts(buf):
		# logger.debug("DHCP: parsing options from: %s" % buf)
		opts = []
		i = 0

		while i < len(buf):
			t = buf[i]
			p = None
			# logger.debug("DHCP: adding option type %d" % t)

			# last option
			if t in [0, 0xff]:
				p = DHCPOpt(type=t, len=0)
				i += 1
			else:
				dlen = buf[i + 1]
				p = DHCPOpt(type=t, len=dlen, body_bytes=buf[i + 2: i + 2 + dlen])
				i += 2 + dlen

			# logger.debug("new option: %s" % p)
			opts.append(p)

			if t == 0xff:
				if i < len(buf):
					# padding is part of the options
					opts.append(Padding(buf[i:]))
				break

		return opts


class DHCPOpt(pypacker.Packet):
	__hdr__ = (
		("type", "B", 0),
		("len", "B", 0),
	)


class Padding(pypacker.Packet):
	pass
