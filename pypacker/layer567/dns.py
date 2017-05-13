"""Domain Name System."""
import struct
import logging

from pypacker import pypacker, triggerlist
from pypacker.pypacker import FIELD_FLAG_AUTOUPDATE

TriggerList = triggerlist.TriggerList
unpack = struct.unpack
logger = logging.getLogger("pypacker")

# avoid reverences for performance reasons
unpack_H = struct.Struct(">H").unpack
unpack_HHHH = struct.Struct(">HHHH").unpack

DNS_Q			= 0
DNS_R			= 1

# Opcodes
DNS_QUERY		= 0
DNS_IQUERY		= 1
DNS_STATUS		= 2
DNS_NOTIFY		= 4
DNS_UPDATE		= 5

# Flags
DNS_AN			= 0x8000		# this is a response
DNS_CD			= 0x0010		# checking disabled
DNS_AD			= 0x0020		# authenticated data
DNS_Z			= 0x0040		# unused
DNS_RA			= 0x0080		# recursion available
DNS_RD			= 0x0100		# recursion desired
DNS_TC			= 0x0200		# truncated
DNS_AA			= 0x0400		# authoritative answer

# Response codes
DNS_RCODE_NOERR		= 0
DNS_RCODE_FORMERR	= 1
DNS_RCODE_SERVFAIL	= 2
DNS_RCODE_NXDOMAIN	= 3
DNS_RCODE_NOTIMP	= 4
DNS_RCODE_REFUSED	= 5
DNS_RCODE_YXDOMAIN	= 6
DNS_RCODE_YXRRSET	= 7
DNS_RCODE_NXRRSET	= 8
DNS_RCODE_NOTAUTH	= 9
DNS_RCODE_NOTZONE	= 10

# RR types
DNS_A			= 1
DNS_NS			= 2
DNS_CNAME		= 5
DNS_SOA			= 6
DNS_WKS			= 11
DNS_PTR			= 12
DNS_HINFO		= 13
DNS_MINFO		= 14
DNS_MX			= 15
DNS_TXT			= 16
DNS_RP			= 17
DNS_SIG			= 24
DNS_GPOS		= 27
DNS_AAAA		= 28
DNS_LOC			= 29
DNS_SRV			= 33
DNS_NAPTR		= 35
DNS_KX			= 36
DNS_CERT		= 37
DNS_DNAME		= 39
DNS_DS			= 43
DNS_SSHFP		= 44
DNS_IPSECKEY		= 45
DNS_RRSIG		= 46
DNS_NSEC		= 47
DNS_DNSKEY		= 48
DNS_DHCID		= 49
DNS_NSEC3		= 50
DNS_NSEC3PARAM		= 51
DNS_TLSA		= 52
DNS_SPF			= 99
DNS_TKEY		= 249
DNS_TSIG		= 250
DNS_IXFR		= 251
DNS_AXFR		= 252
DNS_CAA			= 257
DNS_TA			= 32768
DNS_DLV			= 32769


# RR classes
DNS_IN			= 1
DNS_CHAOS		= 3
DNS_HESIOD		= 4
DNS_ANY			= 255


class DNS(pypacker.Packet):
	__hdr__ = (
		("id", "H", 0x1234),
		("flags", "H", DNS_AD | DNS_RD),
		("questions_amount", "H", 0, FIELD_FLAG_AUTOUPDATE),
		("answers_amount", "H", 0, FIELD_FLAG_AUTOUPDATE),
		("authrr_amount", "H", 0, FIELD_FLAG_AUTOUPDATE),
		("addrr_amount", "H", 0, FIELD_FLAG_AUTOUPDATE),
		("queries", None, TriggerList),
		("answers", None, TriggerList),
		("auths", None, TriggerList),
		("addrecords", None, TriggerList)
	)

	class Query(pypacker.Packet):
		"""DNS question."""
		__hdr__ = (
			("name", None, b"\x03www\x04test\x03com\x00"),
			("type", "H", DNS_A),
			("cls", "H", DNS_IN)
		)

		name_s = pypacker.get_property_dnsname("name")

		def _dissect(self, buf):
			idx = buf.find(b"\x00")
			#logger.debug("name in Query: %s" % buf[:idx+1])
			self.name = buf[:idx + 1]
			#logger.debug("val / format: %s %s" % (self._name, self._name_format))
			return len(buf)		# name (including 0) + type + cls

	class Answer(pypacker.Packet):
		"""DNS resource record."""
		__hdr__ = (
			("name", "H", 0xc00c),
			("type", "H", DNS_A),
			("cls", "H", DNS_IN),
			("ttl", "I", 180),
			("dlen", "H", 4),			# length of the next field
			("address", None, b"1234")		# eg IPv4
		)

		def _dissect(self, buf):
			# needed set format
			addr_len = unpack_H(buf[10:12])[0]
			self.address = buf[12:12 + addr_len]
			# logger.debug("address: %s" % self.address)
			return 12 + addr_len

	class Auth(pypacker.Packet):
		"""Auth, generic type."""
		__hdr__ = (
			("name", "H", 0),
			("type", "H", 0),
			("cls", "H", 0),
			("ttl", "I", 0),
			("dlen", "H", 0),		# length of the rest of header: server + x, x becmoes body content
			("server", None, b"\x03www\x04test\x03com\x00")
			# TODO: add fields for mailbox, serial, refresh etc.
		)

		server_s = pypacker.get_property_dnsname("server")

		def _dissect(self, buf):
			# needed set format
			# find server name by 0-termination
			idx = buf.find(b"\x00", 12)
			if idx == -1:
				idx = len(buf)
			self.server = buf[12: idx + 1]
			# logger.debug("server: %s" % self.server)

			return idx + 1

	class AuthSOA(pypacker.Packet):
		"""
		Auth type SOA.
		Not used atm
		"""
		__hdr__ = (
			("name", "H", 0),
			("type", "H", 0),
			("cls", "H", 0),
			("ttl", "I", 0),
			("dlen", "H", 0),
			("name2", None, b"\x03www\x04test\x03com\x00"),
			("mailbox", None, b"\x03www\x04test\x03com\x00"),
			("pserver", "H", 0),
			("mbox", "H", 0),
			("serial", "H", 0),
			("refresh", "H", 0),
			("retry", "H", 0),
			("expire", "H", 0),
			("minttl", "H", 0)
		)

		name_s = pypacker.get_property_dnsname("name")
		mailbox_s = pypacker.get_property_dnsname("mailbox")

		def _dissect(self, buf):
			# set format
			# find server name by 0-termination
			idx = buf.find(b"\x00", 12)
			# logger.debug(buf[12: idx+1])
			# don't add trailing \0
			self.name = buf[12: idx + 1]
			# logger.debug("name: %s" % buf[idx + 1: -14])
			self.mailbox = buf[idx + 1: -14]
			return len(buf)

	class AddRecord(pypacker.Packet):
		"""DNS additional records."""
		__hdr__ = (
			("name", "H", 0),
			("type", "H", 0x0001),
			("clz", "H", 0x0001),
			("ts", "I", 0),
			("dlen", "H", 0),
			("addr", None, b"\x01\x02\x03\x04")
		)

		def _dissect(self, buf):
			# logger.debug(buf[0: idx+1])
			self.addr = buf[12:]
			# logger.debug("addr: %s" % self.addr)
			return len(buf)

	class AddRecordRoot(pypacker.Packet):
		"""DNS additional records."""
		__hdr__ = (
			("name", "B", 0),
			("type", "H", 0x0001),
			("udpsize", "H", 0x0001),
			("rcode", "B", 0),
			("v", "B", 0),
			("z", "H", 0),
			("dlen", "H", 0)
		)

	def _dissect(self, buf):
		# unpack basic data to get things done
		quests_amount, ans_amount, authserver_amount, addreq_amount = unpack_HHHH(buf[4:12])
		off = 12

		# TODO: use lazy dissect, dns seems to be too shitty for this
		#
		# parse queries
		#
		#logger.debug(">>> parsing questions: %d" % quests_amount)
		while quests_amount > 0:
			# find name by 0-termination
			idx = buf.find(b"\x00", off)
			q_end = idx + 5
			#logger.debug("name is: %s" % buf[off: q_end-4])
			#logger.debug("Query is: %s" % buf[off: q_end])
			#logger.debug(len(buf[off: q_end]))
			q = DNS.Query(buf[off: q_end])
			# logger.debug("query is following..")
			#logger.debug("Query: %s" % q)
			# logger.debug("query name format: %s" % q._name_format)
			self.queries.append(q)
			off = q_end
			quests_amount -= 1

		#
		# parse answers
		#
		#logger.debug(">>> parsing answers: %d" % ans_amount)
		while ans_amount > 0:
			# find name by label/0-termination
			# TODO: handle non-label names
			dlen = unpack_H(buf[off + 10: off + 12])[0]
			index_end = 12 + dlen
			# logger.debug("Answer is: %r" % buf[off: off + index_end])
			a = DNS.Answer(buf[off: off + index_end])
			# logger.debug("Answer: %s" % a)
			self.answers.append(a)
			off += index_end
			ans_amount -= 1

		#
		# parse authorative servers
		#
		#logger.debug(">>> parsing authorative servers: %d" % authserver_amount)
		while authserver_amount > 0:
			dlen = unpack_H(buf[off + 10: off + 12])[0]
			authlen = 12 + dlen
			# logger.debug("Auth: %r" % buf[off: off + authlen])
			a = DNS.Auth(buf[off: off + authlen])

			# logger.debug("Auth server: %s" % a)
			self.auths.append(a)
			off += authlen
			authserver_amount -= 1

		#
		# parse additional requests
		#
		#logger.debug(">>> parsing additional records: %d" % addreq_amount)
		while addreq_amount > 0:
			if buf[off: off + 3] == b"\x00\x00\x29":
				a = DNS.AddRecordRoot(buf[off: off + 11])
				#logger.debug(a)
				#logger.debug(a.bin())
				#logger.debug(len(a.bin()))
				off += 11
			else:
				# logger.debug(buf[idx:])
				# logger.debug(buf[off:])
				# logger.debug("data length via: %r" % buf[idx + 9: idx + 11])
				dlen = unpack_H(buf[off + 10: off + 10 + 2])[0]
				# logger.debug("AddRecord: %s" % buf[off: off + 12 + dlen])
				a = DNS.AddRecord(buf[off: off + 12 + dlen])
				# logger.debug("Additional Record: %s" % a)
				off += 12 + dlen
			self.addrecords.append(a)
			addreq_amount -= 1

		# logger.debug("dns: %s" % self)
		return off

	def bin(self, update_auto_fields=True):
		if update_auto_fields and self._header_changed:
			# logger.debug("updating lenghts")
			# avoid lazy dissect by checking for [b"bytes", dissect_callback]
			# first assigning to length will trigger _unpack(...)
			if self.questions_amount_au_active and self._queries.__class__ is not list:
				self.questions_amount = len(self.queries)
			if self.answers_amount_au_active and self._answers.__class__ is not list:
				self.answers_amount = len(self.answers)
			if self.authrr_amount_au_active and self._auths.__class__ is not list:
				self.authrr_amount = len(self.auths)
			if self.addrr_amount_au_active and self._addrecords.__class__ is not list:
				self.addrr_amount = len(self.addrecords)
			# logger.debug("finished updating lengths")
		return pypacker.Packet.bin(self, update_auto_fields=update_auto_fields)
