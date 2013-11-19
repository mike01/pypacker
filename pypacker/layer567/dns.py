"""Domain Name System."""

from pypacker import pypacker, triggerlist

import struct
import logging

logger = logging.getLogger("pypacker")

DNS_Q			= 0
DNS_R			= 1

# Opcodes
DNS_QUERY		= 0
DNS_IQUERY		= 1
DNS_STATUS		= 2
DNS_NOTIFY		= 4
DNS_UPDATE		= 5

# Flags
DNS_AN			= 0x8000	# this is a response
DNS_CD			= 0x0010	# checking disabled
DNS_AD			= 0x0020	# authenticated data
DNS_Z			= 0x0040	# unused
DNS_RA			= 0x0080	# recursion available
DNS_RD			= 0x0100	# recursion desired
DNS_TC			= 0x0200	# truncated
DNS_AA			= 0x0400	# authoritative answer

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
DNS_PTR			= 12
DNS_HINFO		= 13
DNS_MX			= 15
DNS_TXT			= 16
DNS_AAAA		= 28
DNS_SRV			= 33

# RR classes
DNS_IN			= 1
DNS_CHAOS		= 3
DNS_HESIOD		= 4
DNS_ANY			= 255


class DNSTriggerList(triggerlist.TriggerList):
	def _handle_mod(self, val):
		# update amounts
		self._packet.questions_amount = len(self._packet.queries)
		self._packet.answers_amount = len(self._packet.answers)
		self._packet.authrr_amount = len(self._packet.auths)
		self._packet.addrr_amount = len(self._packet.addrecords)


class DNSString(triggerlist.TriggerList):
	def find_by_id(self, id):
		pass

	def __repr__(self):
		return "%s" % self.bin()

	def _pack(self):
		domains_assembled = b""

		if len(self) > 0 and len(self[0]) > 0:
			# a.b.com -> [a, b, com]
			domains = (b"".join(self)).split(b".")
			domains = [ len(v).to_bytes(1,byteorder='little')+v for v in domains ]
			domains_assembled = b"".join(domains)
			#logger.debug("domains assembled: %s" % domains_assembled)

		return domains_assembled


class DNS(pypacker.Packet):
	__hdr__ = (
		("id", "H", 0x1234),
		("flags", "H", DNS_AD | DNS_RD),
		("questions_amount", "H", 0),
		("answers_amount", "H", 0),
		("authrr_amount", "H", 0),
		("addrr_amount", "H", 0),
		("queries", None, DNSTriggerList),
		("answers", None, DNSTriggerList),
		("auths", None, DNSTriggerList),
		("addrecords", None, DNSTriggerList)
		)


	class Query(pypacker.Packet):
		"""DNS question."""
		__hdr__ = (
			("name", None, DNSString),
			("postfix", "B", 0),
			("type", "H", DNS_A),
			("cls", "H", DNS_IN)
			)

		def _dissect(self, buf):
			idx = buf.find(b"\x00")
			#logger.debug("trying to set name: %s" % buf[:idx+1])
			self.name = buf[1:idx]
			#logger.debug("name is: %s" % self.name)

	class Answer(pypacker.Packet):
		"""DNS resource record."""
		__hdr__ = (
			("name", "H", 0xc00c),
			("type", "H", DNS_A),
			("cls", "H", DNS_IN),
			("ttl", "I", 180),
			("dlen", "H", 4),
			("address", None, triggerlist.TriggerList),
			)

		def _dissect(self, buf):
			# set format
			self.address = buf[12:16]

	class Auth(pypacker.Packet):
		"""Auth data."""
		__hdr__ = (
			("name", "H", 0),
			("type", "H", 0),
			("cls", "H", 0),
			("ttl", "I", 0),
			("dlen", "H", 0),
			("name", None, DNSString),
			("postfix1", "B", 0),
			("mailbox", None, DNSString),
			("postfix2", "B", 0),
			("pserver", "H", 0),
			("mbox", "H", 0),
			("serial", "H", 0),
			("refresh", "H", 0),
			("retry", "H", 0),
			("expire", "H", 0),
			("minttl", "H", 0),
			)

		def _dissect(self, buf):
			# set format
			# find server name by 0-termination
			idx = buf.find(b"\x00", 12)
			# don't add trailing \0: will be auto added
			self.name = buf[ 13 : idx]
			self.mailbox = buf[ idx+2 : -15 ]

	# TODO: something is adding an additional \x00!
	class AddRecord(pypacker.Packet):
		"""DNS additional records."""
		__hdr__ = (
			("name", None, DNSString),
			("postfix", "B", 0),
			("type", "H", 0x0029),
			("plen", "H", 0x1000),
			("rcode", "B", 0),
			("edns", "B", 0),
			("z", "H", 0),
			("dlen", "H", 0),
			)

		def _dissect(self, buf):
			self.name = b""
		#	# add content if prefix found
		#	if buf[0] == b"\x03":
		#		idx_b = buf.find(b"\x00")
		#		self.name = buf[1 : idx_b]

	def _dissect(self, buf):
		# unpack basic data to get things done
		pypacker.Packet._unpack(self, buf[:12])
		off = 12
		quests_amount = self.questions_amount
		ans_amount = self.answers_amount
		authserver_amount = self.authrr_amount
		addreq_amount = self.addrr_amount

		#
		# parse questions
		#
		questions = []

		#logger.debug(">>> parsing questions: %d" % quests_amount)
		while quests_amount > 0:
			# find name by 0-termination
			idx = buf.find(b"\x00", off)
			#logger.debug("name is: %s" % buf[off : idx+1])
			#logger.debug("Query is: %s" % buf[off : idx+5])
			q = DNS.Query( buf[off : idx+5] )
			#logger.debug("Query: %s" % q)
			questions.append(q)
			off += len(q)
			quests_amount -= 1

		self.queries.extend(questions)

		#
		# parse answers
		#
		answers = []

		#logger.debug(">>> parsing answers: %d" % ans_amount)
		while ans_amount > 0:
			# find name by label/0-termination
			# TODO: handle non-label names
			alen = struct.unpack(">H", buf[off+10 : off+12])[0]
			a = DNS.Answer( buf[off : off+12+alen ] )
			answers.append(a)
			off += len(a)
			ans_amount -= 1

		self.answers.extend(answers)

		#
		# parse authorative servers
		#
		auth_server = []

		#logger.debug(">>> parsing authorative servers: %d" % authserver_amount)
		while authserver_amount > 0:
			dlen = struct.unpack(">H", buf[off+10 : off+12])[0]
			a = DNS.Auth( buf[off : off + 12 + dlen])

			#logger.debug("Auth server: %s" % a)
			auth_server.append(a)
			off += len(a)
			authserver_amount -= 1

		self.auths.extend(auth_server)

		#
		# parse additional requests
		#
		add_req = []

		#logger.debug(">>> parsing additional records: %d" % addreq_amount)
		while addreq_amount > 0:
			# find name by 0-termination
			idx = buf.find(b"\x00", off)
			dlen = struct.unpack(">H", buf[ idx+8 : idx+10])[0]
			#logger.debug("data length: %d" % dlen)
			#logger.debug("data: %s" % buf[ off : idx+1+10+dlen])
			a = DNS.AddRecord( buf[ off : idx+1+10+dlen] )
			#logger.debug("Additional Record: %s" % a)
			add_req.append(a)
			off += len(a)
			addreq_amount -= 1

		self.addrecords.extend(add_req)
		#logger.debug("dns: %s" % self)
