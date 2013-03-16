"""Domain Name System."""

from .. import pypacker

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

class DNS(pypacker.Packet):
	__hdr__ = (
		("id", "H", 0),
		("flags", "H", DNS_RD),
		# TODO: update on chnages
		("questions_amount", "H", 0),
		("answers_amount", "H", 0),
		("authrr_amount", "H", 0),
		("addrr_amount", "H", 0)
		)

	# lazy init of queries, answers etc
	def __get_queries(self):
		if not hasattr(self, "_queries"):
			tl = pypacker.TriggerList()
			self._insert_headerfield(6, "_queries", "", tl)
		return self._queries
	queries = property(__get_queries)

	def __get_answers(self):
		if not hasattr(self, "_answers"):
			tl = pypacker.TriggerList()
			self._insert_headerfield(7, "_answers", "", tl)
		return self._answers
	answers = property(__get_answers)

	def __get_auths(self):
		if not hasattr(self, "_auths"):
			tl = pypacker.TriggerList()
			self._insert_headerfield(8, "_auths", "", tl)
		return self._auths
	auths = property(__get_auths)

	def __get_addrequests(self):
		if not hasattr(self, "_addrequests"):
			tl = pypacker.TriggerList()
			self._insert_headerfield(8, "_addrequests", "", tl)
		return self._addrequests
	addrequests = property(__get_addrequests)

	class Query(pypacker.Packet):
		"""DNS question."""
		__hdr__ = (
			# name has to be added separately
			("name", "", b""),
			("type", "H", DNS_A),
			("cls", "H", DNS_IN)
			)

		def _unpack(self, buf):
			# set format
			idx = buf.find(b"\x00")
			#logger.debug("trying to set name: %s" % buf[:idx+1])
			self.name = buf[:idx+1]
			pypacker.Packet._unpack(self, buf)

	class Answer(pypacker.Packet):
		"""DNS resource record."""
		__hdr__ = (
			("name", "H", 0),
			("type", "H", DNS_A),
			("cls", "H", DNS_IN),
			("ttl", "I", 0),
			("dlen", "H", 4),
			# address has to be added separately
			("address", "", b"")
			)

		def _unpack(self, buf):
			# set format
			self.address = buf[12:]
			pypacker.Packet._unpack(self, buf)

	class Auth(pypacker.Packet):
		"""Auth data."""
		__hdr__ = (
			("name", "H", 0),
			("type", "H", 0),
			("cls", "H", 0),
			("ttl", "I", 0),
			("dlen", "H", 0),
			# name has to be added separately
			("name", "", b""),
			# mailbox has to be added separately
			("mailbox", "", b""),
			("pserver", "H", 0),
			("mbox", "H", 0),
			("serial", "H", 0),
			("refresh", "H", 0),
			("retry", "H", 0),
			("expire", "H", 0),
			("minttl", "H", 0),
			)

		def _unpack(self, buf):
			# set format
			# find server name by 0-termination
			idx = buf.find(b"\x00", 12)
			self.name = buf[ 12 : idx+1]
			self.mailbox = buf[ idx+1 : -14 ]
			pypacker.Packet._unpack(self, buf)


	class AddReq(pypacker.Packet):
		"""DNS additional request."""
		__hdr__ = (
			# name has to be added separately
			("name", "", b""),
			("type", "H", 0),
			("plen", "H", 0),
			("rcode", "B", 0),
			("edns", "B", 0),
			("z", "H", 0),
			("dlen", "H", 0),
			)

		def _unpack(self, buf):
			# set format
			idx = buf.find(b"\x00")
			self.name = buf[:idx+1]
			pypacker.Packet._unpack(self, buf)


	def _unpack(self, buf):
		# unpack basic data to get things done
		pypacker.Packet._unpack(self, buf[:12])
		off = 12

		#
		# parse questions
		#
		quests_amount = self.questions_amount
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

		queries_tl = pypacker.TriggerList(questions)
		self._add_headerfield("_queries", "", queries_tl)

		#
		# parse answers
		#
		ans_amount = self.answers_amount
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

		answers_tl = pypacker.TriggerList(answers)
		self._add_headerfield("_answers", "", answers_tl)


		#
		# parse authorative servers
		#
		authserver_amount = self.authrr_amount
		auth_server = []

		#logger.debug(">>> parsing authorative servers: %d" % authserver_amount)
		while authserver_amount > 0:
			dlen = struct.unpack(">H", buf[off+10 : off+12])[0]
			a = DNS.Auth( buf[off : off + 12 + dlen])

			#logger.debug("Auth server: %s" % a)
			auth_server.append(a)
			off += len(a)
			authserver_amount -= 1

		add_req_tl = pypacker.TriggerList(auth_server)
		self._add_headerfield("_auths", "", add_req_tl)

		#
		# parse additional requests
		#
		addreq_amount = self.addrr_amount
		add_req = []

		#logger.debug(">>> parsing additional requests: %d" % addreq_amount)
		while addreq_amount > 0:
			# find name by 0-termination
			idx = buf.find(b"\x00", off)
			dlen = struct.unpack(">H", buf[ idx+8 : idx+10])[0]
			a = DNS.AddReq( buf[ off : idx+1+10+dlen] )
			#logger.debug("Additional Request: %s" % a)
			add_req.append(a)
			off += len(a)
			addreq_amount -= 1

		add_req_tl = pypacker.TriggerList(add_req)
		self._add_headerfield("_addrequests", "", add_req_tl)
		#logger.debug("dns: %s" % self)

		# update cache
		pypacker.Packet._unpack(self, buf)
