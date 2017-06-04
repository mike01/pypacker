"""
Secure Sockets Layer / Transport Layer Security.
"""
import logging
import struct
#
# Note from April 2011: cde...@gmail.com added code that parses SSL3/TLS messages
# more in depth.
#
# Jul 2012: afleenor@google.com modified and extended SSL support further.
#

from pypacker import pypacker, triggerlist

# avoid references for performance reasons
unpack_H = struct.Struct(">H").unpack

logger = logging.getLogger("pypacker")

# SSLv3/TLS versions
SSL3_V	= 0x0300
TLS1_V	= 0x0301
TLS11_V = 0x0302
TLS12_V = 0x0303

ssl3_versions_str = {
	SSL3_V	: "SSL3",
	TLS1_V	: "TLS 1.0",
	TLS11_V	: "TLS 1.1",
	TLS12_V	: "TLS 1.2"
}


# Alert levels
SSL3_AD_WARNING	 = 1
SSL3_AD_FATAL	 = 2
alert_level_str = {
	SSL3_AD_WARNING	: "SSL3_AD_WARNING",
	SSL3_AD_FATAL	: "SSL3_AD_FATAL"
}

# SSL3 alert descriptions
SSL3_AD_CLOSE_NOTIFY			= 0
SSL3_AD_UNEXPECTED_MESSAGE		= 10		# fatal
SSL3_AD_BAD_RECORD_MAC			= 20		# fatal
SSL3_AD_DECOMPRESSION_FAILURE		= 30		# fatal
SSL3_AD_HANDSHAKE_FAILURE		= 40		# fatal
SSL3_AD_NO_CERTIFICATE			= 41
SSL3_AD_BAD_CERTIFICATE			= 42
SSL3_AD_UNSUPPORTED_CERTIFICATE		= 43
SSL3_AD_CERTIFICATE_REVOKED		= 44
SSL3_AD_CERTIFICATE_EXPIRED		= 45
SSL3_AD_CERTIFICATE_UNKNOWN		= 46
SSL3_AD_ILLEGAL_PARAMETER		= 47		# fatal

# TLS1 alert descriptions
TLS1_AD_DECRYPTION_FAILED		= 21
TLS1_AD_RECORD_OVERFLOW			= 22
TLS1_AD_UNKNOWN_CA			= 48		# fatal
TLS1_AD_ACCESS_DENIED			= 49		# fatal
TLS1_AD_DECODE_ERROR			= 50		# fatal
TLS1_AD_DECRYPT_ERROR			= 51
TLS1_AD_EXPORT_RESTRICTION		= 60		# fatal
TLS1_AD_PROTOCOL_VERSION		= 70		# fatal
TLS1_AD_INSUFFICIENT_SECURITY		= 71		# fatal
TLS1_AD_INTERNAL_ERROR			= 80		# fatal
TLS1_AD_USER_CANCELLED			= 90
TLS1_AD_NO_RENEGOTIATION		= 100
# /* codes 110-114 are from RFC3546 */
TLS1_AD_UNSUPPORTED_EXTENSION		= 110
TLS1_AD_CERTIFICATE_UNOBTAINABLE	= 111
TLS1_AD_UNRECOGNIZED_NAME		= 112
TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE = 113
TLS1_AD_BAD_CERTIFICATE_HASH_VALUE 	= 114
TLS1_AD_UNKNOWN_PSK_IDENTITY		= 115		# fatal


# Mapping alert types to strings
alert_description_str = {
	SSL3_AD_CLOSE_NOTIFY			: "SSL3_AD_CLOSE_NOTIFY",
	SSL3_AD_UNEXPECTED_MESSAGE		: "SSL3_AD_UNEXPECTED_MESSAGE",
	SSL3_AD_BAD_RECORD_MAC			: "SSL3_AD_BAD_RECORD_MAC",
	SSL3_AD_DECOMPRESSION_FAILURE		: "SSL3_AD_DECOMPRESSION_FAILURE",
	SSL3_AD_HANDSHAKE_FAILURE		: "SSL3_AD_HANDSHAKE_FAILURE",
	SSL3_AD_NO_CERTIFICATE			: "SSL3_AD_NO_CERTIFICATE",
	SSL3_AD_BAD_CERTIFICATE			: "SSL3_AD_BAD_CERTIFICATE",
	SSL3_AD_UNSUPPORTED_CERTIFICATE		: "SSL3_AD_UNSUPPORTED_CERTIFICATE",
	SSL3_AD_CERTIFICATE_REVOKED		: "SSL3_AD_CERTIFICATE_REVOKED",
	SSL3_AD_CERTIFICATE_EXPIRED		: "SSL3_AD_CERTIFICATE_EXPIRED",
	SSL3_AD_CERTIFICATE_UNKNOWN		: "SSL3_AD_CERTIFICATE_UNKNOWN",
	SSL3_AD_ILLEGAL_PARAMETER		: "SSL3_AD_ILLEGAL_PARAMETER",
	TLS1_AD_DECRYPTION_FAILED		: "TLS1_AD_DECRYPTION_FAILED",
	TLS1_AD_RECORD_OVERFLOW			: "TLS1_AD_RECORD_OVERFLOW",
	TLS1_AD_UNKNOWN_CA			: "TLS1_AD_UNKNOWN_CA",
	TLS1_AD_ACCESS_DENIED			: "TLS1_AD_ACCESS_DENIED",
	TLS1_AD_DECODE_ERROR			: "TLS1_AD_DECODE_ERROR",
	TLS1_AD_DECRYPT_ERROR			: "TLS1_AD_DECRYPT_ERROR",
	TLS1_AD_EXPORT_RESTRICTION		: "TLS1_AD_EXPORT_RESTRICTION",
	TLS1_AD_PROTOCOL_VERSION		: "TLS1_AD_PROTOCOL_VERSION",
	TLS1_AD_INSUFFICIENT_SECURITY		: "TLS1_AD_INSUFFICIENT_SECURITY",
	TLS1_AD_INTERNAL_ERROR			: "TLS1_AD_INTERNAL_ERROR",
	TLS1_AD_USER_CANCELLED			: "TLS1_AD_USER_CANCELLED",
	TLS1_AD_NO_RENEGOTIATION		: "TLS1_AD_NO_RENEGOTIATION",
	TLS1_AD_UNSUPPORTED_EXTENSION		: "TLS1_AD_UNSUPPORTED_EXTENSION",
	TLS1_AD_CERTIFICATE_UNOBTAINABLE	: "TLS1_AD_CERTIFICATE_UNOBTAINABLE",
	TLS1_AD_UNRECOGNIZED_NAME		: "TLS1_AD_UNRECOGNIZED_NAME",
	TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE	: "TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE",
	TLS1_AD_BAD_CERTIFICATE_HASH_VALUE	: "TLS1_AD_BAD_CERTIFICATE_HASH_VALUE",
	TLS1_AD_UNKNOWN_PSK_IDENTITY		: "TLS1_AD_UNKNOWN_PSK_IDENTITY"
}


# Record types
RECORD_TLS_CHG_CIPHERSPEC	= 20
RECORD_TLS_ALERT		= 21
RECORD_TLS_HANDSHAKE		= 22
RECORD_TLS_HANDSHAKE_HELLO		= 22 * 10
RECORD_TLS_HANDSHAKE_DATA		= 22 * 100
RECORD_TLS_APPDATA		= 23

# Handshake types
HNDS_HELLO_REQ			= 0
HNDS_HELLO_CLIENT		= 1
HNDS_HELLO_SERVER		= 2
HNDS_CERTIFICATE		= 11
HNDS_SERVER_KEY_EXCHANGE	= 12
HNDS_CERTIFICATE_REQ		= 13
HNDS_SERVER_HELLO_DONE		= 14
HNDS_CERT_VERIFIY		= 15
HNDS_CLIENT_KEY_EXCHANGE	= 16
HNDS_FINISHED			= 20


class SSL(pypacker.Packet):
	__hdr__ = (
		("records", None, triggerlist.TriggerList),
	)

	def _dissect(self, buf):
		# logger.debug("parsing SSL")
		# parse all records out of message
		# possible types are Client/Sevrer Hello, Change Cipher Spec etc.
		records = []
		offset = 0
		dlen = len(buf)
		self._fragmented = False

		# records is the only header so it's ok to avoid lazy dissecting
		while offset < dlen:
			record_len = unpack_H(buf[offset + 3: offset + 5])[0]

			if offset + record_len > dlen:
				# TODO: handle fragmentation
				# idea: design _dissect() in a way which allows continuation
				# at any given start-point, eg start of a record-entry
				# Later call to a "reassemble([pkt1, pkt2])" can re-use
				# _dissect to add all other records
				logger.info("possible fragmentation found")
				self._fragmented = True
				# non-parsed data becomes body content
				dlen = offset
				break
			record = Record(buf[offset: offset + 5 + record_len])
			records.append(record)
			offset += len(record)
		# logger.debug("adding records, dlen/offset at end: %d %d" % (dlen, offset))
		self.records.extend(records)
		return dlen


class Extension(pypacker.Packet):
	"""
	Handshake protocol extension
	"""
	__hdr__ = (
		("type", "H", 0),
		("len", "H", 0)
	)


#
# Record contents
#
class HandshakeHello(pypacker.Packet):

	__hdr__ = (
		("type", "B", 0),
		# can't use struct here but:
		# int.from_bytes(len, "big")
		("len", "3s", b"\x00" * 3),
		("tlsversion", "H", 0x0301),
		("random", "32s", b"\x00" * 32),
		("sid_len", "B", 32),
		# variable length
		("sid", None, b"A" * 32),
		("ciphersuite", "H", 0x0035),
		("compression", "B", 0),
		("ext_len", "H", 0x0000),
		("extensions", None, triggerlist.TriggerList),
	)

	@staticmethod
	def __parse_extension(buf):
		extensions = []
		offset = 0
		buflen = len(buf)

		while offset < buflen:
			ext_content_len = unpack_H(buf[offset + 2: offset + 4])[0]
			ext_len = 4 + ext_content_len
			extensions.append(Extension(buf[offset: offset + ext_len]))
			offset += ext_len

		return extensions

	def _dissect(self, buf):
		sid_len = buf[38]
		offset_extlen = 38 + sid_len + 3
		# ext_len = unpack_H(buf[offset_extlen : offset_extlen+2])
		self._init_triggerlist("extensions", buf[offset_extlen + 2:], self.__parse_extension)


class HandshakeData(pypacker.Packet):
	pass


class ChangeCipherSpec(pypacker.Packet):
	pass


class ApplicationData(pypacker.Packet):
	pass


class Record(pypacker.Packet):
	"""
	SSLv3 or TLSv1+ Record layer.
	"""

	__hdr__ = (
		("type", "B", 0),
		("version", "H", 0),
		("len", "H", 0),
	)

	__handler__ = {
		RECORD_TLS_CHG_CIPHERSPEC: ChangeCipherSpec,
		RECORD_TLS_HANDSHAKE_HELLO: HandshakeHello,
		RECORD_TLS_HANDSHAKE_DATA: HandshakeData,
		RECORD_TLS_APPDATA: ApplicationData
	}

	def __dissect(self, buf):
		# logger.debug("parsing TLSRecord")
		# TODO: check for different handshages
		self._init_handler(buf[0], buf[5:])
		return 5
