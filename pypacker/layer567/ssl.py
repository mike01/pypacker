"""Secure Sockets Layer / Transport Layer Security."""
#
# Note from April 2011: cde...@gmail.com added code that parses SSL3/TLS messages more in depth.
#
# Jul 2012: afleenor@google.com modified and extended SSL support further.
#

from .. import pypacker
from .. import triggerlist
from . import ssl_ciphersuites

import logging
import struct

logger = logging.getLogger("pypacker")

class SSL2(pypacker.Packet):
	__hdr__ = (
		("len", "H", 0),
		("msg", "s", ""),
		("pad", "s", ""),
		)
	def _dissect(self, buf):
		pypacker.Packet._unpack(self, buf)
		if self.len & 0x8000:
			n = self.len = self.len & 0x7FFF
			self.msg, self.data = self.data[:n], self.data[n:]
		else:
			n = self.len = self.len & 0x3FFF
			padlen = ord(self.data[0])
			self.msg = self.data[1:1+n]
			self.pad = self.data[1+n:1+n+padlen]
			self.data = self.data[1+n+padlen:]


# SSLv3/TLS versions
SSL3_V	= 0x0300
TLS1_V	= 0x0301
TLS11_V = 0x0302
TLS12_V = 0x0303

ssl3_versions_str =	 {
	SSL3_V:	 "SSL3",
	TLS1_V:	 "TLS 1.0",
	TLS11_V: "TLS 1.1",
	TLS12_V: "TLS 1.2"
}

SSL3_VERSION_BYTES = set(("\x03\x00", "\x03\x01", "\x03\x02", "\x03\x03"))


# Alert levels
SSL3_AD_WARNING	 = 1
SSL3_AD_FATAL	 = 2
alert_level_str = {
	SSL3_AD_WARNING:	"SSL3_AD_WARNING",
	SSL3_AD_FATAL:		"SSL3_AD_FATAL"
}

# SSL3 alert descriptions
SSL3_AD_CLOSE_NOTIFY			= 0
SSL3_AD_UNEXPECTED_MESSAGE		= 10	# fatal
SSL3_AD_BAD_RECORD_MAC			= 20	# fatal
SSL3_AD_DECOMPRESSION_FAILURE		= 30	# fatal
SSL3_AD_HANDSHAKE_FAILURE		= 40	# fatal
SSL3_AD_NO_CERTIFICATE			= 41
SSL3_AD_BAD_CERTIFICATE			= 42
SSL3_AD_UNSUPPORTED_CERTIFICATE		= 43
SSL3_AD_CERTIFICATE_REVOKED		= 44
SSL3_AD_CERTIFICATE_EXPIRED		= 45
SSL3_AD_CERTIFICATE_UNKNOWN		= 46
SSL3_AD_ILLEGAL_PARAMETER		= 47	# fatal

# TLS1 alert descriptions
TLS1_AD_DECRYPTION_FAILED		= 21
TLS1_AD_RECORD_OVERFLOW			= 22
TLS1_AD_UNKNOWN_CA			= 48	# fatal
TLS1_AD_ACCESS_DENIED			= 49	# fatal
TLS1_AD_DECODE_ERROR			= 50	# fatal
TLS1_AD_DECRYPT_ERROR			= 51
TLS1_AD_EXPORT_RESTRICTION		= 60	# fatal
TLS1_AD_PROTOCOL_VERSION		= 70	# fatal
TLS1_AD_INSUFFICIENT_SECURITY		= 71	# fatal
TLS1_AD_INTERNAL_ERROR			= 80	# fatal
TLS1_AD_USER_CANCELLED			= 90
TLS1_AD_NO_RENEGOTIATION		= 100
#/* codes 110-114 are from RFC3546 */
TLS1_AD_UNSUPPORTED_EXTENSION		= 110
TLS1_AD_CERTIFICATE_UNOBTAINABLE	= 111
TLS1_AD_UNRECOGNIZED_NAME		= 112
TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE = 113
TLS1_AD_BAD_CERTIFICATE_HASH_VALUE 	= 114
TLS1_AD_UNKNOWN_PSK_IDENTITY		= 115	# fatal


# Mapping alert types to strings
alert_description_str = {
	SSL3_AD_CLOSE_NOTIFY:			"SSL3_AD_CLOSE_NOTIFY",
	SSL3_AD_UNEXPECTED_MESSAGE:		"SSL3_AD_UNEXPECTED_MESSAGE",
	SSL3_AD_BAD_RECORD_MAC:			"SSL3_AD_BAD_RECORD_MAC",
	SSL3_AD_DECOMPRESSION_FAILURE:		"SSL3_AD_DECOMPRESSION_FAILURE",
	SSL3_AD_HANDSHAKE_FAILURE:		"SSL3_AD_HANDSHAKE_FAILURE",
	SSL3_AD_NO_CERTIFICATE:			"SSL3_AD_NO_CERTIFICATE",
	SSL3_AD_BAD_CERTIFICATE:		"SSL3_AD_BAD_CERTIFICATE",
	SSL3_AD_UNSUPPORTED_CERTIFICATE:	"SSL3_AD_UNSUPPORTED_CERTIFICATE",
	SSL3_AD_CERTIFICATE_REVOKED:		"SSL3_AD_CERTIFICATE_REVOKED",
	SSL3_AD_CERTIFICATE_EXPIRED:		"SSL3_AD_CERTIFICATE_EXPIRED",
	SSL3_AD_CERTIFICATE_UNKNOWN:		"SSL3_AD_CERTIFICATE_UNKNOWN",
	SSL3_AD_ILLEGAL_PARAMETER:		"SSL3_AD_ILLEGAL_PARAMETER",
	TLS1_AD_DECRYPTION_FAILED:		"TLS1_AD_DECRYPTION_FAILED",
	TLS1_AD_RECORD_OVERFLOW:		"TLS1_AD_RECORD_OVERFLOW",
	TLS1_AD_UNKNOWN_CA:			"TLS1_AD_UNKNOWN_CA",
	TLS1_AD_ACCESS_DENIED:			"TLS1_AD_ACCESS_DENIED",
	TLS1_AD_DECODE_ERROR:			"TLS1_AD_DECODE_ERROR",
	TLS1_AD_DECRYPT_ERROR:			"TLS1_AD_DECRYPT_ERROR",
	TLS1_AD_EXPORT_RESTRICTION:		"TLS1_AD_EXPORT_RESTRICTION",
	TLS1_AD_PROTOCOL_VERSION:		"TLS1_AD_PROTOCOL_VERSION",
	TLS1_AD_INSUFFICIENT_SECURITY:		"TLS1_AD_INSUFFICIENT_SECURITY",
	TLS1_AD_INTERNAL_ERROR:			"TLS1_AD_INTERNAL_ERROR",
	TLS1_AD_USER_CANCELLED:			"TLS1_AD_USER_CANCELLED",
	TLS1_AD_NO_RENEGOTIATION:		"TLS1_AD_NO_RENEGOTIATION",
	TLS1_AD_UNSUPPORTED_EXTENSION:		"TLS1_AD_UNSUPPORTED_EXTENSION",
	TLS1_AD_CERTIFICATE_UNOBTAINABLE:	"TLS1_AD_CERTIFICATE_UNOBTAINABLE",
	TLS1_AD_UNRECOGNIZED_NAME:		"TLS1_AD_UNRECOGNIZED_NAME",
	TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE:"TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE",
	TLS1_AD_BAD_CERTIFICATE_HASH_VALUE:	"TLS1_AD_BAD_CERTIFICATE_HASH_VALUE",
	TLS1_AD_UNKNOWN_PSK_IDENTITY:		"TLS1_AD_UNKNOWN_PSK_IDENTITY"
}


# Record types
RECORD_TLS_CHG_CIPHERSPEC	= 20
RECORD_TLS_ALERT		= 21
RECORD_TLS_HANDSHAKE		= 22
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
		#logger.debug("parsing SSL")
		# parse all records out of message
		# possible types are Client/Sevrer Hello, Change Cipher Spec etc.
		records = []
		off = 0
		dlen = len(buf)

		while off < dlen:
			rlen = struct.unpack(">H", buf[off+3 : off+5])[0]
			record = TLSRecord(buf[off : off+5+rlen])
			records.append(record)
			off += len(record)

		self.records.extend(records)


class TLSRecord(pypacker.Packet):
	"""
	SSLv3 or TLSv1+ packet.

	In addition to the fields specified in the header, there are
	compressed and decrypted fields, indicating whether, in the language
	of the spec, this is a TLSPlaintext, TLSCompressed, or
	TLSCiphertext. The application will have to figure out when it's
	appropriate to change these values.
	"""

	__hdr__ = (
		("type", "B", 0),
		("version", "H", 0),
		("len", "H", 0),
		)

	def _dissect(self, buf):
		#logger.debug("parsing TLSRecord")
		# client or server hello
		if buf[0] == RECORD_TLS_HANDSHAKE:
			hndl = TLSHello(buf[5:])
			self._set_bodyhandler(hndl)

	#def __init__(self, *args, **kwargs):
	#	# assume plaintext unless specified otherwise in arguments
	#	self.compressed = kwargs.pop("compressed", False)
	#	self.encrypted = kwargs.pop("encrypted", False)
	#	# parent constructor
	#	pypacker.Packet.__init__(self, *args, **kwargs)
	#	# make sure length and data are consistent
	#	self.length = len(self.data)

	#def unpack(self, buf):
	#	pypacker.Packet.unpack(self, buf)
	#	header_length = self.__hdr_len__
	#	self.data = buf[header_length:header_length+self.length]
	#	# make sure buffer was long enough
	#	if len(self.data) != self.length:
	#		raise pypacker.NeedData("TLSRecord data was too short.")
	#	# assume compressed and encrypted when it"s been parsed from
	#	# raw data
	#	self.compressed = True
	#	self.encrypted = True


#
# Record contents
#
class TLSHello(pypacker.Packet):
	"""
	Client and server hello.
	"""
	__hdr__ = (
		("type", "B", 0),
		# can't use struct here but:
		# int.from_bytes(len, "big")
		("len", "3s", 0),
		("version", "H", 0x0301),
		("random", "32s", b"\x00"*32),
		("sid_len", "B", 32),
	)	# the rest is variable-length and has to be done manually

	def _dissect(self, buf):
		#logger.debug("parsing TLSHello")
		pypacker.Packet._unpack(self, buf)
		# for now everything following is just data
		# TODO: parse ciphers, compression, extensions
		return

		# now session, cipher suites, extensions are in self.data
		self.session_id, pointer = parse_variable_array(self.data, 1)
#		 print "pointer",pointer
		# handle ciphersuites
		ciphersuites, parsed = parse_variable_array(self.data[pointer:], 2)
		pointer += parsed
		self.num_ciphersuites = len(ciphersuites) / 2
		# check len(ciphersuites) % 2 == 0 ?
		# compression methods
		compression_methods, parsed = parse_variable_array(
			self.data[pointer:], 1)
		pointer += parsed
		self.num_compression_methods = parsed - 1
		self.compression_methods = list(map(ord, compression_methods))
		# extensions

# struct format strings for parsing buffer lengths
# don't forget, you have to pad a 3-byte value with \x00
_SIZE_FORMATS = ["!B", "!H", "!I", "!I"]

def parse_variable_array(buf, lenbytes):
	"""
	Parse an array described using the "Type name<x..y>" syntax from the spec

	Read a length at the start of buf, and returns that many bytes
	after, in a tuple with the TOTAL bytes consumed (including the size). This
	does not check that the array is the right length for any given datatype.
	"""
	# first have to figure out how to parse length
	assert lenbytes <= 4  # pretty sure 4 is impossible, too
	size_format = _SIZE_FORMATS[lenbytes - 1]
	padding = "\x00" if lenbytes == 3 else ""
	# read off the length
	size = struct.unpack(size_format, padding + buf[:lenbytes])[0]
	# read the actual data
	data = buf[lenbytes:lenbytes + size]
	# if len(data) != size: insufficient data
	return data, size + lenbytes


