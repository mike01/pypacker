"""ITU-T H.225.0 Call Signaling."""

from .. import pypacker
import struct

# H225 Call Signaling
# 
# Call messages and information elements (IEs) are defined by Q.931:
# http://cvsup.de.openbsd.org/historic/comp/doc/standards/itu/Q/Q.931.ps.gz
#
# The User-to-User IEs of H225 are encoded by PER of ASN.1.

# Call Establishment Messages
ALERTING				= 1
CALL_PROCEEDING				= 2
CONNECT					= 7
CONNECT_ACKNOWLEDGE			= 15
PROGRESS				= 3
SETUP					= 5
SETUP_ACKNOWLEDGE			= 13

# Call Information Phase Messages
RESUME					= 38
RESUME_ACKNOWLEDGE			= 46
RESUME_REJECT				= 34
SUSPEND					= 37
SUSPEND_ACKNOWLEDGE			= 45
SUSPEND_REJECT				= 33
USER_INFORMATION			= 32

# Call Clearing Messages
DISCONNECT				= 69
RELEASE					= 77
RELEASE_COMPLETE			= 90
RESTART					= 70
RESTART_ACKNOWLEDGE			= 78

# Miscellaneous Messages
SEGMENT					= 96
CONGESTION_CONTROL			= 121
INFORMATION				= 123
NOTIFY					= 110
STATUS					= 125
STATUS_ENQUIRY				= 117

# Type 1 Single Octet Information Element IDs
RESERVED				= 128
SHIFT					= 144
CONGESTION_LEVEL			= 176
REPEAT_INDICATOR			= 208

# Type 2 Single Octet Information Element IDs
MORE_DATA				= 160
SENDING_COMPLETE			= 161

# Variable Length Information Element IDs 
SEGMENTED_MESSAGE			= 0
BEARER_CAPABILITY			= 4
CAUSE					= 8
CALL_IDENTITY				= 16
CALL_STATE				= 20
CHANNEL_IDENTIFICATION			= 24
PROGRESS_INDICATOR			= 30
NETWORK_SPECIFIC_FACILITIES		= 32
NOTIFICATION_INDICATOR			= 39
DISPLAY					= 40
DATE_TIME				= 41
KEYPAD_FACILITY				= 44
SIGNAL					= 52
INFORMATION_RATE			= 64
END_TO_END_TRANSIT_DELAY		= 66
TRANSIT_DELAY_SELECTION_AND_INDICATION	= 67
PACKET_LAYER_BINARY_PARAMETERS		= 68
PACKET_LAYER_WINDOW_SIZE		= 69
PACKET_SIZE				= 70
CLOSED_USER_GROUP			= 71
REVERSE_CHARGE_INDICATION		= 74
CALLING_PARTY_NUMBER			= 108
CALLING_PARTY_SUBADDRESS		= 109
CALLED_PARTY_NUMBER			= 112
CALLED_PARTY_SUBADDRESS			= 113
REDIRECTING_NUMBER			= 116
TRANSIT_NETWORK_SELECTION		= 120
RESTART_INDICATOR			= 121
LOW_LAYER_COMPATIBILITY			= 124
HIGH_LAYER_COMPATIBILITY		= 125
USER_TO_USER				= 126
ESCAPE_FOR_EXTENSION			= 127

class H225(pypacker.Packet):
	__hdr__ = (
		("proto", "B", 8),
		("ref_len", "B", 2)
		)

	def unpack(self, buf):
		# TPKT header
		self.tpkt = tpkt.TPKT(buf)
		if self.tpkt.v != 3: 
			raise pypacker.UnpackError("invalid TPKT version")
		if self.tpkt.rsvd != 0:
			raise pypacker.UnpackError("invalid TPKT reserved value")
		n = self.tpkt.len - self.tpkt._hdr_len
		if n > len(self.tpkt.data):
			raise pypacker.UnpackError("invalid TPKT length")
		buf = self.tpkt.data

		# Q.931 payload
		pypacker.Packet.unpack(self, buf)
		buf = buf[self._hdr_len:]
		self.ref_val = buf[:self.ref_len]
		buf = buf[self.ref_len:]
		self.type = struct.unpack("B", buf[:1])[0]
		buf = buf[1:]

		# Information Elements
		l = []
		while buf:
			ie = self.IE(buf)
			l.append(ie)
			buf = buf[len(ie):]
		self.data = l

	def __len__(self):
		return self.tpkt._hdr_len + \
			self._hdr_len + \
			sum(map(len, self.data))

	def __str__(self):
		return self.tpkt.pack_hdr() + \
			self.pack_hdr() + \
			self.ref_val + \
			struct.pack("B", self.type) + \
			"".join(map(str, self.data))

	class IE(pypacker.Packet):
		__hdr__ = (
			("type", "B", 0),
			)

		def unpack(self, buf):
			pypacker.Packet.unpack(self, buf)
			buf = buf[self._hdr_len:]

			# single-byte IE
			if self.type & 0x80:
				self.len = 0
				self.data = None
			# multi-byte IE
			else:
				# special PER-encoded UUIE
				if self.type == USER_TO_USER:
					self.len = struct.unpack(">H", buf[:2])[0]
					buf = buf[2:]
				# normal TLV-like IE
				else:
					self.len = struct.unpack("B", buf[:1])[0]
					buf = buf[1:]
				self.data = buf[:self.len]

		def __len__(self):
			if self.type & 0x80:
				n = 0
			else:
				if self.type == USER_TO_USER:
					n = 2
				else:
					n = 1
			return self._hdr_len + self.len + n

		def __str__(self):
			if self.type & 0x80:
				length_str = None
			else:
				if self.type == USER_TO_USER:
					length_str = struct.pack(">H", self.len) 
				else:
					length_str = struct.pack("B", self.len)
			return struct.pack("B", self.type) + length_str + self.data
