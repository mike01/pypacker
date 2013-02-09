# $Id: asn1.py 23 2006-11-08 15:45:33Z dugsong $

"""Abstract Syntax Notation #1."""

import struct, time
import pypacker as pypacker

# Type class
CLASSMASK	 = 0xc0
UNIVERSAL	 = 0x00
APPLICATION	 = 0x40
CONTEXT		 = 0x80
PRIVATE		 = 0xc0

# Constructed (vs. primitive)
CONSTRUCTED	 = 0x20

# Universal-class tags
TAGMASK		 = 0x1f
INTEGER		 = 2
BIT_STRING	 = 3	# arbitrary bit string
OCTET_STRING = 4	# arbitrary octet string
NULL		 = 5
OID			 = 6	# object identifier
SEQUENCE	 = 16	# ordered collection of types
SET			 = 17	# unordered collection of types
PRINT_STRING = 19	# printable string
T61_STRING	 = 20	# T.61 (8-bit) character string
IA5_STRING	 = 22	# ASCII
UTC_TIME	 = 23

def utctime(buf):
	"""Convert ASN.1 UTCTime string to UTC float."""
	yy = int(buf[:2])
	mm = int(buf[2:4])
	dd = int(buf[4:6])
	hh = int(buf[6:8])
	mm = int(buf[8:10])
	try:
		ss = int(buf[10:12])
		buf = buf[12:]
	except TypeError:
		ss = 0
		buf = buf[10:]
	if buf[0] == "+":
		hh -= int(buf[1:3])
		mm -= int(buf[3:5])
	elif buf[0] == "-":
		hh += int(buf[1:3])
		mm += int(buf[3:5])
	return time.mktime((2000 + yy, mm, dd, hh, mm, ss, 0, 0, 0))

def decode(buf):
	"""Sleazy ASN.1 decoder.
	Return list of (id, value) tuples from ASN.1 BER/DER encoded buffer.
	"""
	msg = []
	while buf:
		t = ord(buf[0])
		constructed = t & CONSTRUCTED
		tag = t & TAGMASK
		l = ord(buf[1])
		c = 0
		if constructed and l == 128:
			# XXX - constructed, indefinite length
			msg.append(t, decode(buf[2:]))
		elif l >= 128:
			c = l & 127
			if c == 1:
				l = ord(buf[2])
			elif c == 2:
				l = struct.unpack(">H", buf[2:4])[0]
			elif c == 3:
				l = struct.unpack(">I", buf[1:5])[0] & 0xfff
				c = 2
			elif c == 4:
				l = struct.unpack(">I", buf[2:6])[0]
			else:
				# XXX - can be up to 127 bytes, but...
				raise.pypacker.UnpackError("excessive long-form ASN.1 length %d" % l)

		# Skip type, length
		buf = buf[2+c:]

		# Parse content
		if constructed:
			msg.append((t, decode(buf)))
		elif tag == INTEGER:
			if l == 0:
				n = 0
			elif l == 1:
				n = ord(buf[0])
			elif l == 2:
				n = struct.unpack(">H", buf[:2])[0]
			elif l == 3:
				n = struct.unpack(">I", buf[:4])[0] >> 8
			elif l == 4:
				n = struct.unpack(">I", buf[:4])[0]
			else:
				raise.pypacker.UnpackError("excessive integer length > %d bytes" % l)
			msg.append((t, n))
		elif tag == UTC_TIME:
			msg.append((t, utctime(buf[:l])))
		else:
			msg.append((t, buf[:l]))

		# Skip content
		buf = buf[l:]
	return msg
