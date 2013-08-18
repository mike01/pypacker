"""AOL Instant Messenger."""

from .. import pypacker
import struct

# OSCAR: http://iserverd1.khstu.ru/oscar/

class FLAP(pypacker.Packet):
	__hdr__ = (
		("ast", "B", 0x2a),	# "*"
		("type", "B", 0),
		("seq", "H", 0),
		("len", "H", 0)
	)

class SNAC(pypacker.Packet):
	__hdr__ = (
		("family", "H", 0),
		("subtype", "H", 0),
		("flags", "H", 0),
		("reqid", "I", 0)
		)

def tlv(buf):
	n = 4
	try:
		t, l = struct.unpack(">HH", buf[:n])
	except struct.error:
		raise pypacker.UnpackError
	v = buf[n:n+l]
	if len(v) < l:
		raise pypacker.NeedData
	buf = buf[n+l:]
	return (t,l,v, buf)

# TOC 1.0: http://jamwt.com/Py-TOC/PROTOCOL

# TOC 2.0: http://www.firestuff.org/projects/firetalk/doc/toc2.txt

