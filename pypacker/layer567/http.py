"""Hypertext Transfer Protocol.
In contrast to low-layer protocols HTTP-headers are stored via lists
like [(headername,headervalue), ...] in "header" inclusive reqest/response line.
This will be the exact same header but without ": ".
"""

from .. import pypacker

import re
import logging

logger = logging.getLogger("pypacker")

class HTTP(pypacker.Packet):
	__hdr__ = (
		#("h", "1s", ""),	# avoid optimazation
		)

	"""Hypertext Transfer Protocol headers + body."""
	__req_methods = (
		"GET", "PUT", "ICY",
		"COPY", "HEAD", "LOCK", "MOVE", "POLL", "POST",
		"BCOPY", "BMOVE", "MKCOL", "TRACE", "LABEL", "MERGE",
		"DELETE", "SEARCH", "UNLOCK", "REPORT", "UPDATE", "NOTIFY",
		"BDELETE", "CONNECT", "OPTIONS", "CHECKIN",
		"PROPFIND", "CHECKOUT", "CCM_POST",
		"SUBSCRIBE", "PROPPATCH", "BPROPFIND",
		"BPROPPATCH", "UNCHECKOUT", "MKACTIVITY",
		"MKWORKSPACE", "UNSUBSCRIBE", "RPC_CONNECT",
		"VERSION-CONTROL",
		"BASELINE-CONTROL"
		)

	__PROG_HTTP_SLINE_REQ = re.compile(b"[A-Z]{1,16}\s+[^\s]+\s+HTTP/1.\d")
	__PROG_HTTP_SLINE_RESP = re.compile(b"HTTP/1.\d\s+\d{3,3}\s+.{1, 50}")

	def _unpack(self, buf):
		#f = io.StringIO(buf)
		# parse header if this is the start of a request/response (or just data
		# requestline: [method] [uri] [version] -> GET / HTTP/1.1
		# responseline: [version] [status] [reason] -> HTTP/1.1 200 OK
		buf_header = b""

		if HTTP.__PROG_HTTP_SLINE_REQ.match(buf) is not None or \
			HTTP.__PROG_HTTP_SLINE_RESP.match(buf) is not None:

			buf_header, body = re.split(b"\r\n\r\n", buf, 2)

		#logger.debug("HTTP: init of triggerlist using: %s" % buf_header)
		tlist = HTTPTriggerList(buf_header)
		self._add_headerfield("header", "", tlist)

		pypacker.Packet._unpack(self, buf)

class HTTPTriggerList(pypacker.TriggerList):
	def __init__(self, header):
		"""Init the TriggerList representing the full HTTP header
		as tuples parsed from a byte-string."""
		super().__init__([])
		if len(header) == 0:
			#logger.debug("empty buf 1")
			return
		#logger.debug("parsing HTTP-header: %s" % header)

		lines = re.split(b"\r\n", header)
		req_resp = lines[0]
		del lines[0]
		self.append((req_resp,))

		for line in lines:
			#logger.debug("checking HTTP-header: %s" % line)
			if len(line) == 0:
				break
			key,val = re.split(b": ", line, 2)
			self.append((key, val))

	def pack(self):
		#logger.debug("packing HTTP-header")
		# no header = no CRNL
		if len(self) == 0:
			#logger.debug("empty buf 2")
			return b""
		packed = []
		itera = iter(self)
		packed.append( next(itera)[0] )	# startline

		for h in itera:
			#logger.debug("key/value: %s/%s" % (h[0], h[1]))
			# TODO: more performant
			packed.append(b": ".join(h))
		packed.append(b"\r\n")	# last separating newline header <-> body
		return b"\r\n".join(packed)


def parse_body(buf, headers):
	"""Return HTTP body parsed from a file object, given HTTP header dict."""
	headers_lower = [ k.lower() for k in headers.keys()]
	if "transfer-encoding" in headers_lower:
		# search for value of "transfer-encoding", no easy way beacuse possible upper/lowercase mix
		transfer_val = [ v.lower().strip() for k,v in headers if k.lower() is "transfer-encoding" ]

	if transfer_val is "chunked":
		logger.debug("got chunked encoding")
		f = io.StringIO(buf)
		l = []
		found_end = False
		while 1:
			try:
				sz = f.readline().split(None, 1)[0]
			except IndexError:
				raise pypacker.UnpackError("missing chunk size")
			n = int(sz, 16)
			if n == 0:
				found_end = True
			buf = f.read(n)
			if f.readline().strip():
				break
			if n and len(buf) == n:
				l.append(buf)
			else:
				break
		if not found_end:
			raise pypacker.NeedData("premature end of chunked body")
		body = "".join(l)
	else:
		body = buf
	return body

