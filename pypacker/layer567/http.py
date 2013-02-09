# $Id: http.py 80 2011-01-06 16:50:42Z jon.oberheide $

"""Hypertext Transfer Protocol.
In contrast to the low-layer protocols HTTP-headers are stored via a dict
like {headername : value} in "headers" inclusive reqest/response line.
This will be the exact same header but without ": ".
"""

import pypacker as pypacker
from pypacker import TriggerList
import re
import logging

logger = logging.getLogger("pypacker")

class HTTP(pypacker.Packet):
	__hdr__ = (
		#("h", "1s", ""),	# avoid optimazation
		)

	"""Hypertext Transfer Protocol headers + body."""
	__req_methods = (
		'GET', 'PUT', 'ICY',
		'COPY', 'HEAD', 'LOCK', 'MOVE', 'POLL', 'POST',
		'BCOPY', 'BMOVE', 'MKCOL', 'TRACE', 'LABEL', 'MERGE',
		'DELETE', 'SEARCH', 'UNLOCK', 'REPORT', 'UPDATE', 'NOTIFY',
		'BDELETE', 'CONNECT', 'OPTIONS', 'CHECKIN',
		'PROPFIND', 'CHECKOUT', 'CCM_POST',
		'SUBSCRIBE', 'PROPPATCH', 'BPROPFIND',
		'BPROPPATCH', 'UNCHECKOUT', 'MKACTIVITY',
		'MKWORKSPACE', 'UNSUBSCRIBE', 'RPC_CONNECT',
		'VERSION-CONTROL',
		'BASELINE-CONTROL'
		)

	def __setattr__(self, k, v):
		if k is "header":
			raise Exception("can't set header directly, please chage list by assigning tuples")
		pypacker.Packet.__setattr__(self, k, v)


	def unpack(self, buf):
		#f = io.StringIO(buf)
		header, body = re.split(b"\r\n\r\n", buf, 2)
		# parse headers
		# requestline: [method] [uri] [version] -> GET / HTTP/1.1
		# responseline: [version] [status] [reason] -> HTTP/1.1 200 OK
		try:
			tlist = HTTPTriggerList(header)
		except Exception as e:
			raise Exception("couldn't parse HTTP-header: %s" % e)
		self._add_headerfield("header", "", tlist)
		pypacker.Packet.unpack(self, buf)

class HTTPTriggerList(TriggerList):
	def __init__(self, header):
		"""Return a TriggerList of tuples representing the full HTTP header
		parsed from a byte-string."""
		super().__init__()
		lines = re.split(b"\r\n", header)
		req_resp = lines[0]
		del lines[0]
		self += [(req_resp,)]

		for line in lines:
			#logger.debug("checking HTTP-header: %s" % line)
			if len(line) == 0:
				break
			key,val = re.split(b": ", line, 2)
			self += [(key, val)]

	def pack(self):
		#logger.debug("packing HTTP-header")
		packed = []
		itera = iter(self)
		packed += [next(itera)[0]]	# startline

		for h in itera:
			#logger.debug("key/value: %s/%s" % (h[0], h[1]))
			# TODO: more performant
			packed += [b": ".join(h)]
		packed += [b"\r\n"]	# last separating newline header <-> body
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
				raise pypacker.UnpackError('missing chunk size')
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
			raise pypacker.NeedData('premature end of chunked body')
		body = ''.join(l)
	else:
		body = buf
	return body

