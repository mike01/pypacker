# $Id: http.py 80 2011-01-06 16:50:42Z jon.oberheide $

"""Hypertext Transfer Protocol."""

import io
from . import dpkt

def parse_headers(f):
	"""Return dict of HTTP headers parsed from a file object."""
	d = {}
	while 1:
		line = f.readline()
		if not line:
			raise dpkt.NeedData('premature end of headers')
		line = line.strip()
		if not line:
			break
		l = line.split(':', 1)
		if len(l[0].split()) != 1:
			raise dpkt.UnpackError('invalid header: %r' % line)
		k = l[0].lower()
		v = len(l) != 1 and l[1].lstrip() or ''
		if k in d:
			if not type(d[k]) is list:
				d[k] = [d[k]]
			d[k].append(v)
		else:
			d[k] = v
	return d

def parse_body(f, headers):
	"""Return HTTP body parsed from a file object, given HTTP header dict."""
	if headers.get('transfer-encoding', '').lower() == 'chunked':
		l = []
		found_end = False
		while 1:
			try:
				sz = f.readline().split(None, 1)[0]
			except IndexError:
				raise dpkt.UnpackError('missing chunk size')
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
			raise dpkt.NeedData('premature end of chunked body')
		body = ''.join(l)
	elif 'content-length' in headers:
		n = int(headers['content-length'])
		body = f.read(n)
		if len(body) != n:
			raise dpkt.NeedData('short body (missing %d bytes)' % (n - len(body)))
	elif 'content-type' in headers:
		# TODO: check if next packet gets consumed if no body
		body = f.read()
	else:
		# XXX - need to handle HTTP/0.9
		body = ''
	return body

class Message(dpkt.Packet, metaclass=dpkt.MetaPacket):
	"""Hypertext Transfer Protocol headers + body."""
	__hdr_defaults__ = {}
	headers = None
	body = None

	def __init__(self, *args, **kwargs):
		if args:
			self.unpack(args[0])
		else:
			self.headers = {}
			self.body = ''
			for k, v in self.__hdr_defaults__.items():
				setattr(self, k, v)
			for k, v in kwargs.items():
				setattr(self, k, v)

	def unpack(self, buf):
		f = io.StringIO(buf)
		# Parse headers
		self.headers = parse_headers(f)
		# Parse body
		self.body = parse_body(f, self.headers)
		# Save the rest
		self.data = f.read()

	def pack_hdr(self):
		return ''.join([ '%s: %s\r\n' % t for t in self.headers.items() ])

	def __len__(self):
		return len(str(self))

	def __str__(self):
		return '%s\r\n%s' % (self.pack_hdr(), self.body)

class Request(Message):
	"""Hypertext Transfer Protocol Request."""
	__hdr_defaults__ = {
		'method':'GET',
		'uri':'/',
		'version':'1.0',
		}
	__methods = dict.fromkeys((
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
		))
	__proto = 'HTTP'

	def unpack(self, buf):
		f = io.StringIO(buf)
		line = f.readline()
		l = line.strip().split()
		if len(l) < 2:
			raise dpkt.UnpackError('invalid request: %r' % line)
		if l[0] not in self.__methods:
			raise dpkt.UnpackError('invalid http method: %r' % l[0])
		if len(l) == 2:
			# HTTP/0.9 does not specify a version in the request line
			self.version = '0.9'
		else:
			if not l[2].startswith(self.__proto):
				raise dpkt.UnpackError('invalid http version: %r' % l[2])
			self.version = l[2][len(self.__proto)+1:]
		self.method = l[0]
		self.uri = l[1]
		Message.unpack(self, f.read())

	def __str__(self):
		return '%s %s %s/%s\r\n' % (self.method, self.uri, self.__proto,
									self.version) + Message.__str__(self)

class Response(Message):
	"""Hypertext Transfer Protocol Response."""
	__hdr_defaults__ = {
		'version':'1.0',
		'status':'200',
		'reason':'OK'
		}
	__proto = 'HTTP'

	def unpack(self, buf):
		f = io.StringIO(buf)
		line = f.readline()
		l = line.strip().split(None, 2)
		if len(l) < 2 or not l[0].startswith(self.__proto) or not l[1].isdigit():
			raise dpkt.UnpackError('invalid response: %r' % line)
		self.version = l[0][len(self.__proto)+1:]
		self.status = l[1]
		self.reason = l[2]
		Message.unpack(self, f.read())

	def __str__(self):
		return '%s/%s %s %s\r\n' % (self.__proto, self.version, self.status,
									self.reason) + Message.__str__(self)
