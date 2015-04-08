"""
Hypertext Transfer Protocol.
"""

from pypacker import pypacker, triggerlist

import re
import logging

logger = logging.getLogger("pypacker")


class HTTPStartLine(triggerlist.TriggerList):
	def _pack(self):
		# logger.debug("packing HTTP-header")
		# no header = no CRNL
		if len(self) == 0:
			# logger.debug("empty buf 2")
			return b""
		return b"".join(self) + b"\r\n"


class HTTPHeader(triggerlist.TriggerList):
	def _pack(self):
		# logger.debug("packing HTTP-header")
		# no header = no CRNL
		if len(self) == 0:
			# logger.debug("empty buf 2")
			return b""
		return b"\r\n".join([b": ".join(keyval) for keyval in self]) + b"\r\n\r\n"

# REQ_METHODS_BASIC		= set([b"GET", b"POST", b"HEAD", b"PUT", b"OPTIONS", b"CONNECT", b"UPDATE", b"TRACE"])
PROG_SPLIT_HEADBODY		= re.compile(b"\r\n\r\n")
PROG_SPLIT_HEADER		= re.compile(b"\r\n")
PROG_SPLIT_KEYVAL		= re.compile(b": ")


class HTTP(pypacker.Packet):
	__hdr__ = (
		# content: ["startline"]
		("startline", None, HTTPStartLine),
		# content: [("name", "value"), ...]
		("hdr", None, HTTPHeader),
	)

	def _dissect(self, buf):
		# requestline: [method] [uri] [version] eg GET / HTTP/1.1
		# responseline: [version] [status] [reason] eg HTTP/1.1 200 OK
		bts_header, bts_body = PROG_SPLIT_HEADBODY.split(buf, 1)
		# logger.debug("head: %s" % bts_header)
		# logger.debug("body: %s" % bts_body)
		startline, bts_header = PROG_SPLIT_HEADER.split(bts_header, 1)
		# logger.debug("startline: %s" % startline)
		# logger.debug("bts_header: %s" % bts_header)

		self._init_triggerlist("startline", startline + b"\r\n", lambda bts: bts.strip())
		self._init_triggerlist("hdr", bts_header + b"\r\n\r\n", self.__parse_header)

		# logger.debug(self.startline.bin())
		# logger.debug(self.header.bin())
		# logger.debug(len(startline+b"\r\n") + len(bts_header+b"\r\n\r\n"))
		# logger.debug("lengths head/body: %d %d" % (len(buf), len(bts_body)))
		# logger.debug(buf[:len(buf) - len(bts_body)])
		# HEADER + "\r\n\r\n" + BODY -> newline is part of the header
		return len(buf) - len(bts_body)

	def __parse_header(self, buf):
		# logger.debug("parsing: %s" % buf)
		header = []
		lines = PROG_SPLIT_HEADER.split(buf)

		for line in lines:
			# logger.debug("checking HTTP-header: %s" % line)
			if len(line) == 0:
				break
			key, val = PROG_SPLIT_KEYVAL.split(line, 1)
			header.append((key, val))

		return header
