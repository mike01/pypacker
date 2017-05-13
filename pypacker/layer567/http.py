"""
Hypertext Transfer Protocol.
"""
import re
import logging

from pypacker import pypacker, triggerlist

logger = logging.getLogger("pypacker")


class HTTPHeader(triggerlist.TriggerList):
	def _pack(self, tuple_entry):
		# logger.debug("packing HTTP-header")
		# no header = no CRNL
		if len(self) == 0:
			# logger.debug("empty buf 2")
			return b""
		#return b"\r\n".join([b": ".join(keyval) for keyval in self]) + b"\r\n\r\n"
		#logger.debug("adding: %r" % (tuple_entry[0] +b": "+ tuple_entry[1] + b"\r\n"))
		return tuple_entry[0] + b": " + tuple_entry[1] + b"\r\n"

PROG_SPLIT_HEADBODY	= re.compile(b"\r\n\r\n")
split_headbody		= PROG_SPLIT_HEADBODY.split
PROG_SPLIT_HEADER	= re.compile(b"\r\n")
split_header		= PROG_SPLIT_HEADER.split
PROG_SPLIT_KEYVAL	= re.compile(b": ")
split_keyval		= PROG_SPLIT_KEYVAL.split


class HTTP(pypacker.Packet):
	__hdr__ = (
		# content: b"startline"
		("startline", None, None),
		# content: [("name", "value"), ...]
		("hdr", None, HTTPHeader),
		("sep", "2s", b"\r\n")
	)

	def _dissect(self, buf):
		# requestline: [method] [uri] [version] eg GET / HTTP/1.1
		# responseline: [version] [status] [reason] eg HTTP/1.1 200 OK
		try:
			bts_header, bts_body = split_headbody(buf, maxsplit=1)
		except ValueError:
			# logger.debug("no startline/header present")
			# deactivate separator
			self.sep = None
			# assume this is part of a bigger (splittet) HTTP-message: no header/only body
			return 0

		try:
			startline, bts_header = split_header(bts_header, maxsplit=1)
		except ValueError:
			# logger.debug("just startline: %r, hdr length=%d" % (bts_header, len(bts_header) + 4))
			# bts_header was something like "HTTP/1.1 123 status" (\r\n\r\n previously removed)
			self.startline = bts_header + b"\r\n"
			#self._init_triggerlist("hdr", b"", lambda _: [])
			return len(bts_header) + 4  # startline + 2 (CR NL) + 0 (header) + 2 (sep: CR NL) + 0 (body)

		self.startline = startline + b"\r\n"
		# bts_header = hdr1\r\nhdr2 -> hdr1\r\nhdr2\r\n
		self._init_triggerlist("hdr", bts_header + b"\r\n", self.__parse_header)

		#logger.debug("startline: %s" % self.startline)
		#logger.debug("hdr: %s" % self.hdr)
		#logger.debug("bts_header: %s" % (bts_header+b"\r\n"))
		#logger.debug("sep: %s" % self.sep)

		# logger.debug(self.startline.bin())
		# logger.debug(self.header.bin())
		# logger.debug(len(startline+b"\r\n") + len(bts_header+b"\r\n\r\n"))
		# logger.debug("lengths head/body: %d %d" % (len(buf), len(bts_body)))
		# logger.debug(buf[:len(buf) - len(bts_body)])
		# HEADER + "\r\n" + BODY -> newline is part of the header
		return len(buf) - len(bts_body)

	@staticmethod
	def __parse_header(buf):
		#logger.debug("parsing: %s" % buf)
		header = []
		lines = split_header(buf)

		for line in lines:
			#logger.debug("checking HTTP-header: %s" % line)
			if len(line) == 0:
				break
			key, val = split_keyval(line, 1)
			header.append((key, val))

		return header
