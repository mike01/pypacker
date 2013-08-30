"""Packet reader and write routines for pcap format."""

from pypacker import pypacker
from pypacker.layer12 import ethernet
from pypacker.layer4 import tcp

import sys
import time
import logging

logger = logging.getLogger("pypacker")

TCPDUMP_MAGIC = 0xa1b2c3d4
PMUDPCT_MAGIC = 0xd4c3b2a1

PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4

DLT_NULL			= 0
DLT_EN10MB			= 1
DLT_EN3MB			= 2
DLT_AX25			= 3
DLT_PRONET			= 4
DLT_CHAOS			= 5
DLT_IEEE802			= 6
DLT_ARCNET			= 7
DLT_SLIP			= 8
DLT_PPP				= 9
DLT_FDDI			= 10
DLT_PFSYNC			= 18
DLT_IEEE802_11			= 105
DLT_LINUX_SLL			= 113
DLT_PFLOG			= 117
DLT_IEEE802_11_RADIO		= 127

if sys.platform.find("openbsd") != -1:
	DLT_LOOP	= 12
	DLT_RAW		= 14
else:
	DLT_LOOP	= 108
	DLT_RAW		= 12

dltoff = {
	DLT_NULL:4,
	DLT_EN10MB:14,
	DLT_IEEE802:22,
	DLT_ARCNET:6,
	DLT_SLIP:16,
	DLT_PPP:4,
	DLT_FDDI:21,
	DLT_PFLOG:48,
	DLT_PFSYNC:4,
	DLT_LOOP:4,
	DLT_LINUX_SLL:16
	}

class PktHdr(pypacker.Packet):
	"""pcap packet header."""
	__hdr__ = (
		("tv_sec", "I", 0),
		("tv_usec", "I", 0),
		("caplen", "I", 0),
		("len", "I", 0),
		)

class LEPktHdr(PktHdr):
	__byte_order__ = "<"

class FileHdr(pypacker.Packet):
	"""pcap file header."""
	__hdr__ = (
		("magic", "I", TCPDUMP_MAGIC),
		("v_major", "H", PCAP_VERSION_MAJOR),
		("v_minor", "H", PCAP_VERSION_MINOR),
		("thiszone", "I", 0),
		("sigfigs", "I", 0),
		("snaplen", "I", 1500),
		("linktype", "I", 1),
		)

class LEFileHdr(FileHdr):
	__byte_order__ = "<"

class Writer(object):
	"""
	Simple pcap  writer.
	"""
	def __init__(self, fileobj=None, snaplen=1500, linktype=DLT_EN10MB):
		"""
		fileobj = create a pcap-writer giving a file object retrieved by "open(...)"
		"""

		logger.debug("opening pcap file")
		self.__fh = fileobj
		if sys.byteorder == "little":
			fh = LEFileHdr(snaplen=snaplen, linktype=linktype)
		else:
			fh = FileHdr(snaplen=snaplen, linktype=linktype)
		self.__fh.write(fh.bin())

	def write(self, pkt, ts=None):
		"""Write the given packet's bytes to file."""
		if ts is None:
			ts = time.time()
		s = pkt.bin()
		n = len(s)
		# NO fix: https://code.google.com/p/pypacker/issues/detail?id=86
		# see: http://wiki.wireshark.org/Development/LibpcapFileFormat
		if sys.byteorder == "little":
			ph = LEPktHdr(tv_sec=int(ts),
				tv_usec=int((float(ts) - int(ts)) * 1000000.0),
				caplen=n, len=n)
		else:
			ph = PktHdr(tv_sec=int(ts),
				tv_usec=int((float(ts) - int(ts)) * 1000000.0),
				caplen=n, len=n)
		self.__fh.write(ph.bin())
		self.__fh.write(s)

	def close(self):
		self.__fh.close()

class Reader(object):
	"""
	Simple pcap file reader. Using iterators this
	will return "timestamp, byte string"
	"""

	def __init__(self, fileobj=None):
		"""
		Create a pcap.
		fileobj = create a pcap-reader giving a file object retrieved by "open(...)"
		"""
		#self.name = fileobj.name
		#self.fd = fileobj.fileno()
		self.__fh = fileobj
		buf = self.__fh.read(FileHdr._hdr_len)
		# TODO: remove if not needed
		self.__fh.seek(FileHdr._hdr_len)
		self.__hdr = FileHdr(buf)
		self.__ph = PktHdr


		if self.__hdr.magic == PMUDPCT_MAGIC:
			self.__hdr = LEFileHdr(buf)
			self.__ph = LEPktHdr
		elif self.__hdr.magic != TCPDUMP_MAGIC:
			raise ValueError("invalid tcpdump header")

		if self.__hdr.linktype in dltoff:
			self.dloff = dltoff[self.__hdr.linktype]
		else:
			self.dloff = 0

	#def fileno(self):
	#	return self.fd
	#def datalink(self):
	#	return self.__fh.linktype
	#def setfilter(self, value, optimize=1):
	#	return NotImplementedError
	#def reapypackers(self):
	#	return list(self)

	def dispatch(self, cnt, callback, *args):
		if cnt > 0:
			for i in range(cnt):
				ts, pkt = next(self)
				callback(ts, pkt, *args)
		else:
			for ts, pkt in self:
				callback(ts, pkt, *args)

	def loop(self, callback, *args):
		self.dispatch(0, callback, *args)

	# fix: https://code.google.com/p/pypacker/issues/detail?id=78
	def __next__(self):
		"""return (timestamp, b"...") for pcap-reader."""
		buf = self.__fh.read(PktHdr._hdr_len)

		if not buf:
			raise StopIteration

		hdr = self.__ph(buf)
		buf = self.__fh.read(hdr.caplen)

		return (hdr.tv_sec + (hdr.tv_usec / 1000000.0), buf)

	def __iter__(self):
		"""return (timestamp, b"...") for pcap-reader."""
		self.__fh.seek(FileHdr._hdr_len)

		while 1:
			buf = self.__fh.read(PktHdr._hdr_len)

			if not buf:
				break
			hdr = self.__ph(buf)
			buf = self.__fh.read(hdr.caplen)

			yield (hdr.tv_sec + (hdr.tv_usec / 1000000.0), buf)

	def close(self):
		self.__fh.close()
