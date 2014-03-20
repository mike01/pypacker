"""
Packet read and write routines for pcap format.
See http://wiki.wireshark.org/Development/LibpcapFileFormat
"""

from pypacker import pypacker

import sys
import time
import logging
import struct

# avoid unneeded references for performance reasons
unpack = struct.unpack

logger = logging.getLogger("pypacker")

# File magic numbers
# pcap using microseconds resolution
TCPDUMP_MAGIC			= 0xa1b2c3d4
TCPDUMP_MAGIC_SWAPPED		= 0xd4c3b2a1
# pcap using nanoseconds resolution
TCPDUMP_MAGIC_NANO		= 0xa1b23c4d
TCPDUMP_MAGIC_NANO_SWAPPED 	= 0x4d3cb2a1

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

# retrieve via: FileHdr.linktype
dltoff = {
	DLT_NULL	: 4,
	DLT_EN10MB	: 14,
	DLT_IEEE802	: 22,
	DLT_ARCNET	: 6,
	DLT_SLIP	: 16,
	DLT_PPP		: 4,
	DLT_FDDI	: 21,
	DLT_PFLOG	: 48,
	DLT_PFSYNC	: 4,
	DLT_LOOP	: 4,
	DLT_LINUX_SLL	: 16
	}


class PktHdr(pypacker.Packet):
	"""pcap packet header."""
	__hdr__ = (
		("tv_sec", "I", 0),
		# this can be either microseconds or nanoseconds: check magic number
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
	Simple pcap writer. Note: this will use nanosecond timestamp resolution.
	"""
	def __init__(self, fileobj=None, snaplen=1500, linktype=DLT_EN10MB):
		"""
		fileobj --- create a pcap-writer giving a file object retrieved by "open(...)"
		"""

		logger.debug("opening pcap file")
		self.__fh = fileobj

		if sys.byteorder == "little":
			fh = LEFileHdr(magic=TCPDUMP_MAGIC_NANO_SWAPPED, snaplen=snaplen, linktype=linktype)
		else:
			fh = FileHdr(magic=TCPDUMP_MAGIC_NANO, snaplen=snaplen, linktype=linktype)
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
				tv_usec=int((float(ts) - int(ts)) * 1000000000.0),
				caplen=n, len=n)
		else:
			ph = PktHdr(tv_sec=int(ts),
				tv_usec=int((float(ts) - int(ts)) * 1000000000.0),
				caplen=n, len=n)
		self.__fh.write(ph.bin())
		self.__fh.write(s)

	def close(self):
		self.__fh.close()


class Reader(object):
	"""
	Simple pcap file reader supporting pcap and pcapng format. Using iterators this will
	return (timestamp, bytes) on standard mode and (timestamp, packet) on packet mode.
	Default timestamp resolution ist nanoseconds.
	"""

	def __init__(self, fileobj=None, filename=None, lowest_layer=None, filter=lambda a: True, ts_conversion=True):
		"""
		Create a pcap Reader.

		fileobj -- create a pcap-reader giving a file object retrieved by "open(..., 'rb')"
		filename -- create a pcap-reader giving a filename
		lowest_layer -- setting this to a non-None value will activate the auto-packeting
			mode using the given class as lowest layer to create packets.
			Note: __next__ and __iter__ will return (timestamp, packet) instead of raw (timestamp, raw_bytes)
		filter -- filter callback to be used for packeting mode.
			signature: callback(packet) [True|False], True = accept packet, false otherwise
		ts_conversion -- convert timestamps to nanoseconds. Setting this to False will return
			((seconds, [microseconds|nanoseconds]), buf) for __next__ and __iter__ instead of (timestamp, packet)
			and saves ~2% computation time. Minor fraction type can be checked using "is_resolution_nano".
		"""

		## handle source modes
		if fileobj is not None:
			self.__fh = fileobj
		elif filename is not None:
			self.__fh = open(filename, "rb")
		else:
			raise Exception("No fileobject and no filename given..nothing to read!!!")

		buf = self.__fh.read(FileHdr._hdr_len)
		# file header is skipped per default (needed for __next__)
		self.__fh.seek(FileHdr._hdr_len)
		self.__fhdr = FileHdr(buf)
		self.__phdr = PktHdr

		## handle file types
		if self.__fhdr.magic == TCPDUMP_MAGIC:
			self.__resolution_factor = 1000
			# Note: we could use PktHdr to parse pre-packetdata but calling unpack directly
			# greatly improves performance
			self.__callback_unpack_meta = lambda x: unpack(">IIII", x)
		elif self.__fhdr.magic == TCPDUMP_MAGIC_NANO:
			self.__resolution_factor = 1
			self.__callback_unpack_meta = lambda x: unpack(">IIII", x)
		elif self.__fhdr.magic == TCPDUMP_MAGIC_SWAPPED:
			self.__fhdr = LEFileHdr(buf)
			self.__phdr = LEPktHdr
			self.__resolution_factor = 1000
			self.__callback_unpack_meta = lambda x: unpack("<IIII", x)
		elif self.__fhdr.magic == TCPDUMP_MAGIC_NANO_SWAPPED:
			self.__fhdr = LEFileHdr(buf)
			self.__phdr = LEPktHdr
			self.__resolution_factor = 1
			self.__callback_unpack_meta = lambda x: unpack("<IIII", x)
		else:
			raise ValueError("invalid tcpdump header, magic value: %s" % self.__fhdr.magic)

		#logger.debug("timestamp factor: %s" % self.__resolution_factor)

		# check if timestamp converison to nanoseconds is needed
		if ts_conversion:
			#logger.debug("using _next_bytes_conversion")
			self._next_bytes = self._next_bytes_conversion
		else:
			#logger.debug("using _next_bytes_noconversion")
			self._next_bytes = self._next_bytes_noconversion

		if lowest_layer is None:
		# standard implementation (conversion or non-converison mode)
			self.__next__ = self._next_bytes
		else:
		# set up packeting mode
			self.__next__ = self._next_pmode
			self._lowest_layer = lowest_layer
			self._filter = filter

	def is_resolution_nano(self):
		return self.__resolution_factor == 1000

	def _next_bytes_conversion(self):
		"""
		Standard __next__ implementation. Needs to be a sepearte method to be called by producer.

		return -- (timestamp_nanoseconds, bytes) for pcap-reader.
		"""
		buf = self.__fh.read(PktHdr._hdr_len)

		if not buf:
			raise StopIteration

		#hdr = self.__phdr(buf)
		d = self.__callback_unpack_meta(buf)
		#buf = self.__fh.read(hdr.caplen)
		buf = self.__fh.read(d[2])

		return (d[0] * 1000000000 + (d[1] * self.__resolution_factor), buf)

	def _next_bytes_noconversion(self):
		"""
		Same as _next_bytes_conversion wihtout timestamp-conversion. (Duplicatet because of performance reasons.)

		return -- ((seconds, [microseconds|nanoseconds]), bytes) for pcap-reader.
		"""
		buf = self.__fh.read(PktHdr._hdr_len)

		if not buf:
			raise StopIteration

		#hdr = self.__phdr(buf)
		d = self.__callback_unpack_meta(buf)
		#buf = self.__fh.read(hdr.caplen)
		buf = self.__fh.read(d[2])

		#return ((hdr.tv_sec, hdr.tv_usec), buf)
		return ((d[0], d[1]), buf)

	def _next_pmode(self):
		"""
		return -- (timestamp_nanoseconds, packet) if packet can be created from bytes
			else (timestamp_nanoseconds, bytes)
		"""
		ts_pkt = None

		while ts_pkt is None:
			ts_bts = self._next_bytes()
			try:
				pkt = self._lowest_layer(ts_bts[1])
			except pypacker.UnpackError:
				ts_pkt = (ts_bts[0], ts_bts[1])
				break

			if self._filter(pkt):
				ts_pkt = (ts_bts[0], pkt)
				break

		return ts_pkt

	def __iter__(self):
		"""
		return -- (timestamp, bytes) for pcap-reader.
		"""
		self.__fh.seek(FileHdr._hdr_len)

		# loop until EOF is reached
		while True:
			try:
				yield self.__next__()
			except StopIteration:
				break

	def close(self):
		self.__fh.close()
