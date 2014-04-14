"""
Packet read and write routines for pcap format.
See http://wiki.wireshark.org/Development/LibpcapFileFormat
"""
import sys
import time
import logging
import struct

from pypacker import pypacker, multiproc_unpacker

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

_MODE_BYTES			= 0
_MODE_PACKETS			= 1

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


class FileHdr(pypacker.Packet):
	"""pcap file header."""
	# header length = 24
	__hdr__ = (
		("magic", "I", TCPDUMP_MAGIC),
		("v_major", "H", PCAP_VERSION_MAJOR),
		("v_minor", "H", PCAP_VERSION_MINOR),
		("thiszone", "I", 0),
		("sigfigs", "I", 0),
		("snaplen", "I", 1500),
		("linktype", "I", 1),
	)

class LEFileHdr(pypacker.Packet):
	"""pcap file header."""
	# header length = 24
	__hdr__ = (
		("magic", "I", TCPDUMP_MAGIC),
		("v_major", "H", PCAP_VERSION_MAJOR),
		("v_minor", "H", PCAP_VERSION_MINOR),
		("thiszone", "I", 0),
		("sigfigs", "I", 0),
		("snaplen", "I", 1500),
		("linktype", "I", 1),
	)
	__byte_order__ = "<"

class PktHdr(pypacker.Packet):
	"""pcap packet header."""
	# header length: 16
	__hdr__ = (
		("tv_sec", "I", 0),
		# this can be either microseconds or nanoseconds: check magic number
		("tv_usec", "I", 0),
		("caplen", "I", 0),
		("len", "I", 0),
	)

# TODO: check descenting
class LEPktHdr(pypacker.Packet):
	"""pcap packet header."""
	# header length: 16
	__hdr__ = (
		("tv_sec", "I", 0),
		# this can be either microseconds or nanoseconds: check magic number
		("tv_usec", "I", 0),
		("caplen", "I", 0),
		("len", "I", 0),
	)

	__byte_order__ = "<"



class Writer(object):
	"""
	Simple pcap writer. Note: this will use nanosecond timestamp resolution.
	"""
	def __init__(self, fileobj=None, filename=None, snaplen=1500, linktype=DLT_EN10MB):
		"""
		fileobj --- create a pcap-writer giving a file object retrieved by open(..., "wb")
		filename --- create a pcap-writer giving a file pcap filename
		"""
		## handle source modes
		if fileobj is not None:
			self.__fh = fileobj
		elif filename is not None:
			self.__fh = open(filename, "wb")
		else:
			raise Exception("No fileobject and no filename given..nothing to read!!!")

		fh = FileHdr(magic=TCPDUMP_MAGIC_NANO, snaplen=snaplen, linktype=linktype)
		logger.debug("writing fileheader %r" % fh)
		self.__fh.write(fh.bin())

	def write(self, pkt, ts=None):
		"""Write the given packet's bytes to file."""
		if ts is None:
			ts = time.time()
		s = pkt.bin()
		n = len(s)
		# NO fix: https://code.google.com/p/pypacker/issues/detail?id=86
		# see: http://wiki.wireshark.org/Development/LibpcapFileFormat
		ph = PktHdr(tv_sec=int(ts),
			tv_usec=int((float(ts) - int(ts)) * 1000000000.0),
			caplen=n, len=n)
		#logger.debug("writing packet header + packet data")
		self.__fh.write(ph.bin())
		self.__fh.write(s)

	def close(self):
		self.__fh.close()

_struct_preheader_be = struct.Struct(">IIII")
_struct_preheader_le = struct.Struct("<IIII")

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
			IMPORTANT: when providing lowest_layer: do _NOT_ use lambda expression, the filter _MUST_ be pickable!
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

		buf = self.__fh.read(24)
		# file header is skipped per default (needed for __next__)
		self.__fh.seek(24)
		self.__fhdr = FileHdr(buf)
		self._closed = False

		## handle file types
		if self.__fhdr.magic == TCPDUMP_MAGIC:
			self.__resolution_factor = 1
			# Note: we could use PktHdr to parse pre-packetdata but calling unpack directly
			# greatly improves performance
			self.__callback_unpack_meta = lambda x: _struct_preheader_be.unpack(x)
		elif self.__fhdr.magic == TCPDUMP_MAGIC_NANO:
			self.__resolution_factor = 1000
			self.__callback_unpack_meta = lambda x: _struct_preheader_be.unpack(x)
		elif self.__fhdr.magic == TCPDUMP_MAGIC_SWAPPED:
			self.__fhdr = LEFileHdr(buf)
			self.__resolution_factor = 1
			self.__callback_unpack_meta = lambda x: _struct_preheader_le.unpack(x)
		elif self.__fhdr.magic == TCPDUMP_MAGIC_NANO_SWAPPED:
			self.__fhdr = LEFileHdr(buf)
			self.__resolution_factor = 1000
			self.__callback_unpack_meta = lambda x: _struct_preheader_le.unpack(x)
		else:
			raise ValueError("invalid tcpdump header, magic value: %s" % self.__fhdr.magic)

		logger.debug("pcap file header for reading: %r" % self.__fhdr)

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
			self._mode = _MODE_BYTES
			self.__next__ = self._next_bytes
		else:
		# set up packeting mode
			self._mode = _MODE_PACKETS
			self.__next__ = self._next_pmode
			self._lowest_layer = lowest_layer
			self._filter = filter
			self._mp_unpacker = multiproc_unpacker.MultiprocUnpacker(cb_next=self._next_bytes, filter=self._filter)

	def is_resolution_nano(self):
		return self.__resolution_factor == 1000

	def _next_bytes_conversion(self):
		"""
		Standard __next__ implementation. Needs to be a sepearte method to be called by producer.

		return -- (timestamp_nanoseconds, bytes) for pcap-reader.
		"""
		# read metadata before actual packet
		buf = self.__fh.read(16)

		if not buf:
			raise StopIteration

		d = self.__callback_unpack_meta(buf)
		#logger.debug("reading: input/pos/d[2] = %d/%d/%r" % (len(buf), self.__fh.tell(), d))
		buf = self.__fh.read(d[2])

		return (d[0] * 1000000000 + (d[1] * self.__resolution_factor), buf)

	def _next_bytes_noconversion(self):
		"""
		Same as _next_bytes_conversion wihtout timestamp-conversion. (Duplicatet because of performance reasons.)

		return -- ((seconds, [microseconds|nanoseconds]), bytes) for pcap-reader.
		"""
		# read metadata before actual packet
		buf = self.__fh.read(16)

		if not buf:
			raise StopIteration

		d = self.__callback_unpack_meta(buf)
		#logger.debug("reading: input/d[2] = %d/%d" % (len(buf), d[2]))
		buf = self.__fh.read(d[2])

		#return ((hdr.tv_sec, hdr.tv_usec), buf)
		return ((d[0], d[1]), buf)

	def _next_pmode(self):
		"""
		return -- (timestamp_nanoseconds, packet) if packet can be created from bytes
			else (timestamp_nanoseconds, bytes)
		"""
		return self._mp_unpacker.__next__()

	def __iter__(self):
		"""
		return -- (timestamp, [bytes|packet]) for pcap-reader depending on configuration.
		"""
		if self._closed:
			return

		while True:
		# loop until EOF is reached
			try:
				yield self.__next__()
			except StopIteration:
				# auto close: nothing more to iterate
				#logger.debug("ppcap iter close()")
				self.close()
				break

	def close(self):
		self._closed = True
		self.__fh.close()

		try:
			#logger.debug("closing multiproc unpacker in ppcap")
			self._mp_unpacker.stop()
		except AttributeError:
			# only works on pmode
			pass
