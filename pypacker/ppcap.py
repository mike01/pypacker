"""
Packet read and write routines for pcap format.
See http://wiki.wireshark.org/Development/LibpcapFileFormat
"""
import sys
import logging
import struct

from pypacker import pypacker

# avoid unneeded references for performance reasons
unpack = struct.unpack

logger = logging.getLogger("pypacker")

# File magic numbers
# pcap using microseconds resolution
TCPDUMP_MAGIC			= 0xA1B2C3D4
TCPDUMP_MAGIC_SWAPPED		= 0xD4C3B2A1
# pcap using nanoseconds resolution
TCPDUMP_MAGIC_NANO		= 0xA1B23C4D
TCPDUMP_MAGIC_NANO_SWAPPED 	= 0x4D3CB2A1

PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4

DLT_NULL				= 0
DLT_EN10MB				= 1
DLT_EN3MB				= 2
DLT_AX25				= 3
DLT_PRONET				= 4
DLT_CHAOS				= 5
DLT_IEEE802				= 6
DLT_ARCNET				= 7
DLT_SLIP				= 8
DLT_PPP					= 9
DLT_FDDI				= 10
DLT_PFSYNC				= 18
DLT_IEEE802_11				= 105
DLT_LINUX_SLL				= 113
DLT_PFLOG				= 117
DLT_IEEE802_11_RADIO			= 127
DLT_LINKTYPE_BLUETOOTH_LE_LL		= 251
LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR	= 256

MODE_BYTES			= 0
MODE_PACKETS			= 1

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
	Simple pcap writer supporting pcap format.
	Note: this will use nanosecond timestamp resolution.
	"""
	def __init__(self, filename, snaplen=1500, linktype=DLT_EN10MB):
		"""
		filename -- Filename to write packets to
		"""
		self.__fh = open(filename, "wb")

		fh = FileHdr(magic=TCPDUMP_MAGIC_NANO, snaplen=snaplen, linktype=linktype)
		# logger.debug("writing fileheader %r" % fh)
		self.__fh.write(fh.bin())
		self._timestamp = 0

	def __enter__(self):
		return self

	def __exit__(self, objtype, value, traceback):
		self.close()

	def write(self, bts, ts=None):
		"""
		Write the given packet's bytes to file.

		bts -- bytes to be written
		ts -- timestamp in Nanoseconds
		"""
		# split timestamp into seconds, nanoseconds
		if ts is None:
			sec = self._timestamp // 1000000000
			nsec = int(self._timestamp - (sec * 1000000000))
			self._timestamp += 1000000
		else:
			sec = int(ts / 1000000000)
			nsec = ts - (sec * 1000000000)

		# logger.debug("paket time sec/nsec: %d/%d" % (sec, nsec))
		n = len(bts)
		ph = PktHdr(tv_sec=sec, tv_usec=nsec, caplen=n, len=n)
		# logger.debug("writing packet header + packet data")
		self.__fh.write(ph.bin())
		self.__fh.write(bts)

	def close(self):
		"""Close pcpa file."""
		self.__fh.close()


unpack_IIII_be = struct.Struct(">IIII").unpack
unpack_IIII_le = struct.Struct("<IIII").unpack


def _filter_dummy(_):
	return True


class Reader(object):
	"""
	Simple pcap file reader supporting pcap format. Using iterators this will
	return (timestamp, bytes) on standard mode and (timestamp, packet) on packet mode.
	Default timestamp resolution ist nanoseconds.
	"""

	def __init__(self,
		filename,
		lowest_layer=None,
		pktfilter=None):
		"""
		Create a pcap Reader.

		filename -- Filename to read packets from
		lowest_layer -- setting this to a non-None value will activate the auto-packeting
			mode using the given class as lowest layer to create packets.
			Note: __next__ and __iter__ will return (timestamp, packet) instead
			of raw (timestamp, raw_bytes)
		pktfilter -- filter callback to be used for packeting mode.
			signature: callback(packet) [True|False], True = accept packet, False otherwise
		"""

		self.__fh = open(filename, "rb")
		buf = self.__fh.read(24)
		# file header is skipped per default (needed for __next__)
		self.__fh.seek(24)
		# this is not needed anymore later on but we set it anyway
		self.fhdr = FileHdr(buf)
		self._closed = False

		# handle file types
		if self.fhdr.magic == TCPDUMP_MAGIC:
			self.__resolution_factor = 1000
			# Note: we could use PktHdr to parse pre-packetdata but calling unpack directly
			# greatly improves performance
			self.__callback_unpack_meta = unpack_IIII_be
		elif self.fhdr.magic == TCPDUMP_MAGIC_NANO:
			self.__resolution_factor = 1
			self.__callback_unpack_meta = unpack_IIII_be
		elif self.fhdr.magic == TCPDUMP_MAGIC_SWAPPED:
			self.fhdr = LEFileHdr(buf)
			self.__resolution_factor = 1000
			self.__callback_unpack_meta = unpack_IIII_le
		elif self.fhdr.magic == TCPDUMP_MAGIC_NANO_SWAPPED:
			self.fhdr = LEFileHdr(buf)
			self.__resolution_factor = 1
			self.__callback_unpack_meta = unpack_IIII_le
		else:
			raise ValueError("invalid tcpdump header, magic value: %s" % self.fhdr.magic)

		# logger.debug("pcap file header for reading: %r", self.fhdr)
		# logger.debug("timestamp factor: %s" % self.__resolution_factor)

		if lowest_layer is None:
			# standard implementation (conversion or non-converison mode)
			logger.info("using plain bytes mode")
			self._mode = MODE_BYTES
			self.__next__ = self._next_bytes
		else:
			# set up packeting mode
			logger.info("using packets mode")
			self._mode = MODE_PACKETS
			self.__next__ = self._next_packet
			self._lowest_layer = lowest_layer

			if pktfilter is None:
				self._filter = _filter_dummy
			else:
				self._filter = pktfilter

	def __enter__(self):
		return self

	def __exit__(self, objtype, value, traceback):
		self.close()

	def is_resolution_nano(self):
		"""return -- True if resolution is in Nanoseconds, False if milliseconds."""
		return self.__resolution_factor == 1000

	def _next_bytes(self):
		"""
		return -- (timestamp_nanoseconds, bytes)
		"""
		# read metadata before actual packet
		buf = self.__fh.read(16)

		if not buf:
			raise StopIteration

		d = self.__callback_unpack_meta(buf)
		# logger.debug("reading: input/pos/d[2] = %d/%d/%r" % (len(buf), self.__fh.tell(), d))
		buf = self.__fh.read(d[2])

		return (d[0] * 1000000000 + (d[1] * self.__resolution_factor), buf)

	def _next_packet(self):
		"""
		return -- (timestamp_nanoseconds, packet) if packet can be created from bytes
			else (timestamp_nanoseconds, bytes)
		"""
		while True:
			# until StopIteration
			ts_bts = self._next_bytes()

			try:
				pkt = self._lowest_layer(ts_bts[1])

				if self._filter(pkt):
					return (ts_bts[0], pkt)
			except Exception as ex:
				logger.exception(ex)
				return ts_bts

	def __iter__(self):
		"""
		return -- (timestamp, [bytes|packet]) for pcap-reader depending on configuration.
		"""
		if self._closed:
			raise StopIteration

		while True:
			# loop until EOF is reached (raises StopIteration)
			yield self.__next__()

	def get_by_indices(self, indices):
		"""
		Return [(timestamp, [bytes|packets]), ...] for the specified indices in packet file
		starting at 0 for first packet. This method won't change the current read-pointer.

		indices -- set of indices like {0, 1, 2}. Nonexistent indices will be ignored.
		return -- list of (timestamp, [bytes|packets]) at positions given by indices
			(ordered as in packet source)
		"""
		data_ret = {}

		if self._closed:
			return data_ret

		if type(indices) is list:
			indices = set(indices)

		oldpos = self.__fh.tell()
		self.__fh.seek(24)
		pos = 0

		for data in self:
			if pos in indices:
				data_ret[pos] = data
			pos += 1

		self.__fh.seek(oldpos)
		return data_ret

	def close(self):
		"""Close pcap file."""
		self._closed = True
		self.__fh.close()
