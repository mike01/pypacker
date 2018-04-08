"""
Packet read and write routines for pcap format.
See http://wiki.wireshark.org/Development/LibpcapFileFormat
"""
import logging
import types

from pypacker import pypacker
from pypacker.structcbs import *
from pypacker.layer12 import ethernet, linuxcc, radiotap, btle, can

logger = logging.getLogger("pypacker")


# PCAP/TCPDump related
# PCAP file header

# File magic numbers
# pcap using microseconds resolution
TCPDUMP_MAGIC	        	= 0xA1B2C3D4
TCPDUMP_MAGIC_SWAPPED	        = 0xD4C3B2A1
# pcap using nanoseconds resolution
TCPDUMP_MAGIC_NANO		= 0xA1B23C4D
TCPDUMP_MAGIC_NANO_SWAPPED	= 0x4D3CB2A1

PCAP_VERSION_MAJOR		= 2
PCAP_VERSION_MINOR		= 4

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
DLT_CAN_SOCKETCAN		        = 227
DLT_LINKTYPE_BLUETOOTH_LE_LL		= 251
LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR	= 256

PCAPTYPE_CLASS = {
	DLT_LINUX_SLL: linuxcc.LinuxCC,
	DLT_EN10MB: ethernet.Ethernet,
	DLT_CAN_SOCKETCAN: can.CAN,
	DLT_IEEE802_11_RADIO: radiotap.Radiotap,
	LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR: btle.BTLEHdr
}


class PcapFileHdr(pypacker.Packet):
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


class PcapLEFileHdr(pypacker.Packet):
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


class PcapPktHdr(pypacker.Packet):
	"""pcap packet header."""
	# header length: 16
	__hdr__ = (
		("tv_sec", "I", 0),
		# this can be either microseconds or nanoseconds: check magic number
		("tv_usec", "I", 0),
		("caplen", "I", 0),
		("len", "I", 0),
	)


class PcapLEPktHdr(pypacker.Packet):
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


# PCAP callbacks


def pcap_cb_init_write(self, snaplen=1500, linktype=DLT_EN10MB, **initdata):
	self._timestamp = 0
	header = PcapFileHdr(magic=TCPDUMP_MAGIC_NANO, snaplen=snaplen, linktype=linktype)
	logger.debug("writing fileheader %r", header)
	self._fh.write(header.bin())


def pcap_cb_write(self, bts, **metadata):
	ts = metadata.get("ts", self._timestamp + 1000000)
	self._timestamp = ts
	sec = int(ts / 1000000000)
	nsec = ts - (sec * 1000000000)

	# logger.debug("paket time sec/nsec: %d/%d", sec, nsec)
	n = len(bts)
	self._fh.write(pack_IIII(sec, nsec, n, n))
	self._fh.write(bts)


def pcap_cb_init_read(self, **initdata):
	buf = self._fh.read(24)
	# file header is skipped per default (needed for __next__)
	self._fh.seek(24)
	# this is not needed anymore later on but we set it anyway
	fhdr = PcapFileHdr(buf)
	self._closed = False

	if fhdr.magic not in [TCPDUMP_MAGIC, TCPDUMP_MAGIC_NANO, TCPDUMP_MAGIC_SWAPPED, TCPDUMP_MAGIC_NANO_SWAPPED]:
		return False

	# handle file types
	if fhdr.magic == TCPDUMP_MAGIC:
		self._resolution_factor = 1000
		# Note: we could use PcapPktHdr/PcapLEPktHdr to parse pre-packetdata but calling unpack directly
		# greatly improves performance
		self._callback_unpack_meta = unpack_IIII
	elif fhdr.magic == TCPDUMP_MAGIC_NANO:
		self._resolution_factor = 1
		self._callback_unpack_meta = unpack_IIII
	elif fhdr.magic == TCPDUMP_MAGIC_SWAPPED:
		fhdr = PcapLEFileHdr(buf)
		self._resolution_factor = 1000
		self._callback_unpack_meta = unpack_IIII_le
	elif fhdr.magic == TCPDUMP_MAGIC_NANO_SWAPPED:
		fhdr = PcapLEFileHdr(buf)
		self._resolution_factor = 1
		self._callback_unpack_meta = unpack_IIII_le
	else:
		raise ValueError("invalid tcpdump header, magic value: %s" % fhdr.magic)

	self._lowest_layer_new = PCAPTYPE_CLASS.get(fhdr.linktype, None)

	def is_resolution_nano(obj):
		"""return -- True if resolution is in Nanoseconds, False if milliseconds."""
		return obj._resolution_factor == 1000

	self.is_resolution_nano = types.MethodType(is_resolution_nano, self)
	return True


def pcap_cb_read(self):
	buf = self._fh.read(16)

	if not buf:
		raise StopIteration

	d = self._callback_unpack_meta(buf)
	buf = self._fh.read(d[2])

	return d[0] * 1000000000 + (d[1] * self._resolution_factor), buf


def pcap_cb_btstopkt(self, meta, bts):
	return self._lowest_layer_new(bts)


# PCAPNG related
# Generic/filetype invariant related

FILETYPE_PCAP	= 0
FILETYPE_PCAPNG	= 1  # TODO: to be merged with pcapng.py

# type_id : [
#	cb_init_write(obj, **initdata),
#	cb_write(self, bytes, **metadata),
#	cb_init_read(obj, **initdata),
#	cb_read(self): metadata, bytes
#	cb_btstopkt(self, metadata, bytes): pkt
# ]
FILEHANDLER = {
	FILETYPE_PCAP: [
		pcap_cb_init_write, pcap_cb_write, pcap_cb_init_read, pcap_cb_read, pcap_cb_btstopkt
	]
	#FILETYPE_PCAPNG : [
	#	None, None, None
	#]
}


class FileHandler(object):
	def __init__(self, filename, accessmode):
		self._fh = open(filename, accessmode)
		self._closed = False

	def __enter__(self):
		return self

	def __exit__(self, objtype, value, traceback):
		self.close()

	def flush(self):
		self._fh.flush()

	def close(self):
		self._closed = True
		self._fh.close()


class PcapHandler(FileHandler):
	MODE_READ = 1
	MODE_WRITE = 2

	def __init__(self, filename, mode, filetype=FILETYPE_PCAP, **initdata):
		try:
			callbacks = FILEHANDLER[filetype]
		except IndexError:
			raise Exception("unknown filehandler type for mode %d: %d" % (mode, filetype))

		if mode == PcapHandler.MODE_WRITE:
			super().__init__(filename, "wb")
			callbacks[0](self, **initdata)
			self.write = types.MethodType(callbacks[1], self)
		elif mode == PcapHandler.MODE_READ:
			super().__init__(filename, "rb")
			ismatch = False

			for pcaptype, callbacks in FILEHANDLER.items():
				self._fh.seek(0)
				# init callback
				ismatch = callbacks[2](self, **initdata)

				if ismatch:
					logger.debug("found handler for file: %x", pcaptype)
					# read callback
					self.__next__ = types.MethodType(callbacks[3], self)
					self.read = types.MethodType(callbacks[3], self)
					# bytes-to-packet callback
					self._btstopkt = types.MethodType(callbacks[4], self)
					break
			if not ismatch:
				raise Exception("no matching handler found")
		else:
			raise Exception("wrong mode: %d" % mode)

	def read_packet(self, pktfilter=None):
		"""
		return -- (metadata, packet) if packet can be created from bytes
			else (metadata, bytes). For pcap/tcpdump metadata is a nanoseconds timestamp
		"""
		while True:
			# until StopIteration
			meta, bts = self.__next__()

			try:
				pkt = self._btstopkt(meta, bts)
			except Exception as ex:
				logger.warning("could not create packets from bytes: %r", ex)
				return meta, bts

			try:
				if pktfilter(pkt):
					return meta, pkt
			except AttributeError:
				# no packet filter? return raw bytes
				return meta, bts

	def read_packet_iter(self, pktfilter=lambda pkt: True):
		"""
		return -- iterator yielding (metadata, packet)
		"""
		if self._closed:
			raise StopIteration

		while True:
			yield self.read_packet(pktfilter=pktfilter)

	def __iter__(self):
		"""
		return -- (metadata, bytes)
		"""
		if self._closed:
			raise StopIteration

		while True:
			yield self.__next__()


class Writer(PcapHandler):
	"""
	Simple pcap writer supporting pcap format.
	"""
	def __init__(self, filename, filetype=FILETYPE_PCAP, **initdata):
		super().__init__(filename, PcapHandler.MODE_WRITE, **initdata)


class Reader(PcapHandler):
	"""
	Simple pcap file reader supporting pcap format.
	"""
	def __init__(self, filename, filetype=FILETYPE_PCAP, **initdata):
		super().__init__(filename, PcapHandler.MODE_READ, **initdata)
