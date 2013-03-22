"""Packet reader and write routines (pcap, sockets)."""

from pypacker import pypacker
from pypacker.layer12 import ethernet
from pypacker.layer4 import tcp

import sys, time
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
# socket type for capturing
ETH_P_IP			= 0x800

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
	Simple pcap dumpfile or socket writer.
	"""
	def __init__(self, fileobj=None, snaplen=1500, linktype=DLT_EN10MB, iface_name="lo"):
		"""
		fileobj = create a pcap-writer giving a file object retrieved by "open(...)"
		iface_name = create a socket-writer giving the name of an interface (default is "lo")
		"""
		self.__socket = None

		if fileobj is not None:
			self.__f = fileobj
			if sys.byteorder == "little":
				fh = LEFileHdr(snaplen=snaplen, linktype=linktype)
			else:
				fh = FileHdr(snaplen=snaplen, linktype=linktype)
			self.__f.write(fh.bin())
		elif iface_name is not None:
			self.__socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, ETH_P_IP)
			self.__socket.bind((iface_name, ETH_P_IP))

	def writepkt(self, pkt, ts=None):
		"""Write the given packet's bytes."""
		if self.__socket is not None:
			self.__socket.write(pkt.bin)
			return

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
		self.__f.write(ph.bin())
		self.__f.write(s)

	def close(self):
		if self.__socket is not None:
			self.__socket.close()
		else:
			self.__f.close()

class Reader(object):
	"""
	Simple pcap file and socket reader. Using iterators this
	will return "timestamp, byte string" for pcap-files and
	"byte string" for interfaces.
	"""

	def __init__(self, fileobj=None, iface_name="lo"):
		"""
		Create a pcap or socket reader.
		fileobj = create a pcap-reader giving a file object retrieved by "open(...)"
		iface_name = create a socket-reader giving the name of an interface (default is "lo")
		"""
		self.__socket = None

		if fileobj is not None:
			#self.name = fileobj.name
			#self.fd = fileobj.fileno()
			self.__f = fileobj
			buf = self.__f.read(FileHdr.__hdr_len__)
			# TODO: remove if not needed
			self.__f.seek(FileHdr.__hdr_len__)
			self.__fh = FileHdr(buf)
			self.__ph = PktHdr


			if self.__fh.magic == PMUDPCT_MAGIC:
				self.__fh = LEFileHdr(buf)
				self.__ph = LEPktHdr
			elif self.__fh.magic != TCPDUMP_MAGIC:
				raise ValueError("invalid tcpdump header")

			if self.__fh.linktype in dltoff:
				self.dloff = dltoff[self.__fh.linktype]
			else:
				self.dloff = 0
			#self.snaplen = self.__fh.snaplen
			#self.filter = ""
		elif iface_name is not None:
			self.__socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, ETH_P_IP)
			self.__socket.bind((iface_name, ETH_P_IP))

		# Buffer to hold packets to be consumed prior the file-stream
		# This can happen on: merging packets
		self.__packet_buf = []

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
		"""return (timestamp, b"...") for pcap-reader or (0, b"...") for sockets"""
		# first consume buffered packets
		if len(self.__packet_buf) > 0:
			return self.__packet_buf.pop(0)
		# socket given
		if self.__socket is not None:
			return (0, sock.recv(65536))

		buf = self.__f.read(PktHdr.__hdr_len__)

		if not buf:
			raise StopIteration

		hdr = self.__ph(buf)
		buf = self.__f.read(hdr.caplen)

		return (hdr.tv_sec + (hdr.tv_usec / 1000000.0), buf)

	def __iter__(self):
		"""return (timestamp, b"...") for pcap-reader or (0, b"...") for sockets"""
		self.__f.seek(FileHdr.__hdr_len__)

		while 1:
			# first consume buffered packets
			if len(self.__packet_buf) > 0:
				yield self.__packet_buf.pop(0)
				continue
			# socket given
			if self.__socket is not None:
				yield (0, sock.recv(65536))
				continue

			buf = self.__f.read(PktHdr.__hdr_len__)

			if not buf:
				break
			hdr = self.__ph(buf)
			buf = self.__f.read(hdr.caplen)

			yield (hdr.tv_sec + (hdr.tv_usec / 1000000.0), buf)


	def merge(self, first_packet, dir_rev=True, lowest_layer=ethernet.Ethernet, transport_layer=tcp.TCP):
		"""
		Try to merge data for packets with data_missing > 0. In this case data can be
		spread over multiple packets e.g. data in layer 5/6/7 spread over several
		TCP-segments. This will remove merged bytes from the stream and retain all others.
		Examples:
			1) Merge packets giving the request
			# send a request
			write.write(sock, packet_request)
			# merge response packets
			merged_response = reader.merge(packet_request)

			2) Merge packets after encountering a partial message
			# read some packets
			for ts, buf in reader:
				eth = Ethernet(buf)
				http = eth[HTTP]
				# encounter missing data
				if http is not None and http.data_missing > 0:
					# merge to complete HTTP message
					http = reader.merge(http, dir_rev=False)

		first_packet = the packet which lead to the answer-packets to be merged or 
			the first encountered packet whith data_missing > 0
		dir_rev = direction of the packet "first_packet". True = the given packet was the
			"request" packet, False = a response-packet was given with data_missing > 0
		lowest_layer = The lowest layer to be used to create packets from read bytes (default Ethernet)
		transport_layer = Layer on which segmentation takes place (default TCP)
		return: Object representing data in the merged layer. This can be the
		original data-handler itself if no merge was done.
		"""
		res_ret = None
		packet_transport = packet[transport_layer]

		if packet_transport is None:
			return None

		handler = packet_transport.handler
		logger.debug("handler to be merged: " % handler)

		# sanity checks
		if handler is None or (not dir_rev and handler.data_missing == 0):
			logger.warning("could not merge data: no handler or no data missing on given packet")
			return handler

		packets_partial = []
		data_merged = 0

		#
		# collect partial packets, sort by order and merge
		#
		for ts, buf in self:
			p = lowest_layer(buf)
			p_transport = p[transport_layer]
			# transport layer not found (eg UDP instead of TCP)
			if p_transport is None:
				self.__packets_buffered.append((ts, buf))
				continue

			direction = p.direction(first_packet)
			# correct direction (checks for MAC, port etc)
			if self.dir_rev and direction != pypacker.Packet.DIR_REV or \
				not self.dir_rev and direction != pypacker.Packet.DIR_SAME:
					self.__packets_buffered.append((ts, buf))
					continue

			handler_read = p_transport.handler
			# we only merge handler with incomplete data
			if type(handler_read) is bytes or handler_read.data_missing == 0:
				self.__packets_buffered.append((ts, buf))
				continue

			logger.debug("new partial segment found: %s" % handler_read)
			packets_partial.append(p_transport)
			data_merged += len(handler_read.bin())

			# TODO: this can consume all packets, set break criteria to avoid this
			# (check for transport-layer specific criteria like FIN, RST etc?)
			if data_merged >= handler.data_missing:
				logger.debug("enough data collected, continuing to merge")
				break

		#
		# order bytes for correct merging
		#
		# for now only TCP is implemented
		if packet_transport is tcp.TCP:
			logger.debug("sorting partial segments for merging: %d" % len(packets_partial))
			def criteria_func(p_tcp):
				# TODO: check for SEQ/ACK overflow
				return tuple(p_tcp.seq, p_tcp.ack)

			packets_partial = sorted(packets_partial, key=criteria_func)
			# NOW we can savely merge
			merged = b"".join(p.data for p in packets_partial)
			res_ret = handler.__class__(merged)
		else:
			raise Exception("transport layer not implemented for merging: %s" % packet_transport)
		
		return res_ret 

	def close(self):
		if self.__socket is not None:
			self.__socket.close()
		else:
			self.__f.close()
