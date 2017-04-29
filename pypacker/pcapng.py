"""
Primaly refer:
	http://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html

TODO:
	* Writer class implementation.
	* Options getter/setter implementation.
	* Support nanosecond.
		Investigate the implementation to support multi interface.

Limitation:
	Because the generally considered to only use wireshark,	support header
	referenced to http://wiki.wireshark.org/Development/PcapNg

	Mostly the following limitations
		* Only a single section
		Support:
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			| SHB v1.0  |         Data          |
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		Not support:
			|<-   1st Section   ->|<-   2nd Section   ->| ... |
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			| SHB v1.0  |  Data   | SHB v1.1  |  Data   | ... |
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	Wireshark wiki written as "Capture file will have the following
	pcap-ng blocks: SHB, IDB, IDB, IDB, EPB, EPB, ..., ISB, ISB, ISB.".
		* SHB(Section Header Block)
		* IDB(Interface Description Block)
		* EPB(Enhanced Packet Block) <-- this is DUMP PACKET
		* ISB(Interface Statistics Block)
	Thus, created by assuming the following figure of block format:
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			| SHB | IDB | IDB | EPB | EPB | ... | EPB | ISB | ISB |
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	( 'A`)< Only file reading...

TODO: generic interface for different reader/writer
"""

from pypacker import pypacker
import struct

# avoid references
unpack = struct.unpack

PCAPNG_IDB = 0x00000001		# Interface Description Block
# PCAPNG_PB  = 0x00000002		# (obsolated) Packet Block
PCAPNG_SPB = 0x00000003			# Simple Packet Block
# PCAPNG_NRB = 0x00000004		# Name Resolution Block
PCAPNG_ISB = 0x00000005			# Interface Statistics Block
PCAPNG_EPB = 0x00000006			# Enhanced Packet Block
PCAPNG_SHB = 0x0A0D0D0A			# Section Header Block

PCAPNG_VERSION_MAJOR = 1
PCAPNG_VERSION_MINOR = 0

BE_MAGIC = 0x1A2B3C4D
LE_MAGIC = 0x4D3C2B1A

OPT_ENDOFOPT = 0
OPT_COMMENT = 1
OPT_IDB_IF_NAME = 2
OPT_IDB_IF_DESC = 3
OPT_IDB_IF_V4ADDR = 4
OPT_IDB_IF_V6ADDR = 5
OPT_IDB_IF_MAC = 6
OPT_IDB_IF_EUI = 7
OPT_IDB_IF_SPEED = 8
OPT_IDB_IF_TSRESOL = 9
OPT_IDB_IF_TZONE = 10
OPT_IDB_IF_FILTER = 11
OPT_IDB_IF_OS = 12
OPT_IDB_IF_FCSLEN = 13
OPT_IDB_IF_TSOFFSET = 14
OPT_ISB_STARTTIME = 2
OPT_ISB_ENDTIME = 3
OPT_ISB_IFRECV = 4
OPT_ISB_IFDROP = 5
OPT_ISB_FILTERACCEPT = 6
OPT_ISB_OSDROP = 7
OPT_ISB_USRDELIV = 8
OPT_SHB_HARDWARE = 2
OPT_SHB_OS = 3
OPT_SHB_USERAPPL = 4

IDB_OPTIONS = {
	1: "opt_comment",
	2: "if_name",
	3: "if_description",
	4: "if_IPv4addr",
	5: "if_IPv6addr",
	6: "if_MACaddr",
	7: "if_EUIaddr",
	8: "if_speed",
	9: "if_tsresol",
	10: "if_tzone",
	11: "if_filter",
	12: "if_os",
	13: "if_fcslen",
	14: "if_tsoffset",
}

ISB_OPTIONS = {
	1: "opt_comment",
	2: "isb_starttime",
	3: "isb_endtime",
	4: "isb_ifrecv",
	5: "isb_ifdrop",
	6: "isb_filteraccept",
	7: "isb_osdrop",
	8: "isb_usrdeliv",
}

SHB_OPTIONS = {
	1: "opt_comment",
	2: "shb_hardware",
	3: "shb_os",
	4: "shb_userappl",
}


def _32bit_alignment(offset, length):
	return (offset + length + 3) & 0xFFFC


class OPT(pypacker.Packet):
	"""General option format"""
	__hdr__ = (
		("code", "H", 0),
		("length", "H", 0),
	)


class SHB(pypacker.Packet):
	"""Section Header Block (mandatory)"""
	__hdr__ = (
		("type", "I", PCAPNG_SHB),
		("block_length", "I", 0),
		("magic", "I", BE_MAGIC),
		("v_major", "H", PCAPNG_VERSION_MAJOR),
		("v_minor", "H", PCAPNG_VERSION_MINOR),
		("section_length", "Q", 0),
	)

	class OPT(OPT):
		# TODO: getter and setter
		pass


class SHB_LE(SHB):
	__byte_order__ = "<"

	class OPT(SHB.OPT):
		__byte_order__ = "<"


class IDB(pypacker.Packet):
	"""Interface Description Block (mandatory)"""
	__hdr__ = (
		("type", "I", PCAPNG_IDB),
		("block_length", "I", 0),
		("linktype", "H", 0),
		("reserved", "H", 0),
		("snaplen", "I", 0),
	)

	class OPT(OPT):
		# TODO: getter and setter
		pass


class IDB_LE(IDB):
	__byte_order__ = "<"

	class OPT(IDB.OPT):
		__byte_order__ = "<"


class EPB(pypacker.Packet):
	"""Enhanced Packet Block (optional)"""
	__hdr__ = (
		("type", "I", PCAPNG_EPB),
		("block_length", "I", 32),
		("interface_id", "I", 0),
		("ts_high", "I", 0),
		("ts_low", "I", 0),
		("cap_len", "I", 0),
		("len", "I", 0),
	)

	class OPT(OPT):
		# TODO: getter and setter
		pass


class EPB_LE(EPB):
	__byte_order__ = "<"

	class OPT(EPB.OPT):
		__byte_order__ = "<"


class SPB(pypacker.Packet):
	"""Simple Packet Block (optional)"""
	__hdr__ = (
		("type", "I", PCAPNG_SPB),
		("block_length", "I", 16),
		("len", "I", 0),
	)


class SPB_LE(SPB):
	__byte_order__ = "<"


class ISB(pypacker.Packet):
	"""Interface Statistics Block (optional)"""
	__hdr__ = (
		("type", "I", PCAPNG_ISB),
		("block_length", "I", 0),
		("interface_id", "I", 1),
		("ts_high", "I", 0),
		("ts_low", "I", 0),
	)

	class OPT(OPT):
		# TODO: getter and setter
		pass


class ISB_LE(ISB):
	__byte_order__ = "<"

	class OPT(ISB.OPT):
		__byte_order__ = "<"


# TODO: Writer
class Writer(object):
	def __init__(self):
		pass


class Reader(object):
	def __init__(self, fileobj=None,
		filename=None,
		lowest_layer=None,
		filter=None,
		ts_conversion=True):

		self.idbs = []
		self.isbs = []
		self.__block_order__ = ""
		self._IDB = IDB
		self._EPB = EPB
		self._ISB = ISB
		self._SHB = SHB

		# handle source modes
		if fileobj is not None:
			self.__fh = fileobj
		elif filename is not None:
			self.__fh = open(filename, "rb")
		else:
			raise Exception("No fileobject and no filename given..nothing to read!!!")

		"""
		How to parse:

			|--> Parse1       |--> iter               | Parse2 <--|
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			| SHB | IDB | IDB | EPB | EPB | ... | EPB | ISB | ISB |
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

			1. Parse from head and stop at the EPB pointer.
			2. Parse from tail and stop at the EPB pointer
				or not supported header.
		"""
		# Parse1
		while 1:
			buf = self.__fh.read(8)
			block_type, block_length = unpack(self.__block_order__ + "2I", buf)
			if block_type == PCAPNG_SHB:
				buf = buf + self.__fh.read(block_length - len(buf))
				self.shb = self._SHB(buf)
				# Endian is decided magic in SHB.
				if self.shb.magic == LE_MAGIC:
					self.__to_le()
					self.shb = self._SHB(buf)
				self.shb.opts = self.__unpack_opt(buf, self._SHB)

			elif block_type == PCAPNG_IDB:
				buf = buf + self.__fh.read(block_length - len(buf))
				_idb = self._IDB(buf)
				_idb.opts = self.__unpack_opt(buf, self._IDB)
				self.idbs.append(_idb)

			elif block_type == PCAPNG_EPB:
				self.__iter_pos = self.__fh.tell() - 8
				self.__next__ = self._next_bytes_conversion
				# TODO: Support nanosecond
				self.__resolution_factor = 1000000.0
				break

			else:
				break

		# Parse2
		"""
		1. Read Block Total Length from tail.
		2. Seek reverse the Block Total Length.
		3. Same Parse1.

		0                   1                   2                   3
		0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <---2
		|                          Block Type                           | 3
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
		|                      Block Total Length                       | V
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		/                          Block Body                           /
		/          /* variable length, aligned to 32 bits */            /
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|                      Block Total Length                       |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <---1
		"""
		tail_offset = 0
		while 1:
			self.__fh.seek(-1 * (4 + tail_offset), 2)
			block_length = unpack(self.__block_order__ + "I", self.__fh.read(4))[0]
			self.__fh.seek(-1 * block_length, 1)
			buf = self.__fh.read(8)
			block_type, block_length = unpack(self.__block_order__ + "2I", buf)
			tail_offset += block_length

			if block_type == PCAPNG_ISB:
				buf = buf + self.__fh.read(block_length - len(buf))
				_isb = self._ISB(buf)
				_isb.opts = self.__unpack_opt(buf, self._ISB)
				self.isbs.append(_isb)

			else:
				break

	def __to_le(self):
		self.__block_order__ = "<"
		self._IDB = IDB_LE
		self._EPB = EPB_LE
		self._ISB = ISB_LE
		self._SHB = SHB_LE

	def __unpack_opt(self, buf, BLOCK):
		offset = BLOCK._hdr_fmt.size
		opts = []
		while 1:
			opt_hdr = buf[offset:offset + OPT._hdr_fmt.size]
			if not opt_hdr:
				break
			code, length = unpack(self.__block_order__ + "2H", opt_hdr)
			opt = BLOCK.OPT(buf[offset:offset + OPT._hdr_fmt.size + length])
			if opt.code == OPT_ENDOFOPT:
				break
			opts.append(opt)
			offset = _32bit_alignment(offset + OPT._hdr_fmt.size, length)
		return opts

	def _next_bytes_conversion(self):
		"""
		Standard __next__ implementation. Needs to be a sepearte method to be called by producer.

		return -- (timestamp_microseconds, Enhanced_Packet_Block) for pcap-reader.
			Access DUMP DATA: Enhanced_Packet_Block.data
		"""
		buf = self.__fh.read(8)
		if not buf:
			raise StopIteration

		block_type, block_length = unpack(self.__block_order__ + "2I", buf)
		if not block_type == PCAPNG_EPB:
			raise StopIteration

		buf = buf + self.__fh.read(block_length - len(buf))
		_epb = self._EPB(buf)
		_epb.opts = self.__unpack_opt(buf, self._EPB)

		return (((_epb.ts_high << 32) + _epb.ts_low) / self.__resolution_factor, _epb)

	def __iter__(self):
		"""
		return -- (timestamp, Enhanced Packet Block) for pcap-reader depending on configuration.
		"""
		self.__fh.seek(self.__iter_pos)
		while True:
			try:
				yield self.__next__()
			except StopIteration:
				break
