"""Radiotap"""

from pypacker import pypacker, triggerlist
import struct
import logging

logger = logging.getLogger("pypacker")

RTAP_TYPE_80211 = 0

# Ref: http://www.radiotap.org
# Fields Ref: http://www.radiotap.org/defined-fields/all

# Present flags
TSFT_MASK		= 0x01000000
FLAGS_MASK		= 0x02000000
RATE_MASK		= 0x04000000
CHANNEL_MASK		= 0x08000000

FHSS_MASK		= 0x10000000
DB_ANT_SIG_MASK		= 0x20000000
DB_ANT_NOISE_MASK	= 0x40000000
LOCK_QUAL_MASK		= 0x80000000

TX_ATTN_MASK		= 0x00010000
DB_TX_ATTN_MASK		= 0x00020000
DBM_TX_POWER_MASK	= 0x00040000
ANTENNA_MASK		= 0x00080000

ANT_SIG_MASK		= 0x00100000
ANT_NOISE_MASK		= 0x00200000
RX_FLAGS_MASK		= 0x00400000

CHANNELPLUS_MASK	= 0x00000400
EXT_MASK		= 0x00000800


class FlagTriggerList(triggerlist.TriggerList):
	# no __init__ needed: we just add tuples
	def _pack(self):
		return b"".join( [ flag[1] for flag in self ] )


def get_channelinfo(channel_bytes):
	"""
	return -- [channel_mhz, channel_flags]
	"""
	return [struct.unpack("<H", channel_bytes[0:2])[0], struct.unpack("<H", channel_bytes[2:4])[0]]


class Radiotap(pypacker.Packet):
	__hdr__ = (
		("version", "B", 0),
		("pad", "B", 0),
		("len", "H", 0x0800),
		("present_flags", "I", 0),
		("flags", None, FlagTriggerList)	# stores: (MASK, value)
	)

	# TODO: check flags endiannes
	#__byte_order__ = "<"
	__byte_order__ = ">"

	#__RADIO_FIELDS = {
	#	TSFT_MASK : [("usecs", "Q", 0)],
	#	FLAGS_MASK : [("flags", "B", 0)],
	#	RATE_MASK : [("rate", "B", 0)],
	#	CHANNEL_MASK : [("channel_freq", "H", 0), ("channel_type", "H",  0)],

	#	FHSS_MASK : [("fhss", "B", 0), ("pattern", "B", 0)],
	#	DB_ANT_SIG_MASK : [("antsign_db", "B", 0)],
	#	DB_ANT_NOISE_MASK : [("antnoise_db", "B", 0)],
	#	LOCK_QUAL_MASK : [("lock", "H", 0)],

	#	TX_ATTN_MASK : [("tx_attn",  "H", 0)],
	#	DB_TX_ATTN_MASK : [("tx_attn_db", "H", 0)],
	#	DBM_TX_POWER_MASK : [("power_tx_dbm", "B", 0)],
	#	ANTENNA_MASK : [("antenna", "B",  0)],

	#	ANT_SIG_MASK : [("antsig",  "B", 0)],
	#	ANT_NOISE_MASK : [("antnoise", "B", 0)],
	#	RX_FLAGS_MASK : [("rx_flags", "H", 0)],
	#}

	__RADIO_FIELDS = {
		TSFT_MASK : ("Q", 8),
		FLAGS_MASK : ("B", 1),
		RATE_MASK : ("B", 1),
		# channel + flags
		CHANNEL_MASK : ("HH", 4),

		# fhss + pattern
		FHSS_MASK : ("BB", 2),
		DB_ANT_SIG_MASK : ("B", 1),
		DB_ANT_NOISE_MASK : ("B", 1),
		LOCK_QUAL_MASK : ("H", 2),

		TX_ATTN_MASK : ("H", 2),
		DB_TX_ATTN_MASK : ("H", 2),
		DBM_TX_POWER_MASK : ("B", 1),
		ANTENNA_MASK : ("B", 1),

		ANT_SIG_MASK : ("B", 1),
		ANT_NOISE_MASK : ("B", 1),
		RX_FLAGS_MASK : ("H", 2),
	}

	# we need ordered masks
	__MASK_LIST = [
			TSFT_MASK,
			FLAGS_MASK,
			RATE_MASK,
			CHANNEL_MASK,
			FHSS_MASK,
			DB_ANT_SIG_MASK,
			DB_ANT_NOISE_MASK,
			LOCK_QUAL_MASK,
			TX_ATTN_MASK,
			DB_TX_ATTN_MASK,
			DBM_TX_POWER_MASK,
			ANTENNA_MASK,
			ANT_SIG_MASK,
			ANT_NOISE_MASK,
			RX_FLAGS_MASK
			]

	# handle frame check sequence
	def __get_fcs(self):
		try:
			return self._fcs
		except AttributeError:
			return b""

	def __set_fcs(self, fcs):
		self._fcs = fcs

	fcs = property(__get_fcs, __set_fcs)

	def _dissect(self, buf):
		flags = struct.unpack(">I", buf[4:8] )[0]

		off = 8
		fcs_present = False
		# assume order of flags is correctly stated by "present_flags"
		# TODO: can't use dict because we need ordered masks -> OrderedDict
		for mask in Radiotap.__MASK_LIST:
			# flag not set
			if mask & flags == 0:
				continue

			# add all fields for the stated flag
			size = Radiotap.__RADIO_FIELDS[mask][1]
			value = buf[off : off + size]

			# FCS present?
			if mask == FLAGS_MASK and struct.unpack("B", value)[0] & 0x10 != 0:
				fcs_present = True

			#logger.debug("adding flag: %s" % str(mask))
			self.flags.append( (mask, value ))
			off += size

		pos_end = len(buf)

		if fcs_present:
			self._fcs = buf[-4:]
			pos_end = -4
		# now we got the correct header length
		self._parse_handler(RTAP_TYPE_80211, buf[self.hdr_len : pos_end])

	def bin(self):
		"""Custom bin(): handle FCS."""
		return pypacker.Packet.bin(self) + self.fcs


# load handler
from pypacker.layer12 import ieee80211

pypacker.Packet.load_handler(Radiotap,
	{
		RTAP_TYPE_80211 : ieee80211.IEEE80211
	}
)
