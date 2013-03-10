"""Radiotap"""

from .. import pypacker
from ..layer12.ieee80211 import IEEE80211

import logging
import struct

logger = logging.getLogger("pypacker")

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

class Radiotap(pypacker.Packet):
	__hdr__ = (
		("version", "B", 0),
		("pad", "B", 0),
		("len", "H", 0),
		("present_flags", "I", 0)
		)

	#__byte_order__ = "<"
	def __getlen(self):
		return struct.unpack("H", self._len)[0]
	def __setlen(self, newlen):
		self._len =  newlen
	#len = property(__getlen, __setlen)

	__RADIO_FIELDS = {
		TSFT_MASK : [("usecs", "Q", 0)],
		FLAGS_MASK : [("flags", "B", 0)],
		RATE_MASK : [("rate", "B", 0)],
		CHANNEL_MASK : [("channel", "H", 0), ("channel_flags", "H",  0)],

		FHSS_MASK : [("fhss", "B", 0), ("pattern", "B", 0)],
		DB_ANT_SIG_MASK : [("antsign_db", "B", 0)],
		DB_ANT_NOISE_MASK : [("antnoise_db", "B", 0)],
		LOCK_QUAL_MASK : [("lock", "H", 0)],

		TX_ATTN_MASK : [("tx_attn",  "H", 0)],
		DB_TX_ATTN_MASK : [("tx_attn_db", "H", 0)],
		DBM_TX_POWER_MASK : [("power_tx_dbm", "B", 0)],
		ANTENNA_MASK : [("antenna", "B",  0)],

		ANT_SIG_MASK : [("antsig",  "B", 0)],
		ANT_NOISE_MASK : [("antnoise", "B", 0)],
		RX_FLAGS_MASK : [("rx_flags", "H", 0)],
	}
	# we need ordered masks
	__MASK_LIST = [TSFT_MASK, FLAGS_MASK, RATE_MASK, CHANNEL_MASK, FHSS_MASK, DB_ANT_SIG_MASK, DB_ANT_NOISE_MASK,
			LOCK_QUAL_MASK, TX_ATTN_MASK, DB_TX_ATTN_MASK, DBM_TX_POWER_MASK, ANTENNA_MASK,
			ANT_SIG_MASK, ANT_NOISE_MASK, RX_FLAGS_MASK]

	# TODO: enable dynamic adding of header fields, update header length, using properties or Triggerlist?
	def _unpack(self, buf):
		flags = struct.unpack(">I", buf[4:8] )[0]

		# assume order of flags is correctly stated by "present_flags"
		# TODO: can't use dict because we need ordered masks
		for mask in Radiotap.__MASK_LIST:
			# flag not set
			if mask & flags == 0:
				continue
			# add all fields for the stated flag
			fields = Radiotap.__RADIO_FIELDS[mask]
			for f in fields:
				logger.debug("adding field: %s" % str(f))
				self._add_headerfield(f[0], f[1], f[2], skip_update=True)

		pypacker.Packet._update_fmtstr(self)
		# now we got the real header length, try to parse handler
		try:
			# just one handler for radiotap: ieee80211 data
			ieee80211 = IEEE80211(buf[self.__hdr_len__:])
			self._set_bodyhandler(ieee80211)
		except Exception as e:
			logger.debug("failed to parse ieee80211: %s" % e)

		pypacker.Packet._unpack(self, buf)
