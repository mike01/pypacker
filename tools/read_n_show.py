"""
Bird is the word..
"""
import sys

from pypacker import ppcap
from pypacker.layer12 import radiotap


def show_pcap(fname, cnt=1000):
	"""
	Read cnt packets from a pcap file, default: 1000
	"""
	f = open(fname, "rb")
	pcap = ppcap.Reader(f)

	cnt = 0

	for ts, buf in pcap:
		cnt += 1
		#if cnt > 1:
		#	continue
		print(">>> read packet %d" % cnt)
		rt = radiotap.Radiotap(buf)
		print("%r" % rt)
		print("%r" % rt.ieee80211)

		try:
			print("%r" % rt.ieee80211.dataframe)
		except:
			try:
				print("%r" % rt.ieee80211.assocreq)
			except:
				try:
					print("%r" % rt.ieee80211.beacon)
				except:
					try:
						print("%r" % rt.ieee80211.proberesp)
					except:
						try:
							print("%r" % rt.ieee80211.probereq)
						except:
							print("%r" % rt.ieee80211.assocresp)
	f.close()
#show_pcap("parsefail.pcap")
#show_pcap("parsefail_1.pcap")
show_pcap(sys.argv[1])
