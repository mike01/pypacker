"""802.11 beacon fetcher"""

from pypacker import pypacker
from pypacker import psocket
from pypacker.layer12 import arp, ethernet, ieee80211, prism, radiotap
import time

wlan_monitor_if		= "prism0"


wlan_reader	= psocket.SocketHndl(wlan_monitor_if)
print("please wait for wlan traffic to show up")

aps_found	= {}
time_start	= time.time()

for i in range(10000):
	raw_bytes = wlan_reader.recv()
	#drvinfo = radiotap.Radiotap(raw_bytes)
	drvinfo = prism.Prism(raw_bytes)

	if i % 100 == 0:
		print("packets/s: %d" % (i / (time.time() - time_start)) )

	try:
		beacon = drvinfo[ieee80211.IEEE80211.Beacon]
		data	= drvinfo[ieee80211.IEEE80211.DataFromDS]

		if data is not None:
			print("got some data: %s -> %s" % (data.src_s,
				data.dst_s))
			continue
		if beacon is None:
			continue

		#mac_ap = drvinfo[ieee80211.IEEE80211.MGMTFrame].bssid
		#mac_ap = pypacker.mac_bytes_to_str(mac_ap)
		ie_ssid	= beacon.ies[0].data
		mac_ap	= drvinfo[ieee80211.IEEE80211.MGMTFrame].bssid
		mac_ap	= pypacker.mac_bytes_to_str(mac_ap)

		signal	= 0xffffffff ^ drvinfo.dids[3].value
		quality	= drvinfo.dids[4].value

		if not mac_ap in aps_found:
			aps_found[mac_ap] = (ie_ssid, signal, quality)
			print("found new AP: %s, %s, -%d dB, Quality: %d" % (mac_ap, ie_ssid, signal, quality))
	except Exception as e:
		print(e)
