"""802.11 beacon fetcher"""

from pypacker import psocket
from pypacker.layer12 import ieee80211, radiotap
import time

wlan_monitor_if	= "wlan1"

wlan_reader	= psocket.SocketHndl(iface_name=wlan_monitor_if, timeout=999)

print("please wait for wlan traffic to show up")

aps_found	= {}
time_start	= time.time()

for i in range(100000):
	raw_bytes = wlan_reader.recv()
	drvinfo = radiotap.Radiotap(raw_bytes)

	if i % 1000 == 0:
		print("packets/s: %d" % (i / (time.time() - time_start)))

	try:
		beacon = drvinfo[ieee80211.IEEE80211.Beacon]

		if beacon is None:
			continue

		mac_ap = beacon.src1_s
		#print(beacon)
		ie_ssid	= beacon.params[0].data

		#signal	= 0xffffffff ^ drvinfo.dids[3].value
		#quality	= drvinfo.dids[4].value

		if not mac_ap in aps_found:
			aps_found[mac_ap] = ie_ssid
			#print("found new AP: %s, %s, -%d dB, Quality: %d" % (mac_ap, ie_ssid, signal, quality))
			print("found new AP: %s %s" % (mac_ap, ie_ssid))
	except Exception as e:
		print(e)
		pass
