"""
Check for unparsable files retrieved via network and save them to "parsefail.pcap"
"""
import sys
import time
import socket

from pypacker import psocket, ppcap, utils
from pypacker.layer12 import ethernet, radiotap

iface		= sys.argv[1]

print("opening (wlan?) interface: %s" % iface)
utils.set_wlan_monmode(iface)

sockhndl	= psocket.SocketHndl(iface_name=iface)
pcapwriter	= ppcap.Writer(filename="parsefail.pcap", linktype=ppcap.DLT_IEEE802_11_RADIO)
raw_bytes	= b""
cnt		= 0
time_start	= time.time()

while True:
	if cnt % 1000 == 0:
		print("%d pps" % (cnt / (time.time() - time_start)))
		cnt		= 0
		time_start	= time.time()

	cnt += 1
	try:
		raw_bytes = sockhndl.recv()
		rtap = radiotap.Radiotap(raw_bytes)
		rtap.dissect_full()
		#####
		#pcapwriter.write(raw_bytes)
	except socket.timeout:
		pass
	except Exception as e:
		print("Error while parsing: %s" % e)
		pcapwriter.write(raw_bytes)

pcapwriter.close()
sockhndl.close()
