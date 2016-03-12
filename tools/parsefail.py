"""
Check for unparsable files retrieved via network and save them to "parsefail.pcap"
"""
import sys
import time
import socket

from pypacker import psocket, ppcap, utils
from pypacker.layer12 import ethernet, linuxcc, radiotap
from pypacker.layer3 import ip
from pypacker.layer4 import tcp
from pypacker.layer567 import http

iface		= sys.argv[1]

#print("opening (wlan?) interface: %s" % iface)
#utils.set_wlan_monmode(iface)

sockhndl	= psocket.SocketHndl(iface_name=iface, timeout=99999)
#pcapwriter	= ppcap.Writer(filename="parsefail.pcap", linktype=ppcap.DLT_IEEE802_11_RADIO)
pcapwriter	= ppcap.Writer(filename="parsefail.pcap")
raw_bytes	= b""
cnt		= 0
time_start	= time.time()

for bts in sockhndl:
	if cnt % 1000 == 0:
		print("%d pps" % (cnt / (time.time() - time_start)))
		time_start = time.time()
		cnt = 0

	cnt += 1

	try:
		#pkt = radiotap.Radiotap(bts)
		pkt = ethernet.Ethernet(bts)

		# print(pkt)
		# print(pkt.body_handler)
		"""
		if pkt[ip.IP] is not None:
			tmp = pkt[ip.IP].src_s
			tmp = pkt[ip.IP].dst_s
			tmp = pkt[ip.IP].body_handler.body_handler
		"""

		pkt.dissect_full()
		raw_bytes = pkt.bin()
		#print("%r" % pkt)
		# pcapwriter.write(raw_bytes)
		for layer in pkt:
			if layer.dissect_error:
				print("%r" % raw_bytes)
				print("%r" % pkt[tcp.TCP].body_bytes)
				pcapwriter.write(raw_bytes)
				print("writing bytes to file")
				break
		try:
			startline = pkt[http.HTTP].startline
			if startline is not None:
				print(startline)
		except Exception as e:
			#print(e)
			pass
	except socket.timeout:
		pass
	except Exception as e:
		# print(pkt.ieee80211)
		print(">>>>>>>>>>> Error while parsing: %r" % e)
		pcapwriter.write(raw_bytes)

pcapwriter.close()
sockhndl.close()
