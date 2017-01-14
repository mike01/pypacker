"""
This script aims to find bugs by parsing arbitrary packets.
Packets leading to errors will be dumped to file for later analyzis.
"""
import sys

from pypacker.layer12 import ethernet
from pypacker import ppcap
from pypacker import psocket


def readndump(filename="bugpackets.pcap", iface_name="lo"):
	pcap = ppcap.Writer(filename=filename)
	psock = psocket.SocketHndl(iface_name=iface_name, timeout=999999)

	for bts in psock:
		try:
			eth = ethernet.Ethernet(bts)

			if bts != eth.bin():
				raise Exception("parsing was buggy: %r != %r" % (bts, eth.bin()))
			tmp = "%r" % eth
			#print(bts)
			#print("%r" % eth)
			#print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
			print(".", end="")
			print("%r" % eth.highest_layer.__class__.__name__, end="")

			sys.stdout.flush()

			for layer in eth:
				if layer.dissect_error:
					raise Exception("parsing was buggy: %r != %r" % (bts, eth.bin()))
		except Exception as ex:
			print("\nError while parsing: %r" % ex)
			pcap.write(bts)
	pcap.close()
	psock.close()

if __name__ == "__main__":
	readndump(filename="bugpackets.pcap", iface_name="eth0")
