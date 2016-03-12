from pypacker.psocket import SocketHndl
from pypacker.ppcap import Reader
import pypacker.ppcap as ppcap

from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.visualizer import Visualizer
from pypacker.pypacker import Packet

import time


class IterClassSocket(object):
	"""
	Wrapper class to iterate over packets from psocket
	"""
	def __init__(self):
		self.psock = SocketHndl(iface_name="wlan0", timeout=10)

	def __iter__(self):
		while True:
			#time.sleep(0.5)
			try:
				yield self.psock.recvp()[0]
			except StopIteration:
				break
			except:
				continue
		self.psock.close()


class IterClassFile(object):
	"""
	Wrapper class to iterate over packets from psocket
	"""
	def __init__(self):
		self.reader = Reader(filename="../tests/packets_ether.pcap", lowest_layer=ethernet.Ethernet)

	def __iter__(self):
		while True:
			# time.sleep(0.5)
			try:
				# print("reading next....")
				pkt = self.reader.__next__()[1]
				if type(pkt) is bytes:
					print("only bytes..")
					continue
				yield pkt
			except StopIteration:
				break
			except:
				continue
		self.reader.close()


def src_dst_cb(pkt):
	try:
		return pkt[ip.IP].src_s, pkt[ip.IP].dst_s
	except:
		return None, None


def config_cb(packet, node_src, node_dst, edge, prop_src, prop_dst):
	prop_src.cnt_n += 1
	prop_dst.cnt_n += 1
	edge.cnt_n += 1

	try:
		node_src.ip_src_s = packet[ip.IP].src_s
		node_dst.ip_dst_s = packet[ip.IP].dst_s
	except AttributeError:
		# not an IP-packet
		pass

	node_src.attr["label"] = node_src.ip_src_s
	node_dst.attr["label"] = node_dst.ip_dst_s
	edge.attr["label"] = "cnt: %d" % edge.cnt_n

vis = Visualizer(IterClassSocket(),
		src_dst_cb,
		config_cb)
vis.start()

try:
	time.sleep(99999)
except:
	print("endless sleep was interrupted")
vis.stop()
