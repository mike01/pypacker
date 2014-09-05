from pypacker.psocket import SocketHndl
from pypacker.ppcap import Reader
import pypacker.ppcap as ppcap
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.visualizer import Visualizer
from pypacker.pypacker import Packet

from graph_tool.all import *

import time


class IterClassSocket(object):
	"""
	Wrapper class to iterate over packets from psocket
	"""
	def __init__(self):
		self.psock = SocketHndl(iface_name="wlan0", timeout=10)

	def __iter__(self):
		while True:
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
			#time.sleep(0.5)
			try:
				#print("reading next....")
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


def config_cb(packet, v_src, v_dst, edge, config_v, config_e):
	print("config_cb: %r/%r/%r" % (v_src, v_dst, edge))
	#print("got packet: %r" % packet)
	#print("got packet...")
	v_src.cnt_n += 1
	v_dst.cnt_n += 1
	edge.cnt_n += 1

	try:
		v_src.ip_src_s = packet[ip.IP].src_s
		v_dst.ip_dst_s = packet[ip.IP].dst_s
	except AttributeError:
		# not an IP-packet
		pass

	try:
		#hndl = packet[ip.IP].body_handler.body_handler
		hndl = packet.top_layer
		if hndl is not None:
			edge.protos_e.add(hndl.__class__.__name__)
	except Exception:
		pass

	#config_v["text"][v_src] = v_src.ip_src_s + " (out: %d)" % v_src.cnt_n
	#config_v["text"][v_dst] = v_dst.ip_dst_s + "(out: %d)" % v_dst.cnt_n
	config_v["text"][v_src] = v_src.ip_src_s
	config_v["text"][v_dst] = v_dst.ip_dst_s

	if edge is not None:
		config_e["text"][edge] = "%d|%s" % (edge.cnt_n, ",".join(edge.protos_e))

#vertexprops = [["text_distance", "int", 3]]
vertexprops = []
#edgeprops = [["text_distance", "int32_t", 0]]
edgeprops = []

vis = Visualizer(IterClassFile(),
		src_dst_cb,
		config_cb=config_cb,
		additional_vertexprops=vertexprops,
		additional_edgeprops=edgeprops,
		node_timeout=4)
vis.start()

try:
	time.sleep(99999)
except:
	print("endless sleep was interrupted")
vis.stop()
