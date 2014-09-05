from pypacker.visualizer import Visualizer
from pypacker.psocket import SocketHndl
import pypacker.ppcap as ppcap
from pypacker.layer12 import ieee80211, radiotap

import time


class IterClass(object):
	"""
	Wrapper class to iterate over packets from psocket
	"""
	def __init__(self):
		self.psock = SocketHndl(iface_name="mon0", timeout=10)

	def __iter__(self):
		while True:
			try:
				yield self.psock.recvp(lowest_layer=radiotap.Radiotap)[0]
			except Exception as e:
				print(e)
				continue
		self.psock.close()


def src_dst_cb(pkt):
	try:
		beacon = pkt[ieee80211.IEEE80211.Beacon]
		if beacon is not None:
		#	print("beacon!")
			return beacon.bssid_s, None

		data = pkt[ieee80211.IEEE80211.Dataframe]
		#print(pkt.top_layer)

		if data is not None:
			#print("got data!")
			return data.src_s, data.dst_s
	except Exception as e:
		print(e)
		pass
	return None, None


def config_cb(packet, v_src, v_dst, edge, config_v, config_e):
	#print("got packet...")
	#v_src.cnt_n += 1
	#v_dst.cnt_n += 1

	if packet[ieee80211.IEEE80211.Beacon] is not None:
		beacon = packet[ieee80211.IEEE80211.Beacon]
		v_src.mac_s = beacon.src_s
		v_src.ssid_s = beacon.params.find_value(0, extract_cb=lambda x: x.id).body_bytes.decode("utf-8")
		#config_v["text"][v_src] = v_src.mac_s + "|" + v_src.ssid_s
	elif packet[ieee80211.IEEE80211.Dataframe] is not None:
		data = packet[ieee80211.IEEE80211.Dataframe]
		#config_v["text"][v_src] = v_src.mac_s = data.src_s
		#v_src.mac_s = data.src_s
		v_src.mac_s = data.bssid_s
		if data.dst_s != "FF:FF:FF:FF:FF:FF":
			v_dst.mac_s = data.dst_s

		#if len(v_dst.mac_s) == 0:
		## only set if not already set
		#	config_v["text"][v_dst] = v_dst.mac_s = data.dst_s

	config_v["text"][v_src] = v_src.mac_s + "|" + v_src.ssid_s

	if edge is not None:
		config_v["text"][v_dst] = v_dst.mac_s + "|" + v_dst.ssid_s
		edge.cnt_n += 1
		config_e["text"][edge] = "(%s)" % edge.cnt_n

vis = Visualizer(IterClass(), src_dst_cb, config_cb=config_cb)
vis.start()
try:
	time.sleep(99999)
except:
	pass
vis.stop()
