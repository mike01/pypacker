"""
Utility functions.
"""
import subprocess
import re
import os
import logging
import math

log = math.log

from pypacker import pypacker as pypacker
mac_bytes_to_str = pypacker.mac_bytes_to_str

logger = logging.getLogger("pypacker")


def switch_wlan_channel(iface, channel, shutdown_prior=False):
	"""
	Switch wlan channel to channel.
	Requirements: ifconfig, iwconfig

	iface -- interface name
	channel -- channel numer to be set as number
	shutdown_prior -- shut down interface prior to setting channel
	"""
	if shutdown_prior:
		cmd_call = ["ifconfig", iface, "down"]
		subprocess.check_call(cmd_call)

	cmd_call = ["iwconfig", iface, "channel", "%d" % channel]
	subprocess.check_call(cmd_call)

	if shutdown_prior:
		cmd_call = ["ifconfig", iface, "up"]
		subprocess.check_call(cmd_call)


WLAN_MODE_MANAGED	= 0
WLAN_MODE_MONITOR	= 1
WLAN_MODE_UNKNOWN	= 2

_MODE_STR_INT_TRANSLATE = {
	b"managed": WLAN_MODE_MANAGED,
	b"monitor": WLAN_MODE_MONITOR,
	b"": WLAN_MODE_UNKNOWN
}

PATTERN_MODE	= re.compile(b"Mode:(\w+) ")


def get_wlan_mode(iface):
	"""
	return -- [MODE_MANAGED | MODE_MONITOR | MODE_UNKNOWN]
	"""
	cmd_call = ["iwconfig", iface]
	output = subprocess.check_output(cmd_call)
	match = PATTERN_MODE.search(output)

	try:
		found_str = match.group(1).lower()
		return _MODE_STR_INT_TRANSLATE[found_str]
	except Exception as ex:
		print(ex)
		return WLAN_MODE_UNKNOWN


def is_interface_up(iface):
	"""
	return -- [True | False]
	"""
	cmd_call = ["ifconfig", iface]
	pattern_up = re.compile(b"^" + bytes(iface, "UTF-8") + b": flags=X", re.MULTILINE)
	output = subprocess.check_output(cmd_call)
	return pattern_up.search(output) is not None


def set_interface_mode(iface, monitor_active=None, state_active=None):
	"""
	Activate/deacivate monitor mode.
	Requirements: ifconfig, iwconfig

	monitor_active -- activate/deactivate monitor mode (only for wlan interfaces)
	active -- set interface state
	"""
	initial_state_up = is_interface_up(iface)

	if monitor_active is not None:
		cmd_call = ["ifconfig", iface, "down"]
		subprocess.check_call(cmd_call)
		mode = "monitor" if monitor_active else "managed"
		cmd_call = ["iwconfig", iface, "mode", mode]
		subprocess.check_call(cmd_call)

	"""
	try:
		cmd_call = ["iwconfig", iface, "retry", "0"]
		subprocess.check_call(cmd_call)
		# we don't need retry but this can improve performance
	except:
		# not implemented: don't care
		pass
	"""

	if state_active or initial_state_up:
		cmd_call = ["ifconfig", iface, "up"]
		subprocess.check_call(cmd_call)


PROG_CHANNEL = re.compile(b"Channel ([\d]+) :")


def get_available_wlan_channels(iface):
	"""
	Requirements: iwlist

	return -- channels as integer list
	"""
	cmd_call = ["iwlist", iface, "channel"]
	output = subprocess.check_output(cmd_call)
	# logger.debug("iwlist output: %r" % output)

	return [int(ch) for ch in PROG_CHANNEL.findall(output)]


def set_ethernet_address(iface, ethernet_addr):
	"""
	iface -- interface name
	ethernet_addr -- Ethernet address like "AA:BB:CC:DD:EE:FF"
	"""
	cmd_call = ["ifconfig", iface, "down"]
	subprocess.check_call(cmd_call)
	cmd_call = ["ifconfig", iface, "hw", "ether", ethernet_addr]
	subprocess.check_call(cmd_call)
	cmd_call = ["ifconfig", iface, "up"]
	subprocess.check_call(cmd_call)

MAC_VENDOR = {}
PROG_MACVENDOR = re.compile("([\w\-]{8,8})   \(hex\)\t\t(.+)")


def _load_mac_vendor():
	"""
	Load oui.txt containing mac->vendor mappings into MAC_VENDOR dictionary.
	See http://standards.ieee.org/develop/regauth/oui/oui.txt
	"""
	# logger.debug("loading oui file")
	current_dir = os.path.dirname(os.path.realpath(__file__))
	try:
		fh = open(current_dir + "/oui.txt", "r")

		for line in fh:
			hex_vendor = PROG_MACVENDOR.findall(line)

			if len(hex_vendor) > 0:
				# print(hex_vendor)
				MAC_VENDOR[hex_vendor[0][0].replace("-", ":")] = hex_vendor[0][1]
		fh.close()
	except Exception:
		logger.warning("could not load out.txt, is it present here? %s" % current_dir)


def get_vendor_for_mac(mac):
	"""
	mac -- First bytes of mac address as "AA:BB:CC" (uppercase!) or byte representation b"\xAA\xBB\xCC\xDD\xEE\xFF"
	return -- found vendor string or empty string
	"""
	if len(MAC_VENDOR) == 0:
		_load_mac_vendor()

	if type(mac) == bytes:
		# assume byte representation: convert to AA:BB:CC"
		mac = pypacker.mac_bytes_to_str(mac)[0:8]

	try:
		return MAC_VENDOR[mac]
	except KeyError:
		return ""


def is_special_mac(mac_str):
	"""
	Check if this is a special MAC adress (not a client address). Every MAC not found
	in the official OUI database is assumed to be non-client.

	mac_str -- Uppercase mac string like "AA:BB:CC[:DD:EE:FF]", first 3 MAC-bytes are enough
	"""
	return len(get_vendor_for_mac(mac_str[0:8])) == 0


def wlan_is_beacon(ieee80211_pkt):
	try:
		return ieee80211_pkt.subtype == 8 and ieee80211_pkt.type == 0
	except:
		return False


def wlan_extract_ap_macs(packet_radiotap, macs_aps):
	"""
	packet_radiotap -- packet
	macs_aps -- set()
	return -- True if an AP-MAC was extracted
	"""
	try:
		ieee80211_pkt = packet_radiotap.upper_layer
		ieee_handler = ieee80211_pkt.upper_layer
	except Exception as ex:
		logger.warning("Error while extracting AP MACs: %r" % ex)

	if wlan_is_beacon(ieee80211_pkt) or ieee80211_pkt.type == 0 or ieee80211_pkt.type == 2:
		# TODO: also use control frames where we don't have a BSSID field (more complicated)
		if ieee_handler.bssid is not None:
			macs_aps.add(ieee_handler.bssid)
			return True
		else:
			logger.warning("AP packet seems to have None bssid: %r" % packet_radiotap)
	return False


IEEE_FIELDS_SRC_DST_BSSID = ["src", "dst", "bssid"]


def wlan_extract_possible_client_macs(packet_radiotap, macs_clients):
	"""
	Extracts client MACs. There is a uncertainty that the found MAC
	is actually a client MAC due to missing state information so
	better check against a known-AP list.

	packet_radiotap -- packet
	macs_clients -- set()
	return -- True if a possible Client-MAC was extracted
	"""
	try:
		ieee80211_pkt = packet_radiotap.upper_layer
		ieee_handler = ieee80211_pkt.upper_layer
	except Exception as ex:
		logger.warning("Error while extracting client MACs: %r" % ex)
		logger.warning("%r" % packet_radiotap)
		return

	if wlan_is_beacon(ieee80211_pkt):
		# avoid unneccessary parsing
		return False

	macs_clients_tmp = []
	# management or control
	if ieee80211_pkt.type == 0 or ieee80211_pkt.type == 1:
		# both src/dst could be client
		for field in IEEE_FIELDS_SRC_DST_BSSID:
			try:
				macs_clients_tmp.append(ieee_handler.__getattribute__(field))
			except:
				pass
	# data
	elif ieee80211_pkt.type == 2:
		if ieee80211_pkt.from_ds == 1 and ieee80211_pkt.to_ds == 0:
			macs_clients_tmp.append(ieee_handler.dst)
		elif ieee80211_pkt.to_ds == 1 and ieee80211_pkt.from_ds == 0:
			macs_clients_tmp.append(ieee_handler.src)
	else:
		logger.warning("unknown ieee80211 type: %r (0/1/2 = mgmt/ctrl/data)" % ieee80211_pkt.type)

	found_clients = False

	for addr in macs_clients_tmp:
		#logger.debug("checking client mac: %r" % addr)
		# not an AP and not yet stored
		if addr not in macs_clients and not is_special_mac(addr):
			#logger.info("found possible client: %s\t%s, ieee type: %d" %
			#	(addr, utils.get_vendor_for_mac(addr), ieee80211_pkt.type))
			macs_clients.add(addr)
			found_clients = True
	return found_clients


ENTROPY_GRANULARITY_QUADRUPLE	= 0


def get_entropy(bts, granularity):
	symbol_count = {}
	symbol_len = 0
	if granularity == ENTROPY_GRANULARITY_QUADRUPLE:
		symbol_amount = 16

		for bt in bts:
			q1 = bt >> 4
			q2 = bt & 0x0F

			for val in [q1, q2]:
				try:
					symbol_count[val] += 1
				except:
					symbol_count[val] = 1

		symbol_len = len(bts) * 2  # 2 quadruples per byte
	else:
		logger.warning("invalid granularity: %d" % granularity)
		return -1

	entropy = 0
	#symbol_amount = len(symbol_count)

	for symbol, count in symbol_count.items():
		p = count / symbol_len
		entropy += -log(p, symbol_amount) * p

	return entropy
