"""
Utility functions.
"""
import subprocess
import re
import os
import logging

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


MODE_MANAGED	= 0
MODE_MONITOR	= 1
MODE_UNKNOWN	= 2

_MODE_STR_INT_TRANSLATE = {
		b"managed" : MODE_MANAGED,
		b"monitor" : MODE_MONITOR,
		b"" : MODE_UNKNOWN
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
		return MODE_UNKNOWN


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

	monitor_active -- activate/deactivate monitor mode
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
	logger.debug("loading oui file")
	current_dir = os.path.dirname(os.path.realpath(__file__))
	try:
		fh = open(current_dir + "/oui.txt", "r")

		for line in fh:
			hex_vendor = PROG_MACVENDOR.findall(line)

			if len(hex_vendor) > 0:
				# print(hex_vendor)
				MAC_VENDOR[hex_vendor[0][0].replace("-", ":")] = hex_vendor[0][1]
		fh.close()
	except Exception as e:
		logger.warning("could not load out.txt, is it present here? %s" % current_dir)



def get_vendor_for_mac(mac):
	"""
	mac -- First bytes of mac address as "AA:BB:CC" (uppercase!)
	return -- found vendor string or empty string
	"""
	if len(MAC_VENDOR) == 0:
		_load_mac_vendor()

	try:
		return MAC_VENDOR[mac]
	except KeyError:
		return ""
