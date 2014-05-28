"""
Utility functions.
"""
import subprocess
import re
import os
import logging

logger = logging.getLogger("pypacker")


def switch_wlan_channel(iface, channel):
	"""
	Switch wlan channel to channel.
	Requirements: iwconfig
	"""
	cmd_call = ["iwconfig", iface, "channel", "%d" % channel]
	subprocess.check_call(cmd_call)


def set_wlan_monmode(iface, monitor_active=True, reactivate=True):
	"""
	Activate/deacivate monitor mode.
	Requirements: ifconfig, iwconfig

	monitor_active -- activate/deactivate monitor mode
	reactivate -- set interface to acive at the end
	"""
	#if monitor_active:
	## check if allready activated
	#	cmd_call = ["iwconfig", iface]
	#	output = subprocess.check_output(cmd_call)
	#	if b"Mode:Monitor" in output:
	#		logger.debug("monitor mode allready activated on %s" % iface)
	#		return

	cmd_call = ["ifconfig", iface, "down"]
	subprocess.check_call(cmd_call)
	mode = "monitor" if monitor_active else "managed"
	cmd_call = ["iwconfig", iface, "mode", mode]
	subprocess.check_call(cmd_call)

	if reactivate:
		cmd_call = ["ifconfig", iface, "up"]
		subprocess.check_call(cmd_call)
	try:
		cmd_call = ["iwconfig", iface, "retry", "0"]
		subprocess.check_call(cmd_call)
		# we don't need retry, this can improce perofmance
	except:
		# not implemented: don't care
		pass


PROG_CHANNEL = re.compile(b"Channel ([\d]+) :")

def get_available_wlan_channels(iface):
	"""
	Requirements: iwlist
	return -- channels as integer list
	"""
	cmd_call = ["iwlist", iface, "channel"]
	output = subprocess.check_output(cmd_call)
	#logger.debug("iwlist output: %r" % output)

	return [int(ch) for ch in PROG_CHANNEL.findall(output)]
		

def set_ethernet_address(iface, ethernet_addr):
	"""
	ethernet_addr -- Ethernet address like "AA:BB:CC:DD:EE:FF"
	"""
	cmd_call = ["ifconfig", iface, "down"]
	subprocess.check_call(cmd_call)
	cmd_call = ["ifconfig", iface, "hw", "ether", ethernet_addr]
	subprocess.check_call(cmd_call)
	cmd_call = ["ifconfig", iface, "up"]
	subprocess.check_call(cmd_call)

MAC_VENDOR = {}
PROG_MACVENDOR = re.compile("  ([\w\-]{8,8})   \(hex\)\t\t(.+)")

def load_mac_vendor():
	"""
	Load out.txt containing mac->vendor mappings into MAC_VENDOR
	See http://standards.ieee.org/develop/regauth/oui/oui.txt
	"""
	logger.debug("loading oui file")
	current_dir = os.path.dirname(os.path.realpath(__file__))
	try:
		fh = open(current_dir + "/oui.txt", "r")

		for line in fh:
			hex_vendor = PROG_MACVENDOR.findall(line)

			if len(hex_vendor) > 0:
				#print(hex_vendor)
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
		load_mac_vendor()
	
	try:
		return MAC_VENDOR[mac]
	except KeyError:
		return ""

#print(get_vendor_for_mac("00:00:00"))
#print(get_vendor_for_mac("00:00:01"))
#print(get_vendor_for_mac("00:10:00"))
