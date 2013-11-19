import pypacker.pypacker as pypacker
from pypacker.pypacker import Packet
from pypacker import ppcap
from pypacker import psocket
from pypacker.layer12 import arp, ethernet, ieee80211, prism, radiotap
from pypacker.layer3 import ip, icmp
from pypacker.layer4 import udp, tcp

import socket

# send ICMP request
psock = psocket.SocketHndl(iface_name="eth1")
icmpreq = ethernet.Ethernet(src_s="20:16:d8:ef:1f:49", dst_s="24:65:11:85:e9:00", type=ethernet.ETH_TYPE_IP) +\
	ip.IP(p=ip.IP_PROTO_ICMP, src_s="192.168.178.27", dst_s="192.168.178.24") +\
	icmp.ICMP(type=8) +\
	icmp.ICMP.Echo(id=1, ts=123456789, data=b"12345678901234567890")
psock.send(icmpreq.bin())
