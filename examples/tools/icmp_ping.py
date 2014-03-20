from pypacker import psocket
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip, icmp

# send ICMP request
psock = psocket.SocketHndl(iface_name="eth1")
icmpreq = ethernet.Ethernet(src_s="20:16:d8:ef:1f:49", dst_s="24:65:11:85:e9:00", type=ethernet.ETH_TYPE_IP) +\
	ip.IP(p=ip.IP_PROTO_ICMP, src_s="192.168.178.27", dst_s="192.168.178.24") +\
	icmp.ICMP(type=8) +\
	icmp.ICMP.Echo(id=1, ts=123456789, data=b"12345678901234567890")
psock.send(icmpreq.bin())
