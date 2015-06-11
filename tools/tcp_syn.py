from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.layer4 import tcp
from pypacker import pypacker
from pypacker import psocket

IFACE	= "wlan0"
MAC_SRC	= "11:22:33:44:55:66"
MAC_DST	= "11:22:33:44:55:67"
IP_SRC	= "192.168.0.1"
IP_DST	= "192.168.0.2"

psock_req	= psocket.SocketHndl(iface_name=IFACE, mode=psocket.SocketHndl.MODE_LAYER_2)
tcp_syn		= 	ethernet.Ethernet(dst_s=MAC_SRC, src_s=MAC_DST) +\
			ip.IP(src_s=IP_SRC, dst_s=IP_DST, p=ip.IP_PROTO_TCP) +\
			tcp.TCP(sport=12345, dport=53)

print("%r" % tcp_syn)
answer	= psock_req.sr(tcp_syn)
print("answer is: %s" % answer)
psock_req.close()
