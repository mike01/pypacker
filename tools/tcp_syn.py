import sys
import time
import random

from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.layer4 import tcp
from pypacker import pypacker
from pypacker import psocket

IFACE	= "wlan0"
MAC_SRC	= "00:13:e8:63:f3:8f"
MAC_DST	= "24:65:11:85:E9:AC"
IP_SRC	= "192.168.178.26"
FILE_IP_DST = sys.argv[2]

print("destination IP addresses file: %s" % FILE_IP_DST)
IP_DST = open(FILE_IP_DST, "r").read().split("\n")[:-1]
print("amount addresses: %d" % len(IP_DST))

REPITITIONS = int(sys.argv[1])
print("repititiona: %d" % REPITITIONS)

psock_req	= psocket.SocketHndl(iface_name=IFACE, mode=psocket.SocketHndl.MODE_LAYER_2)
tcp_syn		= ethernet.Ethernet(dst_s=MAC_DST, src_s=MAC_SRC) +\
			ip.IP(src_s=IP_SRC, dst_s="127.0.0.1", p=ip.IP_PROTO_TCP) +\
			tcp.TCP(sport=12345, dport=1337)

print("%r" % tcp_syn)
ip = tcp_syn.ip
tcp = tcp_syn.ip.tcp
randrange = random.randrange

for x in range(REPITITIONS):
	if x % 10000 == 0:
		print("sent %d" % x)
	ip_dst_str = IP_DST[randrange(0, len(IP_DST))]
	try:
		ip.dst_s = ip_dst_str
	except:
		print("could not parse: %s" % ip_dst_str)
		continue
	tcp.seq = randrange(1234, 123123)
	tcp.sport = randrange(1000, 65536)

	psock_req.send(tcp_syn.bin())
	time.sleep(0.0001)
#print("answer is: %s" % answer)
psock_req.close()


# Norway:
# 192.240.0.22,,21,25,28,26
# 108.192.79.230
#
# 197.242.73.195,196,199,200,204,203
