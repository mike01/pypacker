"""
Very simple TCP port scanner. Better use something like masscan or nmap for
more performance/features :D
"""
import threading
import time
import queue

from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.layer4 import tcp
from pypacker import psocket

IFACE_NAME = "wlan0"
MAC_SRC = "00:11:22:33:44:55"  # MAC address of IFACE_NAME
MAC_DST = "00:11:22:33:44:56"  # MAC address of target or router
IP_SRC = "192.168.178.53"  # IP address of IFACE_NAME
IP_DST = "192.168.178.1"  # IP address of target


PORT_SRC = 12345
TCP_SEQ = 1337
sock_rcv = psocket.SocketHndl(iface_name=IFACE_NAME)
sock_send = psocket.SocketHndl(iface_name=IFACE_NAME)
open_ports = queue.Queue()


def filter_pkt(pkt):
	tcp_pkt = pkt[tcp.TCP]

	if tcp_pkt is None or\
		tcp_pkt.dport != PORT_SRC or\
		tcp_pkt.flags != (tcp.TH_SYN | tcp.TH_ACK) or\
		tcp_pkt.ack != TCP_SEQ + 1:
		return False

	open_ports.put(tcp_pkt.sport)
	return True


def rcv_cycler(sock):
	while True:
		try:
			sock.recvp(filter_match_recv=filter_pkt, lowest_layer=ethernet.Ethernet, max_amount=1)
		except:
			print("stopping receive cycler")
			break


thread_rcv = threading.Thread(target=rcv_cycler, args=[sock_rcv])
thread_rcv.start()

print("starting to scan")

for port in range(0, 0xFFFF + 1):
	print("\rPinging TCP port %d" % port, end="")

	while not open_ports.empty():
		port_open = open_ports.get()
		print("\nTCP Port %d on %s seems to be open" % (port_open, IP_DST))

	pkt_send = ethernet.Ethernet(dst_s=MAC_DST, src_s=MAC_SRC) +\
		ip.IP(src_s=IP_SRC, dst_s=IP_DST) +\
		tcp.TCP(sport=PORT_SRC, dport=port, seq=TCP_SEQ)
	sock_send.send(pkt_send.bin())

print()
print("waiting some seconds to receive delayed responses")
time.sleep(2)

sock_rcv.close()
sock_send.close()
