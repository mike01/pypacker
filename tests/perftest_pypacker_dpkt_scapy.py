import time

from pypacker.layer12.ethernet import Ethernet
from pypacker.layer3 import ip
from pypacker.layer4 import tcp
from pypacker.layer567 import http


pkt_eth_ip_tcp = Ethernet() + ip.IP() + tcp.TCP(dport=80)
http_l = http.HTTP(startline=b"GET / HTTP/1.1", hdr=[(b"header1", b"value1")], body_bytes=b"Content123")
pkt_eth_ip_tcp += http_l
pkt_eth_ip_tcp_bts = pkt_eth_ip_tcp.bin()

LOOP_CNT = 100000

print("or = original results (Intel Core2 Duo CPU @ 1,866 GHz, 2GB RAM, Python v3.3)")
print("nr = new results on this machine")
print("rounds per test: %d" % LOOP_CNT)

print(">>> testing pypacker parsing speed")

t_start = time.time()

for cnt in range(LOOP_CNT):
	pkt1 = Ethernet(pkt_eth_ip_tcp_bts)
	# dpkt does not parse TCP content but pypacker does
	# -> access layer ip to get comparable result
	pkt2 = pkt1[ip.IP]
	#pkt2 = pkt1.ip.tcp
	#pkt2 = pkt1.ip.tcp.http
	bts = pkt1.bin(update_auto_fields=False)
t_end = time.time()

print("or = 12527 pkts/s")
print("nr = %d pkts/s" % (LOOP_CNT / (t_end - t_start)))

try:
	import dpkt
	print(">>> testing dpkt parsing speed")
	EthernetDpkt = dpkt.ethernet.Ethernet

	t_start = time.time()

	for cnt in range(LOOP_CNT):
		pkt1 = EthernetDpkt(pkt_eth_ip_tcp_bts)
		pkt2 = pkt1.ip
		#pkt2 = pkt1.ip.tcp
		bts = pkt1.data
	t_end = time.time()

	print("or = 12028 pkts/s")
	print("nr = %d pkts/s" % (LOOP_CNT / (t_end - t_start)))
except ImportError as ex:
	print("could not execute dpkt performance tests:"
		" dpkt is needed in order to test dpkt performance, makes sense doesn't it?")


try:
	from scapy.all import *

	print(">>> testing scapy parsing speed")

	t_start = time.time()

	for _ in range(LOOP_CNT):
		pkt1 = Ether(pkt_eth_ip_tcp_bts)
		pkt2 = pkt1[IP]
		bts = "%s" % pkt1

	t_end = time.time()

	print("or = 771 pkts/s")
	print("nr = %d pkts/s" % (LOOP_CNT / (t_end - t_start)))
except ImportError as ex:
	print("could not execute scapy performance tests:"
		" scapy is needed in order to test scapy performance, makes sense doesn't it?")
