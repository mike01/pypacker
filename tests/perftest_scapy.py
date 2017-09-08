import time

from scapy.all import *

LOOP_CNT = 10000

print("or = original results (Intel Core2 Duo CPU @ 1,866 GHz, 2GB RAM, Python v3.3)")
print("nr = new results on this machine")
print("rounds per test: %d" % LOOP_CNT)

print(">>> testing scapy parsing speed")

eth_ip_tcp_http_bytes = b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x08\x00E\x00\x00S\x00\x00\x00\x00@\x06z\xa6\x00\x00\x00\x00\x00\x00\x00\x00\xde\xad\x00P\xde\xad\xbe\xef\x00\x00\x00\x00P\x02\xff\xffM\xc7\x00\x00GET / HTTP/1.1header1: value1\r\n\r\nContent123"

t_start = time.time()

for _ in range(LOOP_CNT):
	pkt1 = Ether(eth_ip_tcp_http_bytes)
	pkt2 = pkt1[IP]
	bts = "%s" % pkt1

t_end = time.time()

print("or = 771 pkts/s")
print("nr = %d pkts/s" % (LOOP_CNT / (t_end - t_start)))

