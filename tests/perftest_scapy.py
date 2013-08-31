from scapy.all import *
import time

e = Ether() / IP() / TCP() / "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nReferer: http://www.test.de\r\nCookie: SessionID=12345\r\n\r\n"
eth_ip_tcp_http_bytes = str(e)
bts = []
cnt = 0

for i in eth_ip_tcp_http_bytes:
	cnt += 1
	bts.append("\\x%02x" % ord(i))

	if cnt % 20 == 0:
		bts.append("\r\n")
#print("".join(bts))

cnt = 10000

start = time.time()
for i in range(cnt):
	p = Ether(eth_ip_tcp_http_bytes)
print("time diff: %ss" % (time.time() - start))
print("%d pps" % (cnt / (time.time() - start)) )
