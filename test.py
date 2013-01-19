# just some smoke-tests
from pypacker.layer12.ethernet import Ethernet
from pypacker.layer3.ip import IP
from pypacker.layer4.tcp import TCP
from pypacker.layer4.udp import UDP


e=Ethernet()
e.src="aa:bb:cc:dd:ee:ff"
e.dst="ff:ee:dd:cc:bb:aa"
print(e.src)
print(e.dst)
###
ip=IP()
ip.src="127.0.0.1"
ip.dst="192.168.0.1"
print(ip.src)
print(ip.dst)
###
tcp=TCP()
tcp.sport=123
tcp.dport=321
###
eth_ip_tcp = e/ip/tcp
print("%s >>> %s >>> %s" % (eth_ip_tcp.__class__, eth_ip_tcp.ip.__class__, eth_ip_tcp.ip.tcp.__class__))
###
print("RAW tests")
RAW=b"\x24\x65\x11\x85\xe9\xac\x00\xa0\x0b\x21\x37\x84\x08\x06\x00\x01\x08\x00\x06\x04\x00\x02\x00\xa0\x0b\x21\x37\x84\xc0\xa8\xb2\x16\x24\x65\x11\x85\xe9\xac\xc0\xa8\xb2\x01"
eraw=Ethernet(RAW)
print(eraw)
print(eraw.arp)
