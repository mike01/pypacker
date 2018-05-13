<p align="center">
	<img src="./pypacker_logo_large.png">
</p>

[![Build Status](https://travis-ci.org/mike01/pypacker.svg?branch=master)](https://travis-ci.org/mike01/pypacker)
[![Code Health](https://landscape.io/github/mike01/pypacker/master/landscape.svg?style=flat)](https://landscape.io/github/mike01/pypacker/master)
[![version](http://img.shields.io/pypi/v/pypacker.svg)](https://pypi.python.org/pypi/pypacker)
[![supported-versions](https://img.shields.io/pypi/pyversions/pypacker.svg)](https://pypi.python.org/pypi/pypacker)
[![supported-implementations](https://img.shields.io/pypi/implementation/pypacker.svg)](https://pypi.python.org/pypi/pypacker)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](LICENSE)

# General information
This is Pypacker: The fastest and simplest packet manipulation lib for Python.
It lets you create packets manually by defining every aspect of all header data,
dissect packets by parsing raw packet bytes, sending/receiving packets on different layers and intercepting packets.

## What you can do with Pypacker
Create Packets giving specific values or take the defaults:

```python
from pypacker.layer3.ip import IP
from pypacker.layer3.icmp import ICMP

ip = IP(src_s="127.0.0.1", dst_s="192.168.0.1", p=1) +\
	ICMP(type=8) +\
	ICMP.Echo(id=123, seq=1, body_bytes=b"foobar")

# output packet
print("%s" % ip)
IP(v_hl=45, tos=0, len=2A, id=0, off=0, ttl=40, p=1, sum=3B29, src=b'\x7f\x00\x00\x01', dst=b'\xc0\xa8\x00\x01', opts=[], handler=icmp)
ICMP(type=8, code=0, sum=C03F, handler=echo)
Echo(id=7B, seq=1, ts=0, bytes=b'foobar')
```

Read packets from file (pcap/tcpdump format), analyze it and write them back:

```python
from pypacker import ppcap
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.layer4 import tcp

preader = ppcap.Reader(filename="packets_ether.pcap")
pwriter = ppcap.Writer(filename="packets_ether_new.pcap", linktype=ppcap.DLT_EN10MB)

for ts, buf in preader:
	eth = ethernet.Ethernet(buf)

	if eth[ethernet.Ethernet, ip.IP, tcp.TCP] is not None:
		print("%d: %s:%s -> %s:%s" % (ts, eth[ip.IP].src_s, eth[tcp.TCP].sport,
			eth[ip.IP].dst_s, eth[tcp.TCP].dport))
		pwriter.write(eth.bin())

pwriter.close()
```

Intercept (and modificate) Packets eg for MITM:

```python
# Add iptables rule:
# iptables -I INPUT 1 -p icmp -j NFQUEUE --queue-balance 0:2
import time

from pypacker import interceptor
from pypacker.layer3 import ip, icmp

# ICMP Echo request intercepting
def verdict_cb(ll_data, ll_proto_id, data, ctx):
	ip1 = ip.IP(data)
	icmp1 = ip1[icmp.ICMP]

	if icmp1 is None or icmp1.type != icmp.ICMP_TYPE_ECHO_REQ:
		return data, interceptor.NF_ACCEPT

	echo1 = icmp1[icmp.ICMP.Echo]

	if echo1 is None:
		return data, interceptor.NF_ACCEPT

	pp_bts = b"PYPACKER"
	print("changing ICMP echo request packet")
	echo1.body_bytes = echo1.body_bytes[:-len(pp_bts)] + pp_bts
	return ip1.bin(), interceptor.NF_ACCEPT

ictor = interceptor.Interceptor()
ictor.start(verdict_cb, queue_ids=[0, 1, 2])
print("now sind a ICMP echo request to localhost: ping 127.0.0.1")
time.sleep(999)
ictor.stop()
```

Send and receive packets:

```python
# send/receive raw bytes
from pypacker import psocket
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip

psock = psocket.SocketHndl(mode=psocket.SocketHndl.MODE_LAYER_2, timeout=10)

for raw_bytes in psock:
	eth = ethernet.Ethernet(raw_bytes)
	print("Got packet: %r" % eth)
	eth.reverse_address()
	eth.ip.reverse_address()
	psock.send(eth.bin())
	# stop on first packet
	break

psock.close()
```

```python
# send/receive using filter
from pypacker import psocket
from pypacker.layer3 import ip
from pypacker.layer4 import tcp

packet_ip = ip.IP(src_s="127.0.0.1", dst_s="127.0.0.1") + tcp.TCP(dport=80)
psock = psocket.SocketHndl(mode=psocket.SocketHndl.MODE_LAYER_3, timeout=10)

def filter_pkt(pkt):
	return pkt.ip.tcp.sport == 80

psock.send(packet_ip.bin(), dst=packet_ip.dst_s)
pkts = psock.recvp(filter_match_recv=filter_pkt)

for pkt in pkts:
	print("got answer: %r" % pkt)

psock.close()

```

```python
# Send/receive based on source/destination data
from pypacker import psocket
from pypacker.layer3 import ip
from pypacker.layer4 import tcp

packet_ip = ip.IP(src_s="127.0.0.1", dst_s="127.0.0.1") + tcp.TCP(dport=80)
psock = psocket.SocketHndl(mode=psocket.SocketHndl.MODE_LAYER_3, timeout=10)
packets = psock.sr(packet_ip, max_packets_recv=1)

for p in packets:
    print("got layer 3 packet: %s" % p)
psock.close()
```

## Key features

- Create network packets on different OSI layers using keywords like MyPacket(value=123) or raw bytes MyPacket(b"value")
- Concatination of layers via "+" like packet = layer1 + layer2
- Fast access to layers via packet[tcp.TCP] or packet.sublayerXYZ.tcp notation
- Readable packet structure using print(packet) or similar statements
- Read/store packets via Pcap/tcpdump file reader/writer
- Live packet reading/writing using a wrapped socket API
- Auto Checksum calculation capabilities
- Intercept Packets using NFQUEUE targets
- Easily create new protocols (see FAQ below)


## Prerequisites
- Python 3.x (CPython, Pypy, Jython or whatever Interpreter)
- Optional (for interceptor):
  - CPython
  - Linux based system
  - iptables
  - NFQUEUE target support in kernel for packet intercepting
  - libnetfilter_queue library (see http://www.netfilter.org/projects/libnetfilter_queue)

## Installation
Some examples:
- Download/clone pypacker -> python setup.py install (newest version)
- pip install pypacker (synched to master on major version changes)

## Usage examples
See examples/ and tests/test_pypacker.py.

## Testing
Tests are executed as follows:

1) Add Pypacker directory to the PYTHONPATH.

- cd pypacker
- export PYTHONPATH=$PYTHONPATH:$(pwd)

2) execute tests

- python tests/test_pypacker.py

**Performance test results: pypacker**
```
orC = Intel Core2 Duo CPU @ 1,866 GHz, 2GB RAM, CPython v3.6
orP = Intel Core2 Duo CPU @ 1,866 GHz, 2GB RAM, Pypy 5.10.1
rounds per test: 10000
=====================================
>>> parsing (IP + ICMP)
orC = 86064 p/s
orP = 208346 p/s
>>> creating/direct assigning (IP only header)
orC = 41623 p/s
orP = 59370 p/s
>>> bin() without change (IP)
orC = 170356 p/s
orP = 292133 p/s
>>> output with change/checksum recalculation (IP)
orC = 10104 p/s
orP = 23851 p/s
>>> basic/first layer parsing (Ethernet + IP + TCP + HTTP)
orC = 62748 p/s
orP = 241047 p/s
>>> changing Triggerlist element value (Ethernet + IP + TCP + HTTP)
orC = 101552 p/s
orP = 201994 p/s
>>> changing Triggerlist/text based proto (Ethernet + IP + TCP + HTTP)
orC = 37249 p/s
orP = 272972 p/s
>>> direct assigning and concatination (Ethernet + IP + TCP + HTTP)
orC = 7428 p/s
orP = 14315 p/s
>>> full packet parsing (Ethernet + IP + TCP + HTTP)
orC = 6886 p/s
orP = 17040 p/s
```

**Performance test results: pypacker vs. dpkt vs. scapy**
```
Comparing pypacker, dpkt and scapy performance (parsing Ethernet + IP + TCP + HTTP)
orC = Intel Core2 Duo CPU @ 1,866 GHz, 2GB RAM, CPython v3.6
orC2 = Intel Core2 Duo CPU @ 1,866 GHz, 2GB RAM, CPython v2.7
rounds per test: 10000
=====================================
>>> testing pypacker parsing speed
orC = 17938 p/s
>>> testing dpkt parsing speed
orC = 12431 p/s
>>> testing scapy parsing speed
orC2 = 726 p/s
```

# FAQ

**Q**:	Where should I start learn to use Pypacker?

**A**:	If you allready know Scapy starting by reading the examples should be OK. Otherwise there
	is a general introduction to pypacker included at the doc's which shows the usage and concepts
	of pypacker.

**Q**:	How fast is pypacker?

**A**:	See results above. For detailed results on your machine execute tests.

**Q**:	Is there any documentation?

**A**:	Pypacker is based on code of dpkt, which in turn didn't have any official and very little
	internal code documentation. This made understanding of the internal behaviour tricky.
	After all the code documentation was pretty much extended for Pypacker. Documentation can
	be found in these directories and files:
- examples/ (many examples showing the usage of Pypacker)
- wiki (general intro into pypacker)
- pypacker.py (general Packet structure)

Protocols itself (see layerXYZ) generally don't have much documentation because those are documented
by their respective RFCs/official standards.

**Q**:	Which protocols are supported?

**A**:	Currently minimum supported protocols are:
	Ethernet, Radiotap, IEEE80211, ARP, DNS, STP, PPP, OSPF, VRRP, DTP, IP, ICMP, PIM, IGMP, IPX,
	TCP, UDP, SCTP, HTTP, NTP, RTP, DHCP, RIP, SIP, Telnet, HSRP, Diameter, SSL, TPKT, Pmap, Radius, BGP

**Q**:	How are protocols added?

**A**:  Short answer: Extend Packet class and add the class variable `__hdr__` to define header fields.
        Long answer: See examples/examples_new_protocol.py for a very complete example.

**Q**: How can I contribute to this project?

**A**: Please use the Github bug-tracker for bugs/feature request. Please read the bugtracker for
     already known bugs before filing a new one. Patches can be send via pull request.

**Q**:	Under which license Pypacker is issued?

**A**:	It's the GPLv2 License (see LICENSE file for more information).

**Q**:	Are there any plans to support [protocol xyz]?

**A**:	Support for particular protocols is added to Pypacker as a result of people contributing
	that support - no formal plans for adding support for particular protocols in particular
	future releases exist. 

**Q**:	There is problem xyz with Pypacker using Windows 3.11/XP/7/8/mobile etc. Can you fix that?

**A**:	The basic features should work with any OS. Optional ones may make trouble (eg interceptor)
        and there will be no support for that. Why? Because quality matters and I won't give support for
	inferior systems. Think twice before chosing an operating system and deal with the consequences;
	don't blame others for your decision. Alternatively: give me monetary compensation and I'll see
	what I can do (;


# Usage hints
## Performance related
- For maxmimum performance start accessing attributes at lowest level e.g. for filtering:
```
# This will lazy parse only needed layers behind the scenes
if ether.src == "...":
    ...
elif ip.src == "...":
    ...
elif tcp.sport == "...":
    ...
```

- Avoid to convert packets using the "%s" or "%r" format as it triggers parsing behind the scene:
```
pkt = Ethernet() + IP() + TCP()
# This parses ALL layers
packet_print = "%s" % pkt
```

- Avoid searching for a layer using single-value index-notation via pkt[L] as it parses all layers until L is found or highest layer is reached:
```
packet_found = pkt[Telnet]
# Alternative: Use multi-value index-notation. This will stop parsing at any non-matching layer:
packet_found = pkt[Ethernet,IP,TCP,Telnet]
```

- For even more performance disable auto fields (affects calling bin(...)):
```
pkt = ip.IP(src_s="1.2.3.4", dst_s="1.2.3.5") + tcp.TCP()
# Disable checksum calculation (and any other update) for IP and TCP (only THIS packet instance)
pkt.sum_au_active = False
pkt.tcp.sum_au_active = False
bts = pkt.bin(update_auto_fields=False)
```

- Enlarge receive/send buffers to get max performance. This can be done using the following commands
	(taken from: http://www.cyberciti.biz/faq/linux-tcp-tuning/):
```
sysctl -w net.core.rmem_max=12582912
sysctl -w net.core.rmem_default=12582912
sysctl -w net.core.wmem_max=12582912
sysctl -w net.core.wmem_default=12582912
sysctl -w net.core.optmem_max=2048000
sysctl -w net.core.netdev_max_backlog=5000
sysctl -w net.unix.max_dgram_qlen=1000
sysctl -w net.ipv4.tcp_rmem="10240 87380 12582912"
sysctl -w net.ipv4.tcp_wmem="10240 87380 12582912"
sysctl -w net.ipv4.tcp_mem="21228 87380 12582912"
sysctl -w net.ipv4.udp_mem="21228 87380 12582912"
sysctl -w net.ipv4.tcp_window_scaling=1
sysctl -w net.ipv4.tcp_timestamps=1
sysctl -w net.ipv4.tcp_sack=1
```

## Misc related
- Assemblation of TCP/UDP streams can be done by tshark using pipes
	with "-i -" and "-z follow,prot,mode,filter[,range]"
