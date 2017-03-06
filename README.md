[![Build Status](https://travis-ci.org/mike01/pypacker.svg?branch=master)](https://travis-ci.org/mike01/pypacker)
[![Code Health](https://landscape.io/github/mike01/pypacker/master/landscape.svg?style=flat)](https://landscape.io/github/mike01/pypacker/master)
[![version](http://img.shields.io/pypi/v/pypacker.svg)](https://pypi.python.org/pypi/pypacker)
[![supported-versions](https://img.shields.io/pypi/pyversions/pypacker.svg)](https://pypi.python.org/pypi/pypacker)
[![supported-implementations](https://img.shields.io/pypi/implementation/pypacker.svg)](https://pypi.python.org/pypi/pypacker)

### General information
This is Pypacker: The fast and simple packet creation and parsing lib for Python.
It lets you create packets manually by defining every aspect of all header data
and dissect packets by parsing captured packet bytes.

#### What you can do with Pypacker
Create Packets giving specific values or take the defaults:

```python
from pypacker.layer3.ip import IP
from pypacker.layer3.icmp import ICMP

ip = IP(src_s="127.0.0.1", dst_s="192.168.0.1", p=1) +\
	ICMP(type=8) +\
	ICMP.Echo(id=123, seq=1, body_bytes=b"foobar")
```

Read packets from file (pcap format) and analyze all aspects of it:

```python
from pypacker import ppcap
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.layer4 import tcp

pcap = ppcap.Reader(filename="packets_ether.pcap")

for ts, buf in pcap:
	eth = ethernet.Ethernet(buf)

	if eth[tcp.TCP] is not None:
		print("%d: %s:%s -> %s:%s" % (ts, eth[ip.IP].src_s, eth[tcp.TCP].sport,
			eth[ip.IP].dst_s, eth[tcp.TCP].dport))
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
# send/receive based on source/destination data
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

##### Key features

- Create network packets on different OSI layers using keywords like MyPacket(value=123) or raw bytes MyPacket(b"value")
- Concatination of layers via "+" like packet = layer1 + layer2
- Fast access to layers via packet[tcp.TCP] or packet.sublayerXYZ.tcp notation
- Readable packet structure using print(packet) or similar statements
- Read packets via Pcap/tcpdump file reader
- Live packet reading/writing using a capsulated socket API
- Auto Checksum calculation capabilities
- Match replies via "is_direction()"
- Create new protocols (see FAQ)

#### What you can NOT do with it
Pypacker is not as full-blown feature-rich as other packet-analyzer like Scapy, so you can't automatically
use it as a port-scanner, fingerprinting purposes or use it as a fuzzer
out of the box. Those kind of features can easy be written using open-source tools like gnuplot and
very few lines of python-code. 

Please feel free to post bug-reports / patches / feature-requests. Please read
the bugtracker for already known bugs before filing a new one!

### Prerequisites
- Python 3.x
- Un*x based operating system

### Installation
Some examples:
- python setup.py install
- pip install pypacker

### Usage examples
See examples/examples.py and tests/test_pypacker.py.

### Testing
Tests are executed as follows:

1) Optional: Add Pypacker directory to the PYTHONPATH. This is only needed if tests are executed without installing Pypacker

cd pypacker

export PYTHONPATH=$PYTHONPATH:$(pwd)

2) execute tests

python tests/test_pypacker.py

### FAQ

**Q**:	Where should I start learn to use Pypacker?

**A**:	If you allready know Scapy starting by reading the examples should be OK. Otherwise there
	is a general introduction to pypacker included at the doc's which shows the usage and concepts
	of pypacker.

**Q**:	Under which license Pypacker is issued?

**A**:	It's the BSD License. See LICENCE and http://opensource.org/licenses/bsd-license.php
	for more information. I'm willing to change to GPLv2 but this collides with the previous
	license of dpkt (which is BSD).

**Q**:	Which protocols are supported?

**A**:	Currently minimum supported protocols are:
	Ethernet, Radiotap, IEEE80211, ARP, DNS, STP, PPP, OSPF, VRRP, DTP, IP, ICMP, PIM, IGMP, IPX,
	TCP, UDP, SCTP, HTTP, NTP, RTP, DHCP, RIP, SIP, Telnet, HSRP, Diameter, SSL, TPKT, Pmap, Radius, BGP

**Q**:	Are there any plans to support [protocol xyz]?

**A**:	Support for particular protocols is added to Pypacker as a result of people contributing
	that support - no formal plans for adding support for particular protocols in particular
	future releases exist. 

**Q**:	Is there any documentation?

**A**:	Pypacker is based on code of dpkt, which in turn didn't have any official and very little
	internal code documentation. This made understanding of the internal behaviour tricky.
	After all the code documentation was pretty much extended for Pypacker. Documentation can
	be found in these directories and files:
- doc (auto generated documentations showing general header field definitions + general intro into pypacker)
- examples/examples.py (many examples showing the usage of Pypacker)
- pypacker.py (general Packet structure)

Protocols itself (see layerXYZ) generally don't have much documentation because those are documented
by their respective RFCs/official standards.

**Q**:	How fast is pypacker?

**A**:	For detailed results see performance tests in test directory. As a rule of thumb compared
	to scapy packet parsing from raw bytes is about 50 times faster.

**Q**:	How can new protocols be added?

**A**:	Short answer: Extend Packet class and add the class variable __hdr__ to define header fields.
	Long answer: See HACKING file -> "Adding new protocols", class documentation for Packet class
	and all other implemented protocols.

**Q**:	There is problem xyz with Pypacker using Windows 3.11/XP/7/8/mobile etc. Can you fix that?

**A**:	No. There will be no windows support. Why? Because quality matters and I won't give support for
	inferior systems. Think twice before chosing an operating system and deal with the consequences;
	don't blame others for your decision. Alternatively: give me monetary compensation and I'll see
	what I can do (;
