### General information
This is pypacker: The fast and simple packet creation and parsing lib for Python.
It lets you create packets manually by defining every aspect of all header data
and dissect packets by parsing captured packet bytes.

#### What you can do with pypacker
Read packets (eg. via pcap) and analyze all aspects of it. It's as easy as:

	f = open("packets.pcap", "rb")
	pcap = ppcap.Reader(f)
	cnt = 0

	for ts, buf in pcap:
			cnt += 1
			eth = Ethernet(buf)

			if eth[TCP] is not None:
				print("%9.3f: %s:%s -> %s:%s" % (ts, eth[IP].src_s, eth[TCP].sport, eth[IP].dst_s, eth[TCP].dport))

Create Packets giving specific values or take the defaults. Those can be resent using pcap, raw sockets etc. It's as easy as:

	ip = IP(src_s="127.0.0.1", dst_s="192.168.0.1", p=1) +
		ICMP(type=8) +
		Echo(id=123, seq=1, data=b"foobar")
	ip[ICMP].sum = 123	# mark as changed for checksum-recalculation

#### What you can NOT do with it
Pypacker is not as full-blown feature-rich as other packet-analyzer like Scapy, so you can't automatically create neat graphics out of TCP-sequence-numbers, use it as a port-scanner, fingerprint servers	or use it as a fuzzer by writing one line of code. Those kind of features can easy be written using open-source tools like gnuplot and very few lines of python-code. 

Please feel free to post bug-reports / patches / feature-requests. Please read
the bugtracker for already knwown bugs before filing a new one!

### Prerequisites
- Python >=3.1
- python setuptools >=0.6.21

### Examples
See directory pypacker/examples and testcases in pypacker/tests/.

### Testing
Tests are executed as follows:

1) Optional: Add pypacker directory to the PYTHONPATH. This is only needed if tests are executed without installing pypacker

export PYTHONPATH=$PYTHONPATH:/dir/to/pypacker/

2) execute tests

python3 tests/test_pypacker.py

### FAQ

**Q**:	How much does pypacker cost?

**A**:	Pypacker is a free software - you can download it without paying any license fee.
	The version you download is not a demo version, with limitations not present in
	a full version - it's the full version. The license under which pypacker is
	issued is the BSD License. See LICENCE and http://opensource.org/licenses/bsd-license.php
	for more information.

**Q**:	Which protocols are supported?

**A**:	Currently supported protocols are:
	Ethernet, IP, ICMP, TCP, UDP, HTTP, ARP, STP, OSPF, PPP, PPPoE, STP, VRRP, AH, ESP, IGMP,
	IPX, PIM, AIM, NTP, DHCP, RIP, SCTP, RTP, SIP, TFTP

**Q**:	Are there any plans to support [protocol xyz]?

**A**:	Support for particular protocols is added to pypacker as a result of people contributing
	that support - no formal plans for adding support for particular protocols in particular
	future releases exist. 

**Q**:	Is there any documentation?

**A**:	pypacker is based on code of dpkt, which in turn didn't have any official and very little
	internal code documentation. This makes understanding of the internal behaviour pretty hard.
	After all the code documentation was pretty much extended for pypacker (see pypacker/pypacker.py).
	Protocols itself (see layerXYZ) generally don't have much documentation because those are documented
	by their respective RFCs/official standards.

**Q**:	There is problem xyz with pypacker using Windows 3.11/XP/7/8/mobile etc. Can you fix that?

**A**:	No. There will be no windows support.
