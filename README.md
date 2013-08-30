### General information
This is Pypacker: The fast and simple packet creation and parsing lib for Python.
It lets you create packets manually by defining every aspect of all header data
and dissect packets by parsing captured packet bytes.

#### What you can do with Pypacker
Create Packets giving specific values or take the defaults. Those can be resent eg using pcap or raw sockets:

	ip = IP(src_s="127.0.0.1", dst_s="192.168.0.1", p=1) +
		ICMP(type=8) +
		Echo(id=123, seq=1, data=b"foobar")

Read packets (eg. via pcap) and analyze all aspects of it:

	f = open("packets.pcap", "rb")
	pcap = ppcap.Reader(f)
	cnt = 0

	for ts, buf in pcap:
			cnt += 1
			eth = Ethernet(buf)

			if eth[TCP] is not None:
				print("%9.3f: %s:%s -> %s:%s" % (ts, eth[IP].src_s, eth[TCP].sport, eth[IP].dst_s, eth[TCP].dport))

Send and receive packets on different layers:

	packet_ip = ip.IP(src_s="127.0.0.1", dst_s="127.0.0.1") + tcp.TCP(dport=80)
	psock = psocket.SocketHndl(mode=psocket.SocketHndl.MODE_LAYER_3, timeout=10)
	packets = psock.sr(packet_ip, max_packets_recv=1)

	for p in packets:
		print("got layer 3 packet: %s" % p)
	psock.close()


#### What you can NOT do with it
Pypacker is not as full-blown feature-rich as other packet-analyzer like Scapy, so you can't automatically create neat graphics out of TCP-sequence-numbers, use it as a port-scanner, fingerprint servers	or use it as a fuzzer by writing one line of code. Those kind of features can easy be written using open-source tools like gnuplot and very few lines of python-code. 

Please feel free to post bug-reports / patches / feature-requests. Please read
the bugtracker for already knwown bugs before filing a new one!

### Prerequisites
- Python 3.x

### Examples
See directory pypacker/examples and testcases in pypacker/tests/.

### Testing
Tests are executed as follows:

1) Optional: Add Pypacker directory to the PYTHONPATH. This is only needed if tests are executed without installing Pypacker

export PYTHONPATH=$PYTHONPATH:/dir/to/pypacker/

2) execute tests

python3 tests/test_pypacker.py

### FAQ

**Q**:	How much does Pypacker cost?

**A**:	Pypacker is a free software - you can download it without paying any license fee.
	The version you download is not a demo version, with limitations not present in
	a full version - it's the full version. The license under which Pypacker is
	issued is the BSD License. See LICENCE and http://opensource.org/licenses/bsd-license.php
	for more information.

**Q**:	Which protocols are supported?

**A**:	Currently minimum supported protocols are:
	Ethernet, IP, ICMP, TCP, UDP, HTTP, ARP, STP, OSPF, PPP, PPPoE, STP, VRRP, AH, ESP, IGMP,
	IPX, PIM, AIM, NTP, DHCP, RIP, SCTP, RTP, SIP, TFTP

**Q**:	Are there any plans to support [protocol xyz]?

**A**:	Support for particular protocols is added to Pypacker as a result of people contributing
	that support - no formal plans for adding support for particular protocols in particular
	future releases exist. 

**Q**:	Is there any documentation?

**A**:	Pypacker is based on code of dpkt, which in turn didn't have any official and very little
	internal code documentation. This made understanding of the internal behaviour tricky.
	After all the code documentation was pretty much extended for Pypacker. Documentation can
	be found in these directories and files:
- examples (many examples showing the usage of Pypacker)
- doc (auto generated documentations showing general header field definitions)
- pypacker.py (general Packet structure)

Protocols itself (see layerXYZ) generally don't have much documentation because those are documented
by their respective RFCs/official standards.

**Q**:	How can new protocols be added?

**A**:	Short answer: Extend Packet class and add the class variable __hdr__ to define header fields.
	Long answer: See directory examples/extension for a very complete protocol definition and
	class documentation for Packet class and all other implemented protocols.

**Q**:	There is problem xyz with Pypacker using Windows 3.11/XP/7/8/mobile etc. Can you fix that?

**A**:	No. There will be no windows support.



[![Bitdeli Badge](https://d2weczhvl823v0.cloudfront.net/mike01/pypacker/trend.png)](https://bitdeli.com/free "Bitdeli Badge")
