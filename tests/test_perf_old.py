#!/usr/bin/env python

import time, sys

import dnet
sys.path.insert(0, '.')
import pypacker
from impacket import ImpactDecoder, ImpactPacket
from openbsd import packet
import scapy
import xstruct

xip = xstruct.structdef('>', [
    ('v_hl', ('B', 1), (4 << 4) | (dnet.IP_HDR_LEN >> 2)),
    ('tos', ('B', 1), dnet.IP_TOS_DEFAULT),
    ('len', ('H', 1), dnet.IP_HDR_LEN),
    ('id', ('H', 1), 0),
    ('off', ('H', 1), 0),
    ('ttl', ('B', 1), dnet.IP_TTL_DEFAULT),
    ('p', ('B', 1), 0),
    ('sum', ('H', 1), 0),
    ('src', ('s', dnet.IP_ADDR_LEN), dnet.IP_ADDR_ANY),
    ('dst', ('s', dnet.IP_ADDR_LEN), dnet.IP_ADDR_ANY)
    ])

xudp = xstruct.structdef('>', [
    ('sport', ('B', 1), 0),
    ('dport', ('B', 1), 0),
    ('ulen', ('H', 1), dnet.UDP_HDR_LEN),
    ('sum', ('H', 1), 0)
    ])

def compare_create(cnt):
    """
pypacker: 14915.2445937 pps
pypacker (manual): 15494.3632903 pps
impacket: 3929.30572776 pps
openbsd.packet: 1503.7928579 pps
scapy: 348.449269721 pps
xstruct: 88314.8953732 pps
"""
    src = dnet.addr('1.2.3.4').ip
    dst = dnet.addr('5.6.7.8').ip
    data = 'hello world'

    start = time.time()
    for i in range(cnt):
        dnet.ip_checksum(
            str(pypacker.ip.IP(src=src, dst=dst, p=dnet.IP_PROTO_UDP,
                         len = dnet.IP_HDR_LEN + dnet.UDP_HDR_LEN + len(data),
                         data=pypacker.udp.UDP(sport=111, dport=222,
                                       ulen=dnet.UDP_HDR_LEN + len(data),
                                       data=data))))
    print("pypacker: %s pps" % (cnt / (time.time() - start)) )
    
    start = time.time()
    for i in range(cnt):
        dnet.ip_checksum(str(pypacker.ip.IP(src=src, dst=dst, p=dnet.IP_PROTO_UDP,
                                     len=dnet.IP_HDR_LEN + dnet.UDP_HDR_LEN +
                                     len(data))) +
                         str(pypacker.udp.UDP(sport=111, dport=222,
                                      ulen=dnet.UDP_HDR_LEN + len(data))) +
                         data)
    print("pypacker (manual): %d pps" % (cnt / (time.time() - start)) )
    
    start = time.time()
    for i in range(cnt):
        ip = ImpactPacket.IP()
        ip.set_ip_src('1.2.3.4')
        ip.set_ip_dst('5.6.7.8')
        udp = ImpactPacket.UDP()
        udp.set_uh_sport(111)
        udp.set_uh_dport(222)
        udp.contains(ImpactPacket.Data(data))
        ip.contains(udp)
        ip.get_packet()
    print("impacket: %d pps" % (cnt / (time.time() - start)) )

    start = time.time()
    for i in range(cnt):
        p = packet.createPacket(packet.IP, packet.UDP)
        p['ip'].src = '1.2.3.4'
        p['ip'].dst = '5.6.7.8'
        p['udp'].sport = 111
        p['udp'].dport = 22
        p['udp'].payload = data
        p.finalise()
        p.getRaw()
    print('openbsd.packet: %d pps' % (cnt / (time.time() - start)) )
    
    start = time.time()
    for i in range(cnt):
        ip = scapy.IP(src='1.2.3.4', dst='5.6.7.8') / \
             scapy.UDP(sport=111, dport=222) / data
        ip.build()
    print("scapy: %d pps" % (cnt / (time.time() - start)) )
    
    start = time.time()
    for i in range(cnt):
        udp = xudp()
        udp.sport = 111
        udp.dport = 222
        udp.ulen = dnet.UDP_HDR_LEN + len(data)
        ip = xip()
        ip.src = src
        ip.dst = dst
        ip.p = dnet.IP_PROTO_UDP
        ip.len = dnet.IP_HDR_LEN + udp.ulen
        dnet.ip_checksum(str(ip) + str(udp) + data)
    print("xstruct: %d pps" % (cnt / (time.time() - start)) )
    
def compare_parse(cnt):
    """
pypacker: 23347.462887 pps
impacket: 9937.75963595 pps
openbsd.packet: 6826.5955563 pps
scapy: 1461.74727127 pps
xstruct: 206100.202449 pps
"""
    s = 'E\x00\x00T\xc2\xf3\x00\x00\xff\x01\xe2\x18\n\x00\x01\x92\n\x00\x01\x0b\x08\x00\xfc\x11:g\x00\x00A,\xc66\x00\x0e\xcf\x12\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f!"#$%&\'()*+,-./01234567'

    start = time.time()
    for i in range(cnt):
        pypacker.ip.IP(s)
    print("pypacker: %d pps" % (cnt / (time.time() - start)) )
    
    decoder = ImpactDecoder.IPDecoder()
    start = time.time()
    for i in range(cnt):
        decoder.decode(s)
    print("impacket: %d pps" % (cnt / (time.time() - start)) )

    start = time.time()
    for i in range(cnt):
        packet.Packet(packet.IP, s)
    print("openbsd.packet: %d pps" % (cnt / (time.time() - start)) )

    start = time.time()
    for i in range(cnt):
        scapy.IP(s)
    print("scapy: %d pps" % (cnt / (time.time() - start)) )

    start = time.time()
    for i in range(cnt):
        ip = xip(s[:dnet.IP_HDR_LEN])
        udp = xudp(s[dnet.IP_HDR_LEN:dnet.IP_HDR_LEN + dnet.UDP_HDR_LEN])
        data = s[dnet.IP_HDR_LEN + dnet.UDP_HDR_LEN:]
    print("xstruct: %d pps" % (cnt / (time.time() - start)) )

def compare_checksum(cnt):
    s = 'A' * 80
    start = time.time()
    for i in range(cnt):
        pypacker.in_cksum(s)
    print("pypacker.in_cksu:", (cnt / (time.time() - start)), "pps" )
    
    start = time.time()
    for i in range(cnt):
        dnet.ip_cksum_carry(dnet.ip_cksum_add(s, 0))
    print("dnet.ip_cksum_add/carry:", (cnt / (time.time() - start)), "pps" )

def main():
    import psyco
    psyco.full()

    ITER=10000
    
    print('checksum:')
    compare_checksum(100000)

    print('create:')
    compare_create(ITER)

    print('parse:')
    compare_parse(ITER)
    
if __name__ == '__main__':
    main()
    """
    import hotshot, hotshot.stats
    prof = hotshot.Profile('/var/tmp/pypacker.prof')
    prof.runcall(main)
    prof.close()
    stats = hotshot.stats.load('/var/tmp/pypacker.prof')
    stats.strip_dirs()
    stats.sort_stats('time', 'calls')
    stats.print_stats(20)
    """
