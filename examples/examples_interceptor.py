"""
Interceptor example using ICMP

Requirements:
iptables -I INPUT 1 -p icmp -j NFQUEUE --queue-balance 0:2
"""
import time

from pypacker import interceptor
from pypacker.layer3 import ip, icmp

# Add iptables rule:
# iptables -I INPUT 1 -p icmp -j NFQUEUE --queue-balance 0:2


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
	echo1.body_bytes = echo1.body_bytes[:len(pp_bts)] + pp_bts
	return ip1.bin(), interceptor.NF_ACCEPT


ictor = interceptor.Interceptor()
ictor.start(verdict_cb, queue_ids=[0, 1, 2])

try:
	time.sleep(999)
except KeyboardInterrupt:
	pass
ictor.stop()
