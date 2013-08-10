"""Packet read and write routines for sockets."""

from pypacker import pypacker
from pypacker.layer12 import ethernet
from pypacker.layer4 import tcp

import sys
import time
import socket
import logging

logger = logging.getLogger("pypacker")

class SocketHndl(object):
	"""
	Simple socket reader/writer.
	"""

	ETH_P_ALL = 0x0003

	def __init__(self, iface_name="lo"):
		"""
		iface_name = create a socket-writer giving the name of an interface (default is "lo")
		"""
		self.__socket = None

		logger.debug("creating socket on: %s" % iface_name)
		self.__socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(SocketHndl.ETH_P_ALL))
		self.__socket.bind((iface_name, SocketHndl.ETH_P_ALL))

	def send(self, bts):
		"""
		Send the given bytes to network.
		bts -- the bytes to be sent
		"""
		self.__socket.send(bts)

	def recv(self):
		"""Receive next bytes from network."""
		return self.__socket.recv(65536)

	def sr(self, packet_send, max_packets_recv=1, timeout=1 lowest_layer=ethernet.Ethernet):
		"""
		Send and receive packets.
		packet_send --- packet to be sent
		max_packets_recv --- max packets to be received
		timeout --- read timeout in seconds
		lowest_layer --- encapsulation to be used on the lowest layer
		"""
		received = []
		self.send(packet_send.bin())
		# TODO: add timeout

		while len(received) < max_packets:
			bts = self.recv()
			packet_recv = ethernet.Ethernet(bts)

			if packet_send.direction(packet_recv) == packet.DIR_REV:
				received.append(packet_recv)
		return received

	def close(self):
		self.__socket.close()
