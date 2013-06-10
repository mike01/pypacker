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

	def recv(self):
		"""Receive next bytes from network."""
		return self.__socket.recv(65536)

	def send(self, bts):
		"""
		Send the given bytes to network.
		pts -- the bytes to be sent
		"""
		self.__socket.send(bts)

	def close(self):
		self.__socket.close()
