"""Packet read and write routines using network sockets."""

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

	ETH_P_ALL		= 0x0003
	MODE_LAYER_2		= 0
	MODE_LAYER_3		= 1

	def __init__(self, iface_name="lo", mode=MODE_LAYER_2, timeout=3):
		"""
		iface_name -- bind to the given interface, mainly for MODE_LAYER_2
		mode -- set socket-mode for sending/receiving data. The following modes are supported:
			MODE_LAYER_2: layer 2 packets have to be provided (Ethernet etc)
			MODE_LAYER_3: layer 3 packets have to be provided (IP, ARP etc), mac is auto-resolved
		timeout -- read timeout in seconds
		"""

		self.__socket_send = None
		self.__socket_recv = None
		self.__mode = mode

		logger.debug("creating socket on: %s" % iface_name)
		# use raw socket for receiving in all modes
		self.__socket_recv = socket.socket(socket.AF_PACKET,
			socket.SOCK_RAW,
			socket.htons(SocketHndl.ETH_P_ALL))
		self.__socket_recv.settimeout(timeout)

		if iface_name is not None:
			self.__socket_recv.bind((iface_name, SocketHndl.ETH_P_ALL))

		# different sockets for sending
		if mode == SocketHndl.MODE_LAYER_2:
			self.__socket_send = self.__socket_recv
		elif mode == SocketHndl.MODE_LAYER_3:
			self.__socket_send = socket.socket(socket.AF_INET,
				socket.SOCK_RAW,
				socket.IPPROTO_RAW)
			# TODO: bind to interface?
			#if iface_name is not None:
			#	self.__socket_send.bind((iface_name, 0))

			self.__socket_send.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)

	def send(self, bts, dst=None):
		"""
		Send the given bytes to network.

		bts -- the bytes to be sent
		dst -- destination for Layer 3 if mode is MODE_LAYER_3
		"""

		if self.__mode == SocketHndl.MODE_LAYER_2:
			self.__socket_send.send(bts)
		elif self.__mode == SocketHndl.MODE_LAYER_3:
			self.__socket_send.sendto(bts, (dst, 0))

	def recv(self):
		"""
		return -- bytes received from network
		"""

		return self.__socket_recv.recv(65536)

	def recvp(self, filter_match_recv=None, lowest_layer=ethernet.Ethernet, max_amount=1):
		"""
		Receive packets from network. This does the same as calling recv() but using a receive
		filter and received bytes will be converted to packets using class given by lowest_layer.

		filter_match_recv -- filter as callback function to match packets to be retrieved. The only
			parameter is the created packet itself. Return True to accept a specific packet.
			Raise StopIteration to stop receiving packets
		lowest_layer -- packet class to be used to create new packets
		max_amount -- maximum amount of packets to be fetched
		return -- packets received from network as list
		"""

		received = []
		#logger.debug("listening for packets")

		try:
			while len(received) < max_amount:
				bts = self.recv()
				packet_recv = lowest_layer(bts)
				#logger.debug("got packet: %s" % packet_recv)
				try:
					if filter_match_recv(packet_recv):
						received.append(packet_recv)
				except TypeError:
					# no filter set
					received.append(packet_recv)
				except StopIteration:
					break
		except socket.timeout as e:
			logger.debug("socket timeout: stopping to receive socket data")
		return received

	def sr(self, packet_send, max_packets_recv=1, filter=None, lowest_layer=ethernet.Ethernet):
		"""
		Send a packet and receive answer packets. This will use information retrieved
		from direction() to retrieve answer packets.

		packet_send -- pypacker packet to be sent
		max_packets_recv -- max packets to be received
		filter -- filter as lambda function to match packets to be retrieved,
			return True to accept a specific packet
		lowest_layer -- packet class to be used to create new packets

		return -- packets receives
		"""

		received = []
		packet_send_clz = packet_send.__class__

		if self.__mode == SocketHndl.MODE_LAYER_2:
			self.send(packet_send.bin())
		elif self.__mode == SocketHndl.MODE_LAYER_3:
			#logger.debug("sr with layer 3: %s" % packet_send.dst_s)
			self.send(packet_send.bin(), dst=packet_send.dst_s)

		try:
			while len(received) < max_packets_recv:
				bts = self.recv()
				packet_recv = lowest_layer(bts)
				#logger.debug("got packet: %s" % packet_recv)
				try:
					if not filter(packet_recv):
						# filter didn't match
						continue
				except TypeError:
					# no filter set
					pass

				# packet_send_clz can be IP on MODE_LAYER_3, start to compare on corresponding receive-layer
				if packet_send.is_direction(packet_recv[packet_send_clz], pypacker.Packet.DIR_REV):
					#logger.debug("direction matched: %s" % packet_recv)
					received.append(packet_recv)
		except socket.timeout as e:
			logger.debug("stopping to receive socket data: %s" % e)
		return received

	def close(self):
		try:
			self.__socket_send.close()
		except:
			pass
		try:
			self.__socket_recv.close()
		except:
			pass
