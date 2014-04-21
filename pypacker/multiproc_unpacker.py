import multiprocessing as multiprocessing
from multiprocessing import Process
from collections import deque
import threading
import time
import struct
import logging 

from pypacker import pypacker
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip

logger = logging.getLogger("pypacker")

def _unpack_cb(clz_bts_filter):
	# clz_bts_filter = [class, (timestamp, bytes), filter]
	#logger.debug("unpacking")
	try:
		pkt = clz_bts_filter[0](clz_bts_filter[1][1])
	except:
		# something went wrong: return original (timestamp, bytes))
		return (clz_bts_filter[1])

	pkt.dissect_full()

	try:
		#logger.debug("apllying filter")
		if clz_bts_filter[2](pkt):
			return (clz_bts_filter[1][0], pkt)
		else:
			return None
	except Exception as e:
		#logger.debug("filter excption!!!!!! %r" % e)
		# filter is None (default) or any other Exception
		return (clz_bts_filter[1][0], pkt)

class MultiprocUnpacker(object):
	"""
	Multiprcessing unpacking mechanism.
	"""
	# size of input queue until multiprocessing-unpack takes place.
	MP_MIN_COUNT_PERFORM	= 10000

	def __init__(self, cb_next, input_queue_max=100000, lowest_layer=ethernet.Ethernet, filter=None):
		"""
		cb_next -- callback returning next object to be unpacked: (timestamp, bytes)
		lowest_layer -- packet class for unpacking eg Ethernet
		filter -- filter function: return True if packet should be return, otherwise False.
			Will return the packet on any Exception.
			IMPORTANT: do _NOT_ use lambda expression, the filter _MUST_ be pickable!
		"""
		self._cb_next = cb_next
		self._input_queue_max = input_queue_max
		self._lowest_layer = lowest_layer
		self._filter = filter

		self._q_input = deque()
		self._q_output = deque()
		self._stopped = False
		self._lock_next = threading.Lock()
		self._lock_add = threading.Lock()
		self._sema = threading.Semaphore()

		self._add_thread_stopped = False
		self._add_thread = threading.Thread(target=self._cb_addnew)

		try:
			amount_cpu = multiprocessing.cpu_count()
			logger.debug("creating multiproc pool, amount CPU: %d" % amount_cpu)
			self._pp_processpool = multiprocessing.Pool(amount_cpu * 4)
		except Exception as e:
			logger.warning("could not retrieve amount of cores: %r, assuming 1" % e)
			self._pp_processpool = multiprocessing.Pool(1)

		self._add_thread.start()

	def _cb_addnew(self):
		#logger.debug("_cb_addnew")

		while not self._stopped:
			#logger.debug("adding new to input")
			try:
				#if len(self._q_input) > self._input_queue_max:
				#	logger.debug("max reached for input queue, locking")
				#	self._lock_add.acquire()

				self._q_input.appendleft(self._cb_next())

				if len(self._q_input) >= MultiprocUnpacker.MP_MIN_COUNT_PERFORM:
					self._perform_mp()

				# TODO: check performance
				#try:
				#	self._lock_next.release()
				#except threading.ThreadError:
				#	pass
			except StopIteration:
				# eof reached: no more bytes
				self._add_thread_stopped = True
				#logger.debug("got last element for input, stopping input-thread")
				try:
					self._lock_next.release()
				except:
					pass

				break

	def _perform_mp(self):
		self._sema.acquire()
		qsize = len(self._q_input)

		if qsize > 0:
			logger.debug("performing mp, input/output len: %d/%d" % (len(self._q_input), len(self._q_output)))
			pkts = self._pp_processpool.map(_unpack_cb,
						[ tuple([self._lowest_layer, self._q_input.pop(), self._filter])
							for x in range(qsize)]
						)
			self._q_output.extendleft(pkts)
			logger.debug("performed mp, input/output len: %d/%d" % (len(self._q_input), len(self._q_output)))
		self._sema.release()

	def __next__(self):
		retval = None
		mp_forced = False

		while retval is None:
		# this will loop until something can be returned
			#logger.debug("next..")
			try:
				retval = self._q_output.pop()
				mp_forced = False
			except IndexError:
			# queue is empty
				#logger.debug("output queue is empty, releasing add lock")
				try:
					self._lock_add.release()
				except:
					pass

				#logger.debug("output queue empty, waiting..")
				inputlen = len(self._q_input)
				outputlen = len(self._q_output)

				if self._add_thread_stopped and inputlen == 0 and outputlen == 0:
					logger.debug("stopping in __next__")
					self.stop()
					raise StopIteration

				# TODO: make this faster, esp. for realtime nw handling
				# Note: timeout was added in python 3.2
				if not self._add_thread_stopped:
				# continue straight if add-thread stopped
					self._lock_next.acquire(timeout=1)
				#logger.debug("%d/%d" % (len(self._q_input), len(self._q_output)))
				#logger.debug("_lock_next released (timeout or via add)")

				inputlen = len(self._q_input)
				outputlen = len(self._q_output)

				if not mp_forced and inputlen > 0 and inputlen < MultiprocUnpacker.MP_MIN_COUNT_PERFORM and outputlen == 0:
				# not enough pkts created but we need one and there are som' ready to be unpacked: force mp
					#logger.debug("forcing mp! input/output len: %d/%d" % (len(self._q_input), len(self._q_output)))
					mp_forced = True
					self._perform_mp()
		return retval

	def __iter__(self):
		while not self._stopped:
			yield self.__next__()

	def stop(self):
		#logger.debug("stopping multiproc unpacker")
		self._stopped = True
		try:
			self._lock_add.release()
		except RuntimeError:
			# happens if allready unlocked
			pass
		try:
			self._lock_next.release()
		except RuntimeError:
			# happens if allready unlocked
			pass
		self._pp_processpool.close()
		self._pp_processpool.terminate()

"""
BYTES_ETH       = b"\x52\x54\x00\x12\x35\x02\x08\x00\x27\xa9\x93\x9e\x08\x00"
# src="10.0.2.15", dst="10.32.194.141", type=6 (TCP)
BYTES_IP        = b"\x45\x00\x00\xff\xc5\x78\x40\x00\x40\x06\x9c\x81\x0a\x00\x02\x0f\x0a\x20\xc2\x8d"
# sport=6667, dport=55211, win=46
BYTES_TCP       = b"\x1a\x0b\x00\x50\xb9\xb7\x74\xa9\xbc\x5b\x83\xa9\x80\x10\x00\x2e\xc0\x09\x00\x00\x01\x01\x08\x0a\x28\x2b\x0f\x9e\x05\x77\x1b\xe3"
# sport=38259, dport=53
BYTES_UDP       = b"\x95\x73\x00\x35\x00\x23\x81\x49"
BYTES_HTTP      = b"GET / HTTP/1.1\r\nHeader1: value1\r\nHeader2: value2\r\n\r\nThis is the body content\r\n"
BYTES_ETH_IP_TCP_HTTP = BYTES_ETH + BYTES_IP + BYTES_TCP + BYTES_HTTP


def cb():
	return (1234, BYTES_ETH_IP_TCP_HTTP)
def _filter(pkt):
	return pkt.src is not None
	#return False
"""
