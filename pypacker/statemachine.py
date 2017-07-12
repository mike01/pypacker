"""
Logic to build state machines. Borrowed from Scapy's Automata concept.
"""
import threading
import time

import logging

logger = logging.getLogger("pypacker")

STATE_TYPE_BEGIN	= 0
STATE_TYPE_INTERM	= 1  # default
STATE_TYPE_END		= 2


def timed_cb(obj, cb, timeout, old_f, pkt):
	time.sleep(timeout)

	if old_f.active:
		old_f.active = False
		logger.debug("executing timeout cb")
		cb(obj, pkt)


def sm_state(state_type=STATE_TYPE_INTERM, timeout=None, timeout_cb=None):
	def gen(old_f):
		if timeout is not None and timeout_cb is None:
			logger.warning(
				"timeout set to %d but no timeout action for %r",
				timeout,
				old_f.__name__)

		# replace with new method to store state infos
		def new_f(self, *args, **kwds):
			# logger.debug("calling original %r", old_f.__name__)
			if self._old_f is not None:
				# clear old timer
				self._old_f.active = False
				self._old_f = None

			ret = old_f(self, *args, **kwds)
			# start timeout after method reaches end
			if timeout is not None:
				old_f.active = True
				self._old_f = old_f
				logger.debug("starting timeout: %ds", timeout)
				threading.Thread(target=timed_cb, args=[self, timeout_cb, timeout, old_f, args[0]]).start()
			return ret

		if state_type == STATE_TYPE_BEGIN:
			logger.debug("setting inital state cb: %r", old_f)
			new_f._state_method_begin = True
		return new_f
	return gen


class AutomateMeta(type):
	def __new__(mcs, clsname, clsbases, clsdict):
		t = type.__new__(mcs, clsname, clsbases, clsdict)
		for key, val in clsdict.items():
			state_method = getattr(val, "_state_method_begin", None)

			if state_method is not None:
				print("initial method found: %r %r" % (key, val))
				t._state = key
				break
		return t


class StateMachine(object, metaclass=AutomateMeta):
	"""
	This state machine allows to react on network stimulus (incoming packets)
	and imitate/build protocols.

	State_1 -> event: decide next state -> State_2 ...
	"""
	def __init__(self, receive_cb):
		self._states = set()
		self._actions = set()
		self._receive_cb = receive_cb
		self._is_running = True
		self._old_f = None
		self._state = getattr(self, self._state, None)

		if self._state is None:
			logger.exception("no initial state defined!")
		else:
			logger.debug("found state: %r", self._state)

		self._receive_thread = threading.Thread(target=StateMachine.receive_cycler, args=[self])
		self._receive_thread.start()

	@staticmethod
	def receive_cycler(obj):
		while obj._is_running:
			pkt = obj._receive_cb()

			try:
				obj._state(pkt)
			except Exception as ex:
				logger.warning(
					"could not execute callback: %r, %r",
					obj._state,
					ex)

	def stop(self):
		self._is_running = False
		# socket needs to be closed first or this will likely hang
		self._receive_thread.join()
