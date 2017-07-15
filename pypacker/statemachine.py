"""
Logic to build state machines. Borrowed from Scapy's Automata concept.
"""
import threading
import collections
import logging

logger = logging.getLogger("pypacker")

STATE_TYPE_BEGIN	= 0
STATE_TYPE_INTERM	= 1  # default
STATE_TYPE_END		= 2


class TimedCallback(threading.Thread):
	def __init__(self):
		self._obj = None
		self._is_running = True
		self._cb = None
		# assume this will never trigger
		self._timeout = 9999999
		self._event = threading.Event()
		super().__init__()
		self.start()

	def run(self):
		logger.debug("starting cb iterator")

		while self._is_running:
			# logger.debug("cb: next round")
			self._event.clear()
			self._event.wait(timeout=self._timeout)

			# wait was interrupted
			if self._event.is_set():
				continue

			if self._cb is not None:
				# logger.debug("executing timeout cb")
				self._cb(self._obj)
		logger.debug("cb iterator finished")

	def retrigger(self, obj, timeout, cb):
		self._obj = obj
		self._timeout = timeout
		self._cb = cb
		self._event.set()

	def set_inactive(self):
		self._cb = None
		self._timeout = 9999999
		self._event.set()

	def stop(self):
		self._is_running = False
		self._event.set()

_cb_threads = collections.defaultdict(TimedCallback)


def sm_state(state_type=STATE_TYPE_INTERM, timeout=None, timeout_cb=None):
	def gen(old_f):
		if timeout is not None and timeout_cb is None:
			logger.warning(
				"timeout set to %d but no timeout action for %r",
				timeout,
				old_f.__name__)

		# replace with new method to store state infos
		def new_f(self, *args, **kwds):
			# end of function (state) -> clear old one
			# logger.debug("getting cb class via %r", self.__class__)
			cb_thread = _cb_threads[self.__class__]
			cb_thread.set_inactive()

			ret = old_f(self, *args, **kwds)

			# start timeout after method reaches end
			if timeout is not None:
				# logger.debug("restarting timeout: %ds", timeout)
				cb_thread.retrigger(self, timeout, timeout_cb)

			return ret

		if state_type == STATE_TYPE_BEGIN:
			#logger.debug("setting inital state cb: %r", old_f)
			new_f._state_method_begin = True
		return new_f
	return gen


class AutomateMeta(type):
	def __new__(mcs, clsname, clsbases, clsdict):
		t = type.__new__(mcs, clsname, clsbases, clsdict)
		for key, val in clsdict.items():
			state_method = getattr(val, "_state_method_begin", None)

			if state_method is not None:
				#logger.debug("initial method found: %r %r" % (key, val))
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
			logger.debug("initial state: %r", self._state)

		self._receive_thread = threading.Thread(
			target=StateMachine.receive_cycler,
			args=[self]
		)
		self._receive_thread.start()

	@staticmethod
	def receive_cycler(obj):
		while obj._is_running:
			pkt = obj._receive_cb()

			try:
				obj._state(pkt)
			except Exception as ex:
				logger.warning(
					"could not execute callback: %r",
					obj._state
				)
				#ex.printstacktrace()
		logger.debug("receive cycler finished")

	def stop(self):
		self._is_running = False
		# _receive_cb() (eg sockets) needs to be stopped first or this will likely hang
		self._receive_thread.join()

		try:
			_cb_thread = _cb_threads.get(self.__class__, None)
			_cb_thread.stop()
		except AttributeError:
			pass
			# logger.debug("no cb thread found")
		except Exception as ex:
			ex.printstacktrace()
