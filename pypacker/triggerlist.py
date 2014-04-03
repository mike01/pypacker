"""TriggerList for handling dynamic headers."""

import logging

logger = logging.getLogger("pypacker")


class TriggerList(list):
	"""
	List with trigger-capabilities representing dynamic header.
	This list can contain raw bytes, tuples or packets representing individual
	header fields. Using bytes or tuples "_pack()" should be overwritten to reassemble bytes.
	A TriggerList must be initiated using the no-parameter constructor and modified
	by using append/extend/del etc.
	Performance hint: for lazy dissecting, call init_lazy_dissect(buf, callback)
	which gets the buffer to be dissected. The callback has to return a simple
	list itself. Dissecting dynamic fields will only take place on access to TriggerList.
	TODO: add mode for simple/list based access
	"""
	def __init__(self, lst=[], clz=None, packet=None):
		# set by external Packet
		self._packet = packet
		self._cached_result = None
		self._dissect_callback = None

		# a triggerlist is _never_ initiated using constructors
		if len(lst) > 0:
			raise Exception("TriggerList initiated using non-empty list, don't do this!")
		super().__init__()

	def __iadd__(self, v):
		"""Item can be added using '+=', use 'append()' instead."""
		self._lazy_dissect()
		super().append(v)
		self.__handle_mod([v])
		return self

	def __setitem__(self, k, v):
		self._lazy_dissect()

		try:
			# remove listener from old packet which gets overwritten
			self[k].remove_change_listener(None, remove_all=True)
		except:
			pass
		super().__setitem__(k, v)
		self.__handle_mod([v])

	def __delitem__(self, k):
		self._lazy_dissect()
		super().__delitem__(k)

	def __getitem__(self, k):
		"""
		Needed for lazy dissect. Search items giving int or bytes (if supported)
		"""
		self._lazy_dissect()
		return super().__getitem__(k)

	def _get_positions_for_bytes(self, bts):
		"""
		Find alle positions matching the given bytes. Default implementation checks for equality of
		first the value.

		return -- index between 0 and MAX_SIZE-1 or raise KeyError
		"""
		return [pos for pos, key_val in enumerate(self) if key_val == bts]

	def __len__(self):
		"""We need the real length after dissecting: lazy dissect now!"""
		self._lazy_dissect()
		return super().__len__()

	def init_lazy_dissect(self, buf, callback):
		"""
		Initialize lazy dissecting for performance reasons. A packet has to be assigned first to 'packet'.

		buf -- the buffer to be dissected
		callback -- method to be used to dissect the buffer. Gets this buffer as only parameter.
		"""
		#logger.debug("lazy init using: %s" % buf)
		self._cached_result = buf
		self._dissect_callback = callback
		self._packet._header_changed = True
		self._packet._header_format_changed = True

	def _lazy_dissect(self):
		try:
			#logger.debug("dissecting in triggerlist")
			ret = self._dissect_callback(self._cached_result)
			#logger.debug("adding dissected parts: %s" % ret)
			# this won't change values: we just dissect the original value
			super().extend(ret)
			# remove callback: no lazy dissect possible anymore for this object
			self._dissect_callback = None
		except TypeError:
			# no callback present
			pass
		#except Exception as e:
		#	logger.warning("can't lazy dissect in TriggerList: %s" % e)
		#	#logger.warning("master packet is: %s" % self._packet)

	def append(self, v):
		self._lazy_dissect()
		super().append(v)
		self.__handle_mod([v])

	def extend(self, v):
		self._lazy_dissect()
		super().extend(v)
		self.__handle_mod(v)

	def insert(self, pos, v):
		self._lazy_dissect()
		super().insert(pos, v)
		self.__handle_mod([v])

	#
	#

	def __handle_mod(self, val):
		"""
		Handle modifications of TriggerList.

		val -- list of bytes, tuples or packets
		"""
		try:
			for v in val:
				v.remove_change_listener(None, remove_all=True)
				v.add_change_listener(self._notify_change)
		# This will fail if val is not a packet
		except AttributeError:
			pass

		self._notify_change(val, force_fmt_update=True)
		self._handle_mod(val)

	def _handle_mod(self, val):
		"""
		Handle modifications of tirggerlist (adding, removing etc) for advanced
		header field handling eg IP->offset.

		val -- list of bytes, tuples or Packets
		"""
		pass

	def _notify_change(self, pkt, force_fmt_update=False):
		"""
		Called by informers eg Packets in this list. Reset caches and set correct states
		on Packet containing this TrigerList.
		"""
		try:
			# structure has changed so we need to recalculate the whole format
			if force_fmt_update or pkt.body_changed:
				self._packet._header_format_changed = True
			# header and/or body changed, clear cache
			self._packet.header_changed = True
		# this only works on Packets
		except AttributeError:
			pass
		# old cache of TriggerList not usable anymore
		self._cached_result = None

	__TYPES_TRIGGERLIST_SIMPLE = set([bytes, tuple])

	def bin(self):
		"""Output the TriggerLists elements as concatenated bytestring."""
		if self._cached_result is None:
			try:
				probe = self[0]
			except IndexError:
				return b""

			probe_type = type(probe)
			if not probe_type in TriggerList.__TYPES_TRIGGERLIST_SIMPLE:
				# assume packet
				self._cached_result = b"".join( [ pkt.bin() for pkt in self ] )
			else:
				self._cached_result = self._pack()

		return self._cached_result

	def __repr__(self):
		self._lazy_dissect()
		return super().__repr__()

	def find_pos(self, needle, extract_cb=None, offset=0, preformat_cb=lambda x: x):
		"""
		Find an item-position giving needle as search criteria.

		needle -- value to search for
		extract_cb -- lambda expression to extract values from packets: needle == extract_cb(packet)
		offset -- start at index "offset" to search
		preformat_cb -- lambda expression to preformat key before comparing: needle == preformat_cb(key),
			eg lowercase for HTTP-header names
		return -- index of first element found or None
		"""
		def cmp_bytes(a, b):
			return a == preformat_cb( b )

		def cmp_tuple(a, b):
			# tuples are found by first index
			return a == preformat_cb( b[0] )

		def cmp_packet(a, b):
			return a == preformat_cb( extract_cb(b) )

		try:
			probe = self[0]
		except IndexError:
			return None

		if type(probe) is bytes:
			cmp = cmp_bytes
		elif type(probe) is tuple:
			cmp = cmp_tuple
		else:
			# assume packet
			cmp = cmp_packet

		while offset < len(self):
			if cmp(needle, self[offset]):
				return offset
			offset += 1
		return None

	def find_value(self, needle, extract_cb=None, offset=0, preformat_cb=lambda x: x):
		"""
		Same as find_pos() but directly returning found value or None.
		"""
		try:
			return self[ self.find_pos(needle, extract_cb, offset, preformat_cb) ]
		except TypeError:
			return None

	#def __str__(self):
	#	return str(self.bin(), encoding='UTF-8')

	def __iter__(self):
		self._lazy_dissect()
		return super().__iter__()

	def _pack(self):
		"""
		This must be overwritten to pack textual dynamic headerfields eg HTTP.
		The basic implemenation just concatenates all bytes without change.
		"""
		return b"".join(self)
