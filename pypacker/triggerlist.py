"""TriggerList for handling dynamic headers."""

import logging

logger = logging.getLogger("pypacker")


class TriggerList(list):
	"""
	List with trigger-capabilities representing dynamic header.
	This list can contain one type of raw bytes, tuples or packets representing individual
	header fields. Using bytes or tuples "_pack()" should be overwritten to reassemble bytes.
	A TriggerList must be initiated using the no-parameter constructor and modified
	by using append/extend/del etc.
	Performance hint: for lazy dissecting, call init_lazy_dissect(buf, callback)
	which gets the buffer to be dissected. The callback has to return a simple
	list itself. Dissecting dynamic fields will only take place on access to TriggerList.
	"""
	def __init__(self, packet):
		# set by external Packet
		self._packet = packet
		self._cached_result = None

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

		if type(k) is int:
			itemlist = [self[k]]
		else:
		# assume slice: [x:y]
			itemlist = self[k]
		super().__delitem__(k)
		logger.debug("removed, handle mod")
		self.__handle_mod(itemlist, add_listener=False)
		logger.debug("finished removing")

	def __getitem__(self, k):
		"""
		Needed for lazy dissect. Search items giving int or bytes (if supported)
		"""
		self._lazy_dissect()
		return super().__getitem__(k)

	def __len__(self):
		"""We need the real length after dissecting: lazy dissect now!"""
		self._lazy_dissect()
		return super().__len__()

	def init_lazy_dissect(self, buf, callback):
		"""
		Initialize lazy dissecting for performance reasons. A packet has to be assigned first to 'packet'.

		buf -- the buffer to be dissected
		callback -- method to be used to dissect the buffer. Signature: callback(buffer) return [].
		"""
		self._cached_result = buf

		if len(buf) == 0:
		# avoid unneeded lazy parsing
			return
		#logger.debug("lazy init using: %s" % buf)
		self._dissect_callback = callback
		self._packet._header_changed = True

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
			# callback set to None
			pass
		except AttributeError:
			# no callback present
			pass
		#except Exception as e:
		#	logger.warning("can't lazy dissect in TriggerList: %s" % e)
		#	#logger.warning("master packet is: %s" % self._packet)

	def append(self, v):
		self._lazy_dissect()
		#logger.debug("adding to triggerlist (super)")
		super().append(v)
		#logger.debug("handling mod")
		self.__handle_mod([v])
		#logger.debug("finished")

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

	def __handle_mod(self, val, add_listener=True):
		"""
		Handle modifications of TriggerList.

		val -- list of bytes, tuples or packets
		add_listener -- re-add listener if True
		"""
		try:
			for v in val:
			# react on changes of packets in this triggerlist
				v._remove_change_listener(None, remove_all=True)
				if add_listener:
					v._add_change_listener(self._notify_change)
		except AttributeError:
		# this will fail if val is not a packet
			pass

		#logger.debug("notifying change")
		# header value added, revmoved etc: format needs update
		self._notify_change(val, force_fmt_update=True)
		logger.debug("handle mod sub, cached: %s" % self._cached_result)
		self._handle_mod(val)
		logger.debug("handle mod sub: finished")

	def _handle_mod(self, val):
		"""
		Handle modifications of tirggerlist (adding, removing etc) for advanced
		header field handling eg IP->offset. Default implementation does nothing.
		Gets called AFTER item was added to TriggerList.

		val -- list of bytes, tuples or Packets
		"""
		pass

	def _notify_change(self, pkt, force_fmt_update=False):
		"""
		Called by informers eg Packets in this list. Reset caches and set correct states
		on Packet containing this TrigerList.
		"""
		try:
			if force_fmt_update or pkt._body_changed:
			# structure has changed so we need to recalculate the whole format
				self._packet._header_format_changed = True
		except AttributeError:
		# this only works on Packets
			pass

		# list changed: old cache of TriggerList not usable anymore
		# this will raise an exception if there is no packet
		self._packet._header_changed = True
		self._cached_result = None

	__TYPES_TRIGGERLIST_SIMPLE = set([bytes, tuple])

	def bin(self):
		"""Output the TriggerLists elements as concatenated bytestring."""
		if self._cached_result is None:
			#logger.debug("caching result")
			try:
				probe = self[0]
				#logger.debug("probe is: %r" % probe)
			except IndexError:
				return b""

			probe_type = type(probe)
			if not probe_type in TriggerList.__TYPES_TRIGGERLIST_SIMPLE:
				# assume packet
				self._cached_result = b"".join([pkt.bin() for pkt in self])
			else:
				self._cached_result = self._pack()

		return self._cached_result

	def __repr__(self):
		self._lazy_dissect()
		return super().__repr__()

	def find_pos(self, search_cb, offset=0):
		"""
		Find an item-position giving search callback as search criteria.
		Searchable content: bytes, tuples (compare index 0), packagees

		search_cb -- callback to compare values, signature: callback(value) [True|False]
			Return True to return value found.
		offset -- start at index "offset" to search
		return -- index of first element found or None
		"""
		self._lazy_dissect()

		while offset < len(self):
			try:
				if search_cb(self[offset]):
					return offset
			except:
				# error on callback (unknown fields etc), ignore
				pass
			offset += 1
		return None

	def find_value(self, search_cb, offset=0):
		"""
		Same as find_pos() but directly returning found value or None.
		"""
		try:
			return self[self.find_pos(search_cb, offset=offset)]
		except TypeError:
			return None

	def __iter__(self):
		self._lazy_dissect()
		return super().__iter__()

	def _pack(self):
		"""
		This must be overwritten to pack dynamic headerfields represented by bytes like TriggerList[b"xxx", b"yyy"].
		The basic implemenation just concatenates all bytes without change.

		return -- byte string representation of this triggerlist
		"""
		return b"".join(self)
