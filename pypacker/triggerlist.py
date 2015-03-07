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
	"""
	def __init__(self, bts, packet):
		# set by external Packet
		self._packet = packet
		self._cached_result = bts
		# TODO: lazy init?

		super().__init__()

	def __iadd__(self, v):
		"""Item can be added using '+=', use 'append()' instead."""
		super().__iadd__(v)
		self.__handle_mod([v])
		return self

	def __setitem__(self, k, v):
		try:
			# remove listener from old packet which gets overwritten
			self[k].remove_change_listener(None, remove_all=True)
		except:
			pass
		super().__setitem__(k, v)
		self.__handle_mod([v])

	def __delitem__(self, k):
		if type(k) is int:
			itemlist = [self[k]]
		else:
		# assume slice: [x:y]
			itemlist = self[k]
		super().__delitem__(k)
		logger.debug("removed, handle mod")
		self.__handle_mod(itemlist, add_listener=False)
		logger.debug("finished removing")


	def append(self, v):
		#logger.debug("adding to triggerlist (super)")
		super().append(v)
		#logger.debug("handling mod")
		self.__handle_mod([v])
		#logger.debug("finished")

	def extend(self, v):
		super().extend(v)
		self.__handle_mod(v)

	def insert(self, pos, v):
		super().insert(pos, v)
		self.__handle_mod([v])

	#
	#

	def __handle_mod(self, val, add_listener=True):
		"""
		Handle modifications of this TriggerList (adding, removing, ...).

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
		self._notify_change(val)
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

	def _notify_change(self):
		"""
		Update _header_changed of and _header_format_changed of the Packet having
		this TriggerList as field and _cached_result.
		Called by: this list on changes or Packets in this list
		"""
		try:
			self._packet._header_changed = True
			self._packet._header_format_changed = True
		except AttributeError:
		# this only works on Packets
			pass

		# list changed: old cache of TriggerList not usable anymore
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

	def find_pos(self, search_cb, offset=0):
		"""
		Find an item-position giving search callback as search criteria.
		Searchable content: bytes, tuples (compare index 0), packagees

		search_cb -- callback to compare values, signature: callback(value) [True|False]
			Return True to return value found.
		offset -- start at index "offset" to search
		return -- index of first element found or None
		"""
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

	def _pack(self):
		"""
		This must be overwritten to pack dynamic headerfields represented by bytes like TriggerList[b"xxx", b"yyy"].
		The basic implemenation just concatenates all bytes without change.

		return -- byte string representation of this triggerlist
		"""
		return b"".join(self)
