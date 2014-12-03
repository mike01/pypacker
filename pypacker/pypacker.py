"""
Simple packet creation and parsing logic.
"""

import logging
import random
import struct
from collections import OrderedDict

from pypacker import triggerlist

logging.basicConfig(format="%(levelname)s (%(funcName)s): %(message)s")
logger = logging.getLogger("pypacker")
#logger.setLevel(logging.WARNING)
#logger.setLevel(logging.INFO)
logger.setLevel(logging.DEBUG)

# avoid unneeded references for performance reasons
pack = struct.pack
unpack = struct.unpack
calcsize = struct.calcsize
randint = random.randint


class UnpackError(Exception):
	pass


class NeedData(Exception):
	pass


class MetaPacket(type):
	"""
	This Metaclass is a more efficient way of setting attributes than using __init__.
	This is done by reading name / format / default out of __hdr__ in every subclass.
	This configuration is set one time when loading the module (not at instatiation).
	Actual values are retrieved using "obj.field" notation.

	CAUTION:
	- list et al are _SHARED_ among all classes! A copy is needed on changes to them.
	General note: __new__ is called before __init__
	- new protocols: don't use header fields having same names as methods in Packet class
	"""

	def __new__(cls, clsname, clsbases, clsdict):
		t = type.__new__(cls, clsname, clsbases, clsdict)
		# all (static+dynamic) header field descriptions: name -> format, order needs to be preseved
		t._hdr_fields = OrderedDict()
		# all active (static+dynamic) fields in order
		t._hdr_fields_active = []
		# dictionary of dynamic headers: name -> TriggerListClass
		t._hdr_fields_dyn_dict = {}
		# get header-infos from subclass: ("name", "format", value)
		hdrs = getattr(t, "__hdr__", None)
		# cache header for performance reasons
		t._header_cached = []

		if hdrs is not None:
			#logger.debug("loading meta for: %s, st: %s" % (clsname, st))
			# all header formats including byte order
			t._hdr_fmt_order = getattr(t, "__byte_order__", ">")
			hdr_fmt = [t._hdr_fmt_order]

			for hdr in hdrs:
				#logger.debug("meta: %s -> %s" % (x[0]))
				t._hdr_fields[hdr[0]] = hdr[1]

				if hdr[1] is not None:
				# simple type
					if hdr[2] is not None:
					# is active
						t._hdr_fields_active.append(hdr[0])
						hdr_fmt.append(hdr[1])
						t._header_cached.append(hdr[2])
				else:
				# assume TriggerList (always active)
					t._hdr_fields_active.append(hdr[0])
					hdr_fmt.append("0s")
					t._header_cached.append(b"")

				if type(hdr[2]) is not type:
					# TODO: remove
					# simple type, set initial value
					#setattr(t, hdr[0], hdr[2])
					pass
				else:
					# assume TriggerList
					# remmember for lazy instantiation
					t._hdr_fields_dyn_dict[hdr[0]] = hdr[2]

			#logger.debug(">>> translated header names: %s/%r" % (clsname, t._hdr_name_translate))
			# current format list as string for convenience
			t._hdr_fmt = struct.Struct("".join(v for v in hdr_fmt))
			t._header_cached = t._hdr_fmt.pack(*t._header_cached)
			#logger.debug("formatstring is: %s" % hdr_fmt)
			# body as raw byte string (None if handler is present)
			t._body_bytes = b""
			# name of the attribute which holds the object representing the body aka the body handler
			t._bodytypename = None
			# next lower layer: a = b + c -> b will be lower layer for c
			t._lower_layer = None
			# track changes to header values and data: This is needed for layers like TCP for
			# checksum-recalculation. Set to "True" on changes to header/body values, set to False on "bin()"
			## track changes to header values
			t._header_changed = False
			## track changes to header format. This will happen eg when changing TriggerLists
			t._header_format_changed = False
			## track changes to body value like [None | bytes | body-handler] -> [None | bytes | body-handler]
			t._body_changed = False
			# objects which get notified on changes on header or body (shared)
			# TODO: use sets here
			t._changelistener = []
			# lazy handler data, format: [name, class, bytes]
			t._lazy_handler_data = None
			# indicates the most top layer until which should be unpacked (vs. lazy parsing = just next upper layer)
			t._target_unpack_clz = None
			# indicates if active-field list for tracking header infos is still shared
			t._hdrlist_original = True
			# inicates if given static header values got already unpacked
			t._unpacked = False

		# TODO: pre-set variables to None
		return t


class Packet(object, metaclass=MetaPacket):
	"""
	Base packet class, with metaclass magic to generate members from self.__hdr__.
	This class can be instatiated via:

		Packet(byte_string)
		Packet(key1=val1, key2=val2, ...)
		Packet(byte_string, key1=val1, key2=val2, ...)

	Every packet got an optional header and an optional body.
	Body-data can be raw byte string OR a packet itself (the body handler).
	which stores the data. The following schema illustrates the Packet-structure:

	Packet structure
	================

	[Packet:
	[headerfield1]
	[headerfield2]
	...
	[headerfieldN]
	[Body: Handler (Packet):
		[headerfield1]
		...
		[Body: Handler (Packet):
			...
			[Body: Raw data]
	]]]

	A header definition like __hdr__ = (("name", "12s", b"defaultvalue"),) will define a header field
	having the name "name", format "12s" and default value b"defaultvalue" as bytestring. Fields will
	be added in order of definition. __byte_order__ can be set to override the default value '>'.
	Extending classes should overwrite the "_dissect"-method in order to dissect given data.

	Requirements
	============

		- Auto-decoding of headers via given format-patterns (defined via __hdr__)
		- Auto-decoding of body-handlers (like IP -> parse IP-data -> add TCP-handler to IP -> parse TCP-data..)
		- Access of fields via "layer1.key" notation
		- There are two types of headers:
			1) Static (same order, pre-defined header-names, constant format)
				Format for __hdr__: ("name", "format", value)
				This header type can be deactivated by setting the value to None (initial or afterwards)
			2) Dynamic (Packet based or textual protocol-headers, changes in format, length and order)
				Format for __hdr__: ("name", None, TriggerList)
				Allowed contents (mutual exclusive): raw bytes, tuples like (key, value), Packets

				For raw bytes or tuple-based TriggerLists, _pack() can be overwritten to reassemble
				the whole header (see ip.py and tcp.py).
				For changes on other fields resulting from TriggerList-changes, _handle_mod(value)
				can be overwritten
		- Convenient access for standard types (MAC, IP address) using string-representations
			This is done by appending "_s" to the attributename:
			ip.src_s = "127.0.0.1"
			ip_src_bytes = ip.src

			Implementation info:
			Convenient access should be set via varname_s = pypacker.Packet._get_property_XXX("varname")
		- Access of higher layers via layer1.layer2.layerX or "layer1[layerX]" notation
		- Concatination via "layer1 + layer2 + layerX"
		- Header-values with length < 1 Byte should be set by using properties
		- Static fields can be deactivated via setting None "obj.field = None", re-activate by setting a value
		- Checksums (static auto fields in general) are auto-recalculated when calling bin(update_auto_fields=True) (default)
		- Ability to check direction to other Packets via "direction()"
		- Access to next lower/upper layer
		- No correction of given raw packet-data eg checksums when creating a packet from it
			(exception: if the packet can't be build without correct data -> raise exception).
			The internal state will only be updated on changes to headers or data.
		- General rule: less changes to headers/body-data = more performance

	Call-flow
	=========

		pypacker(__init__)
			-> _dissect(): has to be overwritten, get to know/verify the real header-structure
				-> (optional): call _parse_handler() setting a handler representing an upper-layer
				-> (optional): call init_lazy_dissect() to initiate a dynamic field
			-> _init_header_body(): set caches for header/body
			-> _unpack(): set all header values (lazy call)

	"""

	"""Dict for saving body datahandler globaly: { Classname : {id : HandlerClass} }"""
	_handler = {}
	"""Constants for Packet-directons"""
	DIR_SAME	= 1
	DIR_REV		= 2
	DIR_UNKNOWN	= 3

	def __init__(self, *args, **kwargs):
		"""
		Packet constructor: Packet(bytestring, target_class, keyword1=val1, keyword2=val2, ...).
		Note: target_class is only mmeant for internal usage

		buf -- packet bytes to build packet from
		keywords -- keyword arguments correspond to header fields to be set (overwrites fields parsed via buf)
		"""

		if args:
			if len(args) > 1:
				# additional parameters are only given by packet-class itself internaly
				self._target_unpack_clz = args[1]._target_unpack_clz

			try:
				logger.debug("dissecting: %r" % self.__class__.__name__)
				self._dissect(args[0])
				logger.debug("init header body: %r" % self.__class__.__name__)
				self._init_header_body(args[0])
			except Exception as e:
				# TODO: remove to continue parsing
				#raise Exception("%r" % e)
				logger.exception("could not dissect or unpack: %r" % e)
		elif len(kwargs) > 0:
			# overwrite default parameters
			logger.debug("New Packet with keyword args (%s)" % self.__class__.__name__)
			for k, v in kwargs.items():
				#logger.debug("setting: %s=%s" % (k, v))
				self.__setattr__(k, v)
			self._unpacked = True
			# no reset: directly assigned = changed

	def _dissect(self, buf):
		"""
		Dissect packet bytes. Call self._parse_handler() and/or dyn_field.init_lazy_dissect() to initiate
		packet state.

		buf -- bytestring to be dissected
		"""
		pass

	def __len__(self):
		"""Return total length (= header + all upper layer data) in bytes."""

		if self._body_bytes is not None:
			#logger.debug("returning length from raw bytes in %s" % self.__class__.__name__)
			return self.hdr_len + len(self._body_bytes)
		else:
			try:
				# avoid unneeded parsing
				#logger.debug("returning length from cached lazy handler in %s" % self.__class__.__name__)
				return self.hdr_len + len(self._lazy_handler_data[2])
			except TypeError:
				#logger.debug("returning length from present handler in %s, handler is: %s"\
				#	% (self.__class__.__name__, self._bodytypename))
				return self.hdr_len + len(self.__getattribute__(self._bodytypename))

	#
	# public access to header length: keep it uptodate
	#
	def __get_hdrlen(self):
		# format changed: recalculate length
		if self._header_format_changed:
			self._update_fmt()
		return self._hdr_fmt.size

	# update format if needed and return actual header size
	hdr_len = property(__get_hdrlen)
	header_len = property(__get_hdrlen)

	# non-intrusive version of "hdr_len": doesn't change anything, format needs to be uptodate to return correct length
	# TODO: remove if unneeded
	_hdr_len = property(lambda v: v._hdr_fmt.size)

	def __get_bodybytes(self):
		"""
		Return raw data bytes or handler bytes (including all upper layers) if present.
		This is the same as calling bin() but excluding this header and without resetting changed-status.
		"""
		if self._lazy_handler_data is not None:
		# no need to parse: raw bytes for all upper layers
			return self._lazy_handler_data[2]
		elif self._bodytypename is not None:
		# some handler was set
			hndl = self.__getattribute__(self._bodytypename)
			return hndl._pack_header() + hndl.__get_bodybytes()
		# return raw bytes
		else:
			return self._body_bytes

	def __set_body_bytes(self, value):
		"""
		Set body bytes to value (bytestring). This will reset any handler.

		value -- a byte string (do NOT set to None)
		"""
		if self._bodytypename is not None:
		# reset all handler data
			self._set_bodyhandler(None)
		#logger.debug("setting new raw data: %s" % value)
		self._body_bytes = value

	# return body data as raw bytes (deprecated)
	data = property(__get_bodybytes, __set_body_bytes)
	# get and set bytes for body
	body_bytes = property(__get_bodybytes, __set_body_bytes)

	def _get_bodyhandler(self):
		"""
		return -- handler object or None if not present.
		"""
		if self._lazy_handler_data is not None:
		# parse lazy handler data on the next layer
			return self.__getattr__(self._lazy_handler_data[0])
		elif self._bodytypename is not None:
		# body handler allready parsed
			return self.__getattribute__(self._bodytypename)
		else:
		# nope, chuck testa
			#logger.debug("returning None")
			return None

	def _set_bodyhandler(self, hndl):
		"""
		Set handler to decode the actual body data using the given handler
		and make it accessible via layername.addedtype like ethernet.ip.
		This will take the classname of the given handler as lowercase.
		If handler is None any handler will be reset and data will be set to an
		empty byte string.

		hndl -- the handler to be set (None or Packet)
		"""
		if hndl is None:
		# switch (handler=obj, body_bytes=None) to (handler=None, body_bytes=b'')
			self._bodytypename = None
			# avoid (body_bytes=None, handler=None)
			self._body_bytes = b""
		else:
			# set a new body handler
			# associate ip, arp etc with handler-instance to call "ether.ip", "ip.tcp" etc
			self._bodytypename = hndl.__class__.__name__.lower()
			# connect highest layer (self) to upper (hndl) layer eg IP -access to-> TCP
			hndl._lower_layer = self
			object.__setattr__(self, self._bodytypename, hndl)
			self._body_bytes = None

	# get/set body handler or None. Note: this will force lazy parsing when reading
	body_handler = property(_get_bodyhandler, _set_bodyhandler)
	# get/set body handler or None. Note: this will force lazy parsing when reading
	upper_layer = property(_get_bodyhandler, _set_bodyhandler)
	# get next lower body handler or None (lowest layer reached)
	lower_layer = property(lambda v: v._lower_layer)

	def _lowest_layer(self):
		current = self

		while current._lower_layer is not None:
			current = current._lower_layer

		return current

	def _highest_layer(self):
		current = self

		while current.body_handler is not None:
			current = current.body_handler

		return current

	# get lowest layer
	lowest_layer = property(_lowest_layer)
	# get top layer
	highest_layer = property(_highest_layer)

	def __getattr__(self, varname):
		"""
		Gets called if there are no fields matching the name 'varname'. Check if we got
		lazy handler data or lazy dynamic fields set which must now me initiated.
		"""
		if self._lazy_handler_data is not None and self._lazy_handler_data[0] == varname:
		# lazy handler data was set, parse lazy handler data now!
			#logger.debug("lazy parsing handler: %s" % varname)
			handler_data = self._lazy_handler_data

			try:
				# instantiate handler class using lazy data buffer
				# See _parse_handler() for 2nd place where handler instantation takes place
				type_instance = handler_data[1](handler_data[2], self)

				self._set_bodyhandler(type_instance)
				self._lazy_handler_data = None
				# this was a lazy init: same as direct parsing -> no body change
				self._body_changed = False

				return type_instance
			except:
				# error on lazy parsing: set raw bytes
				#logger.debug("Exception on parsing lazy handler")
				logger.exception("could not lazy-parse handler: %r, there could be 2 reasons for this: " +
					"1) packet was malformed 2) parsing-code is buggy" % handler_data)
				self._bodytypename = None
				object.__setattr__(self, "_body_bytes", handler_data[2])
				self._lazy_handler_data = None

				# TODO: remove this to ignore parse errors (set raw bytes after all)
				#raise Exception("2>>>>>>>>>>> %r (lazy parsing)" % e)
				return None
		#logger.debug("searching for dynamic field: %s/%r" % (varname,self._hdr_fields_dyn_dict))
		# static fields not yet unpacked
		elif varname in self._hdr_fields_dyn_dict:
		# no lazy body data, try dynamic fields
			#logger.debug("lazy init of dynamic field: %s" % varname)
			dh = self._hdr_fields_dyn_dict[varname](self)
			object.__setattr__(self, varname, dh)
			return dh
		elif varname in self._hdr_fields:
			# static fields not yet unpacked, do it now
			logger.debug("unpacking static fields in: %r (got: %s)" % (self.__class__, varname))
			self._unpack()
			logger.debug("got static fields: %s=%r" % (varname, self.__getattribute__(varname)))
			return self.__getattribute__(varname)

		#logger.warning("unable to find: %s" % varname)
		# nope not found...
		raise AttributeError("Can't find Attribute in %r: %s (body type: %s)" % (self.__class__, varname, self._bodytypename))

	def _deactivate_hdr(self, hdr):
		"""
		Dectivate a static field.
		"""
		# deactivating is less costly than activating
		#logger.debug("de-activating: %s" % hdr)
		if self._hdrlist_original:
			self._hdr_fields_active = list(self._hdr_fields_active)
			self._hdrlist_original = False
		self._hdr_fields_active.remove(hdr)
		self._header_format_changed = True

	def _activate_hdr(self, hdr):
		"""
		Activate a static field.
		"""
		#logger.debug("activating: %s" % hdr)
		# we need the correct order: use _hdr_fields
		# assuming field was already set to "None"
		self._hdr_fields_active = [name for name in self._hdr_fields if name in self._hdr_fields_active + [hdr]]
		self._hdrlist_original = False
		self._header_format_changed = True

	def __setattr__(self, varname, value):
		"""
		Set an attribute "varname" value via "a.varname=value".
		"""
		# TODO: remove
		if varname == "_header_format_changed":
			logger.debug("setting format changed: %r" % value)
		#logger.debug("setting attribute: %s: %s->%s" % (self.__class__, varname, value))
		if varname in self._hdr_fields:
		# track changes to header fields
			if not self._unpacked:
			# set original values before overwriting
				self._unpack()
			#logger.debug("setting field attribute: %s: %s->%s" % (self.__class__, varname, value))
			self._header_changed = True

			if not varname in self._hdr_fields_dyn_dict:
			# static header field
				object.__setattr__(self, varname, value)

				# check for activated/deactivated header
				# TODO: use dicts?
				if value is None and varname in self._hdr_fields_active:
					self._deactivate_hdr(varname)
				elif value is not None and not varname in self._hdr_fields_active:
					self._activate_hdr(varname)
			else:
			# TriggerList: avoid overwriting dynamic fields when using keyword constructor Class(key=val)
			# triggerlistObj = [ b"" | (KEY_X, VAL) | [(KEY_X, VAL), ...]] => clear current
			# list and add value.
				#logger.debug("got obj.triggerlist = [b''|[...]]: adding triggerlist values: %s=%s" % (varname,value))
				# this will trigger a lazy init
				header_val = getattr(self, varname)
				del header_val[:]

				if type(value) is list:
					#logger.debug("extending dynamic field")
					header_val.extend(value)
				else:
					#logger.debug("appending dynamic field")
					header_val.append(value)

			self._notify_changelistener()
		elif varname == "_body_bytes":
			#logger.debug("setting body bytes: %s" % value)
			object.__setattr__(self, varname, value)
			# track changes to raw data
			self._body_changed = True
			self._lazy_handler_data = None
			self._notify_changelistener()
		else:
			object.__setattr__(self, varname, value)

	def __getitem__(self, packet_type):
		"""
		Check every layer upwards (inclusive this layer) for the given Packet-Type
		and return the first matched instance or None if nothing was found.

		packet_type -- Packet-type to search for like Ethernet, IP, TCP etc.
		"""
		p_instance = self
		# set most top layer to be unpacked, __getattr__() could be called unpacking lazy data
		self._target_unpack_clz = packet_type

		while not type(p_instance) is packet_type:
			# this will auto-parse lazy handler data via _get_bodyhandler()
			p_instance = p_instance._get_bodyhandler()

			if p_instance is None:
				break

		#logger.debug("returning found packet-handler: %s->%s" % (type(self), type(p_instance)))
		return p_instance

	def __iter__(self):
		"""
		Iterate over every layer starting with this ending at last/highest one
		"""
		p_instance = self
		# assume string class never gets found
		self._target_unpack_clz = str.__class__

		while not p_instance is None:
			yield p_instance
			# this will auto-parse lazy handler data via _get_bodyhandler()
			p_instance = p_instance._get_bodyhandler()

			if p_instance is None:
				break

	def dissect_full(self):
		"""
		Recursive unpack ALL data inlcuding lazy header etc up to highest layer inlcuding danymic fields.
		"""
		for hdr in self._hdr_fields_dyn_dict:
			self.__getattribute__(hdr)._lazy_dissect()

		try:
			self._get_bodyhandler().dissect_full()
		except AttributeError:
			# no handler present
			pass

	def __add__(self, packet_to_add):
		"""
		Handle concatination of layers like "Ethernet + IP + TCP" and make them accessible
		via "ethernet.ip.tcp" (class names as lowercase). Every "A + B" operation will return A,
		setting B as the handler (of the deepest handler) of A.

		NOTE: changes to A, B... after creating a Packet like "A+B+C+..." will affect the new created Packet itself.
		Create a deep copy to avoid this behaviour.

		packet_to_add -- the packet to be added as new highest layer for this packet
		"""

		# get highest layer from this packet
		highest_layer = self
		# unpack all layer, assuming string class will be never found
		self._target_unpack_clz = str.__class__

		while highest_layer is not None:
			if highest_layer._bodytypename is not None:
				# this will dissect any lazy data
				highest_layer = highest_layer._get_bodyhandler()
			else:
				break

		highest_layer._set_bodyhandler(packet_to_add)

		return self

	def __repr__(self):
		"""Verbose represention of this packet as "key=value"."""
		# recalculate fields like checksums, lengths etc
		if self._header_changed or self._body_changed:
			#logger.debug("header/body changed: need to reparse")
			self.bin()

		# create key=value descriptions
		# this will lazy init dynamic fields
		l = ["%s=%r" % (k, getattr(self, k)) for k in self._hdr_fields_active]
		# no handler present
		if self._body_bytes is not None:
			l.append("bytes=%r" % self.body_bytes)
		else:
			# assume bodyhandler is set
			#l.append("handler=%s" % self.__getattribute__(self._bodytypename).__class__)
			l.append("handler=%s" % self._bodytypename)
		return "%s(%s)" % (self.__class__.__name__, ", ".join(l))

	#
	# Methods for creating properties for convenient access eg: mac (bytes) -> mac (str), ip (bytes) -> ip (str)
	# Names of property fields should be named like: [name_of_variable]_s
	#
	def _get_property_mac(var):
		"""Create a get/set-property for a MAC address as string-representation."""
		#logger.debug("--------------------- returning property")
		def getattrlocal(obj):
			logger.debug(">>>>>>>>>>>>>>>>> getting attribute for: %s/%r" % (var, obj.__class__))
			try:
				return mac_bytes_to_str(obj.__getattribute__(var))
			except Exception as e:
				try:
					return mac_bytes_to_str(obj.__getattr__(var))
				except Exception as ex:
					logger.debug("????? still no variable found?????")
					print(ex)

		return property(
				lambda obj: getattrlocal(obj),
				lambda obj, val: obj.__setattr__(var, mac_str_to_bytes(val))
		)

	def _get_property_ip4(var):
		"""Create a get/set-property for an IP4 address as string-representation."""
		return property(
				lambda self: ip4_bytes_to_str(self.__getattribute__(var)),
				lambda self, val: self.__setattr__(var, ip4_str_to_bytes(val))
		)

	def _init_header_body(self, buf):
		"""
		Set initial value for header and body.

		buf -- the buffer to be set
		"""
		# calling "self.hdr_len" will update format for dynamic fields
		self._header_cached = buf[:self.hdr_len]

		if not self._body_changed:
		# extending class didn't change body itself and didn't set body_bytes via keyword: set raw data
			# use object.__setattr__: avoid calling __setattr__ of Packet
			object.__setattr__(self, "_body_bytes", buf[self._hdr_fmt.size:])

		#logger.debug("header: %s, body: %s" % (self._hdr_fmt, self.body_bytes))
		# reset the changed-flags: original unpacked value = no changes
		self._reset_changed()

	def _unpack(self):
		"""
		Unpack/import a full layer using bytes in buf and set all headers
		and data accordingly. This will use the current value of _header_cached
		to set all field values. This will also set data if not allready set
		via dissect().
		NOTE: This is only called by the Packet class itself!
		"""
		logger.debug("format/fields/active/cached: /1 %s /2 %r /3 %r /4 %s" % (self._hdr_fmt.format,
												self._hdr_fields,
												self._hdr_fields_active,
												self._header_cached))

		#try:
		hdr_unpacked = self._hdr_fmt.unpack(self._header_cached)
		cnt = 0
		for name in self._hdr_fields_active:
			if self._hdr_fields[name] is not None:
			# skip TriggerLists
				#logger.debug("unpacking value: %s -> %s" % (name_bytes[0], name_bytes[1]))
				object.__setattr__(self, name, hdr_unpacked[cnt])
			cnt += 1
		#except Exception as ex:
		#	raise UnpackError("could not unpack, format/fields/active/cached: /1 %s /2 %r /3 %r /4 %s" % (self._hdr_fmt.format,
		#										self._hdr_fields,
		#										self._hdr_fields_active,
		#										self._header_cached))
		self._unpacked = True

	def reverse_address(self):
		"""
		Reverse source<->destination address of THIS packet. This is at minimum defined for: Ethernet, IP, TCP, UDP
		"""
		pass

	def reverse_all_address(self):
		"""
		Reverse source<->destination address of EVERY packet upwards including this one.
		"""
		current_hndl = self

		while current_hndl is not None:
			current_hndl.reverse_address()
			current_hndl = current_hndl._get_bodyhandler()

	def _parse_handler(self, hndl_type, buffer):
		"""
		Called by overwritten "_dissect()":
		Initiate the handler-parser using the given buffer and set it using _set_bodyhandler() later on (lazy
		init). This will use the calling class and given handler type to retrieve the resulting handler.
		On any error this will set raw bytes given for body data.

		hndl_type -- A value to place the handler in the handler-dict like
			dict[Class.__name__][hndl_type] (eg type-id, port-number)
		buffer -- The buffer to be used to create the handler
		"""
		if len(buffer) == 0:
			# no handler set by default, no bytes given -> data = b""
			#logger.debug("empty buffer given for _parse_handler()!")
			return

		try:
			if self._target_unpack_clz is None or self._target_unpack_clz is self.__class__:
			# set lazy handler data, __getattr__() will be called on access to handler
				clz = Packet._handler[self.__class__.__name__][hndl_type]
				clz_name = clz.__name__.lower()
				#logger.debug("setting handler name: %s -> %s" % (self.__class__.__name__, clz_name))
				self._lazy_handler_data = [clz_name, clz, buffer]
				# set name although we don't set a handler (needed for direction() et al)
				self._bodytypename = clz_name
				object.__setattr__(self, "_body_bytes", None)
				# avoid setting body_bytes by _unpack()
				self._body_changed = True
			else:
			# continue parsing layers, happens on "__getitem__()": avoid unneeded lazy-data creation
			# if specific class must be found
				#logger.debug("--------> direct unpacking in: %s" % (self.__class__.__name__))
				type_instance = Packet._handler[self.__class__.__name__][hndl_type](buffer, self)
				self._set_bodyhandler(type_instance)
		except KeyError:
			logger.info("unknown type for %s: %d, feel free to implement" % (self.__class__, hndl_type))
			self.body_bytes = buffer
			# TODO: remove
			#raise Exception("1a>>>>>>>>>>> (key unknown)")
		except Exception as e:
			logger.exception("can't set handler data, type/lazy: %s/%s:" %
				(str(hndl_type), self._target_unpack_clz is None or self._target_unpack_clz is self.__class__))
			# set raw bytes as data (eg handler class not found)
			self.body_bytes = buffer
			# TODO: remove this to ignore parse errors (set raw bytes after all)
			#raise Exception("1b>>>>>>>>>>> %r" % e)

	def direction(self, packet2):
		"""
		Every layer can check the direction to the given "packet2" layer.
		This continues upwards until no body handler can be found anymore.
		The extending class should overwrite _direction() to implement an individual check.

		packet2 -- Packet to be compared with this Packet
		return -- Possible Bitwise OR-concatination of [DIR_SAME | DIR_REV | DIR_UNKNOWN], check using "&" operator
		"""
		try:
			dir_ext = self._direction(next)
		except AttributeError:
			# attribute not set when comparing: no direction known
			dir_ext = Packet.DIR_UNKNOWN

		try:
			# check upper layers and combine current result
			#logger.debug("direction? checking next layer")
			return dir_ext & self._get_bodyhandler().direction(next._get_bodyhandler())
		except AttributeError:
			# one of both _bodytypename was None
			# Example: TCP ACK (last step of handshake, no payload) <-> TCP ACK + Telnet
			return dir_ext

	def is_direction(self, packet2, direction):
		"""
		Same as "direction()" but using explicit direction to be checked.
		As direction can be DIR_SAME and DIR_REV at the same time, this call
		is more clearly.

		packet2 -- packet to be compared to this packet
		direction -- check for this direction (DIR_...)
		return -- True if direction is found in this packet, False otherwise.
		"""
		return self.direction(packet2) & direction == direction

	def _update_fmt(self):
		"""
		Update header format string and length using current fields.
		This will also update the active headers.
		NOTE: should only called if format has changed eg on changes in TriggerList etc.
		"""
		logger.debug(">>> updating format in %r" % self.__class__.__name__)
		# byte-order is set via first character
		hdr_fmt_tmp = [self._hdr_fmt_order]
		#logger.debug("active fields: %r" % self._hdr_fields_active)

		# we need to preserve the order of formats / fields
		for name in self._hdr_fields_active:
			#logger.debug("format update with field/format: %s/%s" % (name, self._hdr_fields[name]))
			# two options:
			# - value bytes					-> add given format
			# - value TriggerList	(found via format None) -> call bin()
			if self._hdr_fields[name] is not None:				# bytes/int/float
				hdr_fmt_tmp.append(self._hdr_fields[name])
			else:								# assume TriggerList
				try:
					val = object.__getattribute__(self, name).bin()
					hdr_fmt_tmp.append("%ds" % len(val))
				except AttributeError:
					hdr_fmt_tmp.append("0s")
					# dynamic field not yet initiated = no value parsed = not needed: skip
					continue

		#logger.debug("format update class/hdr: %s/%r" % (self.__class__.__name__, self._hdr_fields))
		self._hdr_fmt = struct.Struct("".join(hdr_fmt_tmp))
		self._header_format_changed = False

	def bin(self, update_auto_fields=True):
		"""
		Return this header and body (including all upper layers) as byte string
		and reset changed-status.
		"""
		#logger.debug("bin for: %s" % self.__class__.__name__)
		# preserve change status until we got all data of all sub-handlers
		# needed for eg IP (changed) -> TCP (check changed for sum).
		if self._lazy_handler_data is not None:
			# no need to parse, just take lazy handler data bytes
			body_tmp = self._lazy_handler_data[2]
		elif self._bodytypename is not None:
			# handler allready parsed
			body_tmp = self._get_bodyhandler().bin(update_auto_fields=update_auto_fields)
		else:
			# raw bytes
			body_tmp = self._body_bytes
		header_tmp = self._pack_header()
		# now every layer got informed about our status, reset it
		self._reset_changed()
		return header_tmp + body_tmp

	def _pack_header(self):
		"""
		Return header as byte string.
		"""
		logger.debug("packing header in %r" % self.__class__.__name__)
		if self._header_format_changed:
		# format changed, if static field was acticated/deactivated: _unpack() was already done
			self._update_fmt()

			if not self._unpacked:
			# this happens if only dynamic fields gets changed
				self._unpack()
		elif not self._header_changed:
		# return cached data if nothing changed
			#logger.warning("returning cached header (hdr changed=%s): %s->%s" %\
			#	(self._header_changed, self.__class__.__name__, self._header_cached))
			return self._header_cached

		hdr_bytes = []

		for name in self._hdr_fields_active:
			# two options:
			# - value bytes					-> add given bytes
			# - value TriggerList	(found via format None) -> call bin()
			#logger.debug("packing header with field/format: %s/%s" % (name, self._hdr_fields[name]))
			if self._hdr_fields[name] is not None:			# bytes/int/float
				val = self.__getattribute__(name)
				hdr_bytes.append(val)
			else:							# assume TriggerList
				try:
					val = object.__getattribute__(self, name)
				except AttributeError:
					hdr_bytes.append(b"")
					# dynamic field not yet initiated: skip
					continue

				hdr_bytes.append(val.bin())
		#logger.debug("header bytes for %s: %s = %s" % (self.__class__.__name__, self._hdr_fmt.format, hdr_bytes))
		self._header_cached = self._hdr_fmt.pack(*hdr_bytes)
		#logger.debug("cached header: %s" % self._header_cached)

		return self._header_cached

	# readonly access to header
	header_bytes = property(_pack_header)

	def _changed(self):
		"""
		Check if this or any upper layer changed in header or body.
		"""
		changed = False
		p_instance = self

		while p_instance is not None:
			if p_instance._header_changed or p_instance._body_changed:
				changed = True
				break
			elif p_instance._lazy_handler_data is None:
			# one layer up, stop if next layer is not yet initiated which means: no change
				p_instance = p_instance._get_bodyhandler()
			else:
			# nothing changed upwards: lazy handler data still present/nothing got parsed
				break
		return changed

	def _reset_changed(self):
		"""Set the header/body changed-flag to False. This won't clear caches."""
		self._header_changed = False
		self._body_changed = False

	def _add_change_listener(self, listener_cb):
		"""
		Add a new callback to be called on changes to header or body.
		The only argument is this packet itself.

		listener_cb -- the change listener to be added as callback-function
		"""
		if len(self._changelistener) == 0:
			# copy list (shared)
			self._changelistener = []
		self._changelistener.append(listener_cb)

	def _remove_change_listener(self, listener_cb, remove_all=False):
		"""
		Remove callback from the list of listeners.

		listener_cb -- the change listener to be removed
		remove_all -- remove all listener at once
		"""
		#logger.debug("remove_change_listener, present: %d /// %s /// %s" % (len(self._changelistener),
		#	self._changelistener, listener_cb))
		if not remove_all:
			self._changelistener.remove(listener_cb)
		else:
			del self._changelistener[:]

	def _notify_changelistener(self):
		"""
		Notify listener about changes in header or body using signature callback(self).
		This is primarily meant for triggerlist to react
		on changes in packets like Triggerlist[packet1, packet2, ...].
		"""
		for listener_cb in self._changelistener:
			try:
				listener_cb(self)
			except Exception as e:
				logger.exception("error when informing listener: %r" % e)

	def __load_handler(clz, clz_add, handler):
		"""
		Load Packet handler using a shared dictionary.

		clz_add -- class for which handler has to be added
		handler -- dict of handlers to be set like { id : class }, id can be a tuple of values
		"""
		clz_name = clz_add.__name__

		if clz_name in Packet._handler:
			logger.debug("handler already loaded: %r" % clz_name)
			return

		logger.debug("adding classes as handler: [%r] = %r" % (clz_add, handler))

		Packet._handler[clz_name] = {}

		for id, packetclass in handler.items():
			# pypacker.Packet.load_handler(IP, { ID : class } )
			if type(id) is not tuple:
				Packet._handler[clz_name][id] = packetclass
			else:
			# pypacker.Packet.load_handler(IP, { (ID1, ID2, ...) : class } )
				for id_x in id:
					Packet._handler[clz_name][id_x] = packetclass

	load_handler = classmethod(__load_handler)


#
# utility functions
#
def mac_str_to_bytes(mac_str):
	"""Convert mac address AA:BB:CC:DD:EE:FF to byte representation."""
	return b"".join([bytes.fromhex(x) for x in mac_str.split(":")])


def mac_bytes_to_str(mac_bytes):
	"""Convert mac address from byte representation to AA:BB:CC:DD:EE:FF."""
	return "%02X:%02X:%02X:%02X:%02X:%02X" % unpack("BBBBBB", mac_bytes)


def get_rnd_mac():
	"""Create random mac address as bytestring"""
	return pack("BBBBBB", randint(0, 255), randint(0, 255), randint(0, 255),
		randint(0, 255), randint(0, 255), randint(0, 255))


def ip4_str_to_bytes(ip_str):
	"""Convert ip address 127.0.0.1 to byte representation."""
	ips = [int(x) for x in ip_str.split(".")]
	return pack("BBBB", ips[0], ips[1], ips[2], ips[3])


def ip4_bytes_to_str(ip_bytes):
	"""Convert ip address from byte representation to 127.0.0.1."""
	return "%d.%d.%d.%d" % unpack("BBBB", ip_bytes)


def get_rnd_ipv4():
	"""Create random ipv4 adress as bytestring"""
	return pack("BBBB", randint(0, 255), randint(0, 255), randint(0, 255), randint(0, 255))


def byte2hex(buf):
	"""Convert a bytestring to a hex-represenation:
	b'1234' -> '\x31\x32\x33\x34'"""
	return "\\x" + "\\x".join(["%02X" % x for x in buf])


import re

PROG_VISIBLE_CHARS	= re.compile(b"[^\x20-\x7e]")


def hexdump(buf, length=16):
	"""Return a hexdump output string for the given bytestring."""
	bytepos = 0
	res = []
	buflen = len(buf)

	while bytepos < buflen:
		line = buf[bytepos: bytepos + length]
		hexa = " ".join(["%02x" % x for x in line])
		#line = line.translate(__vis_filter)
		line = re.sub(PROG_VISIBLE_CHARS, b".", line)
		res.append("  %04d:      %-*s %s" % (bytepos, length * 3, hexa, line))
		bytepos += length
	return "\n".join(res)
