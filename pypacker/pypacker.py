"""
Simple packet creation and parsing logic.
"""

import copy
from collections import OrderedDict
import logging
import random
import re
import struct

logging.basicConfig(format="%(levelname)s (%(funcName)s): %(message)s")
logger = logging.getLogger("pypacker")
logger.setLevel(logging.WARNING)
# logger.setLevel(logging.INFO)
# logger.setLevel(logging.DEBUG)

# avoid unneeded references for performance reasons
pack = struct.pack
unpack = struct.unpack
calcsize = struct.calcsize
randint = random.randint
deepcopy = copy.deepcopy
Struct = struct.Struct

PROG_VISIBLE_CHARS	= re.compile(b"[^\x20-\x7e]")
HEADER_TYPES_SIMPLE	= set([int, bytes])


class UnpackError(Exception):
	pass


class MetaPacket(type):
	"""
	This Metaclass is a more efficient way of setting attributes than using __init__.
	This is done by reading name, format and default value out of __hdr__ in every subclass.
	This configuration is set one time when loading the module (not at instatiation).
	Attributes can be normally accessed using "obj.field" notation.
	General note: Callflaw is: __new__ (loading module) -> __init__ (initiate class)

	CAUTION:
	- List et al are _SHARED_ among all instantiated classes! A copy is needed on changes to them
	- New protocols: don't use header fields having same name as methods in Packet class
	"""

	def __new__(cls, clsname, clsbases, clsdict):
		# Using properties will slow down access to header fields but it's needed:
		# This way we get informed about get-access more efficiently than using
		# __getattribute__ (slow access for header fields vs. slow access
		# for ALL class fields).
		def get_setter(varname, is_field_type_simple=True, is_field_static=True):
			"""
			varname -- name of the variable to set the property for
			is_field_type_simple -- get property for simple static or dynamic type if True, else TriggerList
			is_field_static -- if is_field_type_simple is True: get static type (int, fixed size bytes, ...),
				else dynamic (format "xs") which can change in format (eg DNS names)

			return -- set-property for simple types or triggerlist
			"""
			varname_shadowed = "_%s" % varname

			def setfield_simple(obj, value):
				"""
				Unpack field ondemand
				"""
				if obj._unpacked is not None and not obj._unpacked:
					# obj._unpacked = None means: dissect not yet finished
					obj._unpack()
				if value is None and obj.__getattribute__(varname_shadowed + "_active"):
					object.__setattr__(obj, varname_shadowed + "_active", False)
					obj._header_format_changed = True
					# logger.debug("deactivating field: %s" % varname_shadowed)
				elif value is not None and not obj.__getattribute__(varname_shadowed + "_active"):
					object.__setattr__(obj, varname_shadowed + "_active", True)
					obj._header_format_changed = True
					# logger.debug("activating field: %s" % varname_shadowed)
				if not is_field_static and value is not None:
					# simple dynamic field
					format_new = "%ds" % len(value)
					# logger.debug(">>> changing format for dynamic field: %r / %s / %s" % (obj.__class__, varname_shadowed, format_new))
					object.__setattr__(obj, varname_shadowed + "_format", format_new)
					obj._header_format_changed = True

				object.__setattr__(obj, varname_shadowed, value)
				obj._header_changed = True
				obj._notify_changelistener()

			def setfield_triggerlist(obj, value):
				"""
				Clear list and add value as only value.

				value -- Packet, bytes (single or as list)
				"""
				tl = obj.__getattribute__(varname_shadowed)

				if type(tl) is list:
					# we need to create the original TriggerList in order to unpack correctly
					# _triggerlistName = [b"bytes", callback] or
					# _triggerlistName = [b"", callback] (default initiation)
					# logger.debug(">>> initiating TriggerList")
					tl = obj._header_fields_dyn_dict[varname_shadowed](obj, dissect_callback=tl[1], buffer=tl[0])
					object.__setattr__(obj, varname_shadowed, tl)
				# this will trigger unpacking

				del tl[:]

				# TriggerList: avoid overwriting dynamic fields eg when using keyword constructor Class(key=val)
				if type(value) is list:
					tl.extend(value)
				else:
					tl.append(value)
				obj._header_changed = True
				obj._notify_changelistener()

			if is_field_type_simple:
				return setfield_simple
			else:
				return setfield_triggerlist

		def get_getter(varname, is_field_type_simple=True):
			"""
			varname -- name of the variable to set the property for
			is_field_type_simple -- get property for simple static or dynamic type if True, else TriggerList
			return -- get-property for simple type or triggerlist
			"""
			varname_shadowed = "_%s" % varname

			def getfield_simple(obj):
				"""
				Unpack field ondemand
				"""
				# logger.debug("getting value for simple field: %s" % varname_shadowed)
				if obj._unpacked is not None and not obj._unpacked:
					obj._unpack()
				# logger.debug("now returning value")
				return obj.__getattribute__(varname_shadowed)

			def getfield_triggerlist(obj):
				tl = obj.__getattribute__(varname_shadowed)
				# logger.debug(">>> getting Triggerlist: %r" % tl)

				if type(tl) is list:
					# _triggerlistName = [b"bytes", callback] or
					# _triggerlistName = [b"", callback] (default initiation)
					tl = obj._header_fields_dyn_dict[varname_shadowed](obj, dissect_callback=tl[1], buffer=tl[0])
					object.__setattr__(obj, varname_shadowed, tl)

				return tl

			if is_field_type_simple:
				return getfield_simple
			else:
				return getfield_triggerlist

		t = type.__new__(cls, clsname, clsbases, clsdict)
		# dictionary of TriggerLists: name -> TriggerListClass
		t._header_fields_dyn_dict = {}
		# get header-infos from subclass: [("name", "format", value), ...]
		hdrs = getattr(t, "__hdr__", None)
		# cache header for performance reasons, will be set to bytes later on
		t._header_cached = []
		# all header names
		t._header_field_names = []
		t._header_format_order = getattr(t, "__byte_order__", ">")
		# all header formats including byte order
		header_fmt = [t._header_format_order]

		if hdrs is not None:
			# every header var will get two additional values set:
			# var_active = indicates if header is active
			# var_format = indicates the header format
			# logger.debug("loading meta for: %s, st: %s" % (clsname, st))
			for hdr in hdrs:
				shadowed_name = "_%s" % hdr[0]
				t._header_field_names.append(shadowed_name)
				setattr(t, shadowed_name + "_active", True)

				# remember header format
				# t._header_field_infos[shadowed_name] = [True, hdr[1]]
				is_field_type_simple = False
				is_field_static = True

				if hdr[1] is not None or (hdr[2] is None or type(hdr[2]) == bytes):
					# simple static or simple dynamic type
					# we got one of: ("name", format, ???) = static or
					# ("name", None, ???) = dynamic
					# -> Format given = static, Format None = dynamic
					is_field_type_simple = True

					if hdr[1] is None:
						# assume simple dynamic field
						is_field_static = False

				setattr(t, shadowed_name + "_format", hdr[1])

				if is_field_type_simple:
					fmt = hdr[1]

					if hdr[2] is not None:
						# value given: field is active
						if fmt is None:
							# dynamic field
							fmt = "%ds" % len(hdr[2])
							setattr(t, shadowed_name + "_format", fmt)
						header_fmt.append(fmt)
						t._header_cached.append(hdr[2])
						"""
						if fmt is not None:
							header_fmt.append(fmt)
							t._header_cached.append(hdr[2])
						"""
						# logger.debug("--------> field is active: %r" % hdr[0])
					else:
						setattr(t, shadowed_name + "_active", False)

					# only simple fields can get deactivated
					setattr(t, shadowed_name + "_active", True if hdr[2] is not None else False)

					# set initial value via shadowed variable: _varname <- varname [optional in subclass: <- varname_s]
					# setting/getting value is done via properties.
					# logger.debug("init simple type: %s=%r" % (shadowed_name, hdr[2]))
					setattr(t, shadowed_name, hdr[2])
					setattr(t, hdr[0], property(
							get_getter(hdr[0], is_field_type_simple=True),
							get_setter(hdr[0], is_field_type_simple=True, is_field_static=is_field_static)
						)
							)
				else:
					# assume TriggerList
					# Triggerlists don't have initial default values (and can't get deactivated) TODO?
					t._header_fields_dyn_dict[shadowed_name] = hdr[2]
					# initial value of TiggerLists is: values to init empty list
					setattr(t, shadowed_name, [b"", None])
					setattr(t, hdr[0], property(
							get_getter(hdr[0], is_field_type_simple=False),
							get_setter(hdr[0], is_field_type_simple=False, is_field_static=is_field_static)
								)
					)
					# format and value needed for correct length in _unpack()
					header_fmt.append("0s")
					t._header_cached.append(b"")
			# logger.debug("<<<<")

		# logger.debug(">>> translated header names: %s/%r" % (clsname, t._header_name_translate))
		# current format as string
		t._header_format = struct.Struct("".join(header_fmt))
		# header size can be assigened by __init__() directly or given by _header_format.size
		t._header_len = t._header_format.size
		# track changes to header format (changes to simple dynamic fields or TriggerList)
		t._header_format_changed = False
		# cached header, return this if nothing changed
		t._header_cached = t._header_format.pack(*t._header_cached)
		# logger.debug("formatstring is: %s" % header_fmt)
		# body as raw byte string (None if handler is present)
		t._body_bytes = b""
		# name of the attribute which holds the object representing the body aka the body handler
		t._bodytypename = None
		# next lower layer: a = b + c -> b will be lower layer for c
		t._lower_layer = None
		# track changes to header values: This is needed for layers like TCP for
		# checksum-recalculation. Set to "True" on changes to header/body values, set to False on "bin()"
		# track changes to header values
		t._header_changed = False
		# track changes to body value like [None | bytes | body-handler] -> [None | bytes | body-handler]
		t._body_changed = False
		# objects which get notified on changes on header or body (shared)
		# TODO: use sets here
		t._changelistener = []
		# lazy handler data: [name, class, bytes]
		t._lazy_handler_data = None
		# indicates the most top layer until which should be unpacked (vs. lazy dissecting = just next upper layer)
		t._target_unpack_clz = None
		# inicates if static header values got already unpacked
		# [True|False] = Status after dissect, None = pre-dissect (not unpacked)
		t._unpacked = None

		return t


class Packet(object, metaclass=MetaPacket):
	"""
	Base packet class, with metaclass magic to generate members from self.__hdr__ field.
	This class can be instatiated via:

		Packet(byte_string)
		Packet(key1=val1, key2=val2, ...)

	Every packet got a header and a body. Body-data can be raw byte string OR a packet itself
	(the body handler) which itself stores a packet etc. This continues until a packet only
	contains raw bytes (highest layer). The following schema illustrates the Packet-structure:

	Packet structure
	================

	[Packet:
	headerfield_1
	headerfield_2
	...
	headerfield_N
	[Body -> Packet:
		headerfield_1
		...
		headerfield_N
		[Body: -> Packet:
			headerfields
			...
			[Body: b"some_bytes"]
	]]]

	A header definition like __hdr__ = (("name", "12s", b"defaultvalue"),) will define a header field
	having the name "name", format "12s" and default value b"defaultvalue" as bytestring. Fields will
	be added in order of definition. The static variable __byte_order__ can be set to override the
	default value '>'. Extending classes should overwrite the "_dissect"-method in order to dissect given data.

	Requirements
	============

	- Auto-decoding of headers via given format-patterns (defined via __hdr__)
	- Auto-decoding of body-handlers (like IP -> parse IP-data -> add TCP-handler to IP -> parse TCP-data..)
	- Access of higher layers via layer1.layer2.layerX or "layer1[layerX]" notation
	- There are three types of headers:
	1) Simple constant fields (constant format)
		Format for __hdr__: ("name", "format", value)

	2) Simple dynamic fields (byte string which changes in length)
		Format for __hdr__: ("name", None, b"bytestring")
		Such types MUST get initiated in _dissect() because there is no way in guessing
		the correct format when unpacking values!

	3) TriggerList (List containing Packets, bytes or whatever implemented)
		Format for __hdr__: ("name", None, TriggerList)

	- Convenient access for standard types (MAC, IP address) using string-representations
		This is done by appending "_s" to the attributename:
		ip.src_s = "127.0.0.1"
		ip_src_bytes = ip.src

		Implementation info:
		Convenient access should be set via varname_s = pypacker.Packet.get_property_XXX("varname")
		Concatination via "layer1 + layer2 + layerX"
	- Header-values with length < 1 Byte should be set by using properties
	- Activate/deactivate non-TriggerList header fields by setting values (None=deactive, value=active)
	- Checksums (static auto fields in general) are auto-recalculated when calling bin(update_auto_fields=True) (default)
	- Ability to check direction to other Packets via "[is_]direction()"
	- Access to next lower/upper layer
	- No correction of given raw packet-data eg checksums when creating a packet from it
		If the packet can't be parsed without correct data -> raise exception.
		The internal state will only be updated on changes to headers or data later on
	- General rule: less changes to headers/body-data = more performance

	Call-flows
	==========

		pypacker(bytes)
			-> _dissect(): has to be overwritten, get to know/verify the real header-structure
				-> (optional): call _init_handler() initiating a handler representing an upper-layer
				-> (optional): call _init_triggerlist(name, b"bytes", dissect_callback) to initiate a TriggerList field
			-> (optional) on access to simple headers: _unpack() sets all header values
			-> (optional) on access to TriggerList headers: lazy parsing gets triggered
			-> (optional) on access to body handler next upper layer gets initiated

		pypacker(keyword1=value, ...)
			-> (optional) set headers

		pypacker()
			-> sets standard values for simple headers

	"""

	"""Dict for saving body handler globaly: { class_name : {id : handler_class} }"""
	_handler = {}
	"""Constants for Packet-directions"""
	DIR_SAME	= 1
	DIR_REV		= 2
	DIR_UNKNOWN	= 3

	def __init__(self, *args, **kwargs):
		"""
		Packet constructors:

		Packet(bytestring, target_class)
			Note: target_class is only meant for internal usage
		Packet(keyword1=val1, keyword2=val2, ...)

		bytestring -- packet bytes to build packet from, nonempty values are NOT allowed
		target_class -- For internal usage only: unpack until this class (meant eg for __getitem__(...))
		keywords -- keyword arguments correspond to header fields to be set
		"""

		if args:
			if len(args) > 1:
				# assume packet, target class given until which we unpack
				self._target_unpack_clz = args[1]._target_unpack_clz

			try:
				# logger.debug("dissecting: %r" % self.__class__.__name__)
				header_len = self._dissect(args[0])
				# logger.debug("init header (+ body bytes): %r" % self.__class__.__name__)

				self._header_len = header_len
				self._header_cached = args[0][:header_len]

				if not self._body_changed:
					# _dissect(...) didn't change body: set raw data.
					self._body_bytes = args[0][header_len:]

				# reset the changed-flags: original unpacked value = no changes
			except Exception as e:
				# TODO: remove to continue parsing
				# raise Exception("%r" % e)
				logger.exception("could not dissect or unpack: %r" % e)
			self._reset_changed()
			self._unpacked = False
		elif len(kwargs) > 0:
			# overwrite default parameters
			# logger.debug("new packet with keyword args (%s)" % self.__class__.__name__)
			# _unpack is set to None: nothing to unpack until now

			for k, v in kwargs.items():
				# logger.debug("setting: %s=%s" % (k, v))
				setattr(self, k, v)
			# no reset: directly assigned = changed
			# keyword args means: allready unpacked (nothing to unpack)
			self._unpacked = True
		else:
			self._unpacked = True

	def _dissect(self, buf):
		"""
		Dissect packet bytes by doing some (or nothing) of the following:
		- call self._init_triggerlist(...) to initiate TriggerLists
		- call self._init_handler(...) to initiate upper layer handler
		- activate/deactivate non-TriggerList fields by setting values/None to fields

		buf -- bytestring to be dissected
		return -- header length
		"""
		# _dissect(...) was not overwritten: no changes to header, return original header length
		return self._header_len

	def __len__(self):
		"""Return total length (= header + all upper layer data) in bytes."""

		if self._body_bytes is not None:
			# logger.debug("returning length from raw bytes in %s" % self.__class__.__name__)
			return self.header_len + len(self._body_bytes)
		else:
			try:
				# lazy data present: avoid unneeded parsing
				# logger.debug("returning length from cached lazy handler in %s" % self.__class__.__name__)
				return self.header_len + len(self._lazy_handler_data[2])
			except TypeError:
				# logger.debug("returning length from present handler in %s, handler is: %s"\
				# % (self.__class__.__name__, self._bodytypename))
				return self.header_len + len(self.__getattribute__(self._bodytypename))

	#
	# public access to header length: keep it uptodate
	#
	def _get_header_len(self):
		if self._header_changed and self._header_format_changed:
			# header has NOT changed if __init__ just finished -> avoid unneeded re-formating
			# update format to get the real length
			self._update_header_format()
		return self._header_len

	# update format if needed and return actual header size
	header_len = property(_get_header_len)

	def _get_bodybytes(self):
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
			return hndl._pack_header() + hndl._get_bodybytes()
			# return raw bytes
		else:
			return self._body_bytes

	def _set_body_bytes(self, value):
		"""
		Set body bytes to value (bytestring). This will reset any handler.

		value -- a byte string (do NOT set to None)
		"""
		if self._bodytypename is not None:
			# reset all handler data
			self._set_bodyhandler(None)
		# logger.debug("setting new raw data: %s" % value)
		self._body_bytes = value
		self._body_changed = True
		self._lazy_handler_data = None
		self._notify_changelistener()

	# return body data as raw bytes (deprecated)
	data = property(_get_bodybytes, _set_body_bytes)
	# get and set bytes for body
	body_bytes = property(_get_bodybytes, _set_body_bytes)

	def _get_bodyhandler(self):
		"""
		return -- handler object or None if not present.
		"""
		if self._lazy_handler_data is not None:
			# parse lazy handler data on the next layer
			return self.__getattr__(self._lazy_handler_data[0])
		elif self._bodytypename is not None:
			# body handler already parsed
			return self.__getattribute__(self._bodytypename)
		else:
			# nope, chuck testa
			# logger.debug("returning None")
			return None

	def _set_bodyhandler(self, hndl):
		"""
		Set body handler for this packet and make it accessible via layername.addedtype
		like ethernet.ip. This will take the lowercase classname of the given handler eg "ip"
		and make the handler accessible by this name. If handler is None any handler will
		be reset and data will be set to an empty byte string.

		hndl -- the handler to be set (None or a Packet instance)
		"""
		if self._bodytypename is not None and self._lazy_handler_data is None:
			# clear old linked data if body handler is already parsed
			# logger.debug("removing old data handler connections")
			current_handl = self.__getattribute__(self._bodytypename)
			current_handl._lower_layer = None

		if hndl is None:
			# switch (handler=obj, body_bytes=None) to (handler=None, body_bytes=b'')
			self._bodytypename = None
			# avoid (body_bytes=None, handler=None)
			self._body_bytes = b""
		else:
			# set a new body handler
			# associate ip, arp etc with handler-instance to call "ether.ip", "ip.tcp" etc
			self._bodytypename = hndl.__class__.__name__.lower()
			self._body_bytes = None
			# upper layer (self) to lower layer (hndl) eg TCP -access to-> IP
			hndl._lower_layer = self
			setattr(self, self._bodytypename, hndl)
			# logger.debug("finished setting handler: %s" % self._bodytypename)
		self._body_changed = True
		self._lazy_handler_data = None
		self._notify_changelistener()

	# get/set body handler or None. Note: this will force lazy dissecting when reading
	body_handler = property(_get_bodyhandler, _set_bodyhandler)
	# get/set body handler or None. Note: this will force lazy dissecting when reading
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
		lazy handler data set which must get initiated now.
		"""
		try:
			# This should be the best way lazy initiating body handler as body handler names/types
			# are not known a priori.
			if self._lazy_handler_data[0] == varname:
				# lazy handler data was set, parse lazy handler data now!
				# logger.debug("lazy dissecting handler: %s" % varname)
				handler_data = self._lazy_handler_data

				try:
					# instantiate handler class using lazy data buffer
					# See _init_handler() for 2nd place where handler instantation takes place
					# logger.debug("lazy parsing using: %r" % handler_data)
					type_instance = handler_data[1](handler_data[2], self)

					self._set_bodyhandler(type_instance)
					self._lazy_handler_data = None
					# this was a lazy init: same as direct dissecting -> no body change
					self._body_changed = False

					return type_instance
				except:
					# error on lazy dissecting: set raw bytes
					# logger.debug("Exception on dissecting lazy handler")
					logger.exception("could not lazy-parse handler: %r, there could be 2 reasons for this: " +
						"1) packet was malformed 2) dissecting-code is buggy" % handler_data)
					self._bodytypename = None
					self._body_bytes = handler_data[2]
					self._lazy_handler_data = None

					# TODO: remove this to ignore parse errors (set raw bytes after all)
					# raise Exception("2>>>>>>>>>>> %r (lazy dissecting)" % e)
					return None
		# logger.debug("searching for dynamic field: %s/%r" % (varname,self._header_fields_dyn_dict))
		except TypeError:
			# logger.warning("unable to find: %s" % varname)
			pass

		# nope not found...
		raise AttributeError("Can't find Attribute %s in %r, body type: %s" % (varname, self.__class__, self._bodytypename))

	def __getitem__(self, packet_type):
		"""
		Check every layer upwards (inclusive this layer) for the given Packet class
		and return the first matched instance or None if nothing was found.

		packet_type -- Packet class to search for like Ethernet, IP, TCP etc.
		return -- first finding of packet_type or None if nothing was found
		"""
		p_instance = self
		# set most top layer to be unpacked, __getattr__() could be called unpacking lazy data
		self._target_unpack_clz = packet_type

		while not type(p_instance) is packet_type:
			# this will auto-parse lazy handler data via _get_bodyhandler()
			p_instance = p_instance._get_bodyhandler()

			if p_instance is None:
				break

		# logger.debug("returning found packet-handler: %s->%s" % (type(self), type(p_instance)))
		return p_instance

	def __iter__(self):
		"""
		Iterate over every layer starting with this ending at last/highest one
		"""
		p_instance = self._get_bodyhandler()
		# assume string class never gets found
		self._target_unpack_clz = str.__class__

		while p_instance is not None:
			yield p_instance
			# this will auto-parse lazy handler data via _get_bodyhandler()
			p_instance = p_instance._get_bodyhandler()

			if p_instance is None:
				break

	def dissect_full(self):
		"""
		Recursive unpack ALL data inlcuding lazy header etc up to highest layer inlcuding danymic fields.
		"""
		for name in self._header_field_names:
			self.__getattribute__(name)

		try:
			self._get_bodyhandler().dissect_full()
		except AttributeError:
			# no handler present
			pass

	def __add__(self, packet_to_add):
		"""
		Handle concatination of layers like "Ethernet + IP + TCP" and make them accessible
		via "ethernet.ip.tcp" (class names as lowercase). Every "A + B" operation will return A
		after setting B as the handler (of the deepest handler) of A.

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

	def _summarize(self, verbose=False):
		"""
		verbose -- If False just include this layer, otherweise include all up to highest layer
		"""
		# recalculate fields like checksums, lengths etc
		if self._header_changed or self._body_changed:
			# logger.debug("header/body changed: need to reparse")
			self.bin()
		if not self._unpacked:
			self._unpack()

		# create key=value descriptions
		# show all header even deactivated ones
		l = ["%s=%r" % (name[1:], getattr(self, name[1:])) for name in self._header_field_names]
		if self.body_bytes is not None:
			# no bodyhandler present
			l.append("bytes=%r" % self.body_bytes)
		else:
			# assume bodyhandler is set
			l.append("handler=%s" % self._bodytypename)
		layer_sums = ["%s(%s)" % (self.__class__.__name__, ", ".join(l))]

		if verbose:
			next_upper_layer = self._get_bodyhandler()
			while next_upper_layer is not None:
				layer_sums.append("%r" % next_upper_layer)
				next_upper_layer = next_upper_layer._get_bodyhandler()
			layer_sums.reverse()

		return "\n".join(layer_sums)

	def __str__(self):
		return self._summarize()

	def __repr__(self):
		return self._summarize(verbose=True)

	def _unpack(self):
		"""
		Unpack a full layer (set field values) unpacked (extracted) from cached header bytes.
		This will use the current value of _header_cached to set all field values.
		NOTE:
		- This is only called by the Packet class itself
		- This is called prior to changing ANY header values
		"""
		# Needed to set here (and not at the end) to avoid recursive calls
		self._unpacked = True
		# logger.debug("%r" % self._header_field_names)
		# we need the whole format when:
		# format changed or some TriggestLists are non-empty (not yet dissected)
		if self._header_format_changed:
			self._update_header_format()
		self_setattr = self.__setattr__
		self_getattr = self.__getattribute__

		"""
		logger.debug(">=================\nunpacking 1: %r, %r,\n%s,\n(format via xxx_format) %r,\n%r,\n%s\nformat.size %d\ncached size: %d\n=====================<" %
			(self.__class__,
			self._header_field_names,
			self._header_format.format,
			[self_getattr(name + "_format") for name in self._header_field_names],
			[self_getattr(name + "_active") for name in self._header_field_names],
			self._header_cached,
			self._header_format.size,
			len(self._header_cached)))
		"""

		# logger.debug([self_getattr(name) for name in self._header_field_names])

		header_unpacked = self._header_format.unpack(self._header_cached)
		# logger.debug("unpacking via format: %r -> %r" % (self._header_format.format, header_unpacked))
		cnt = 0
		"""
		logger.debug("unpacking 2: %r, %r -> %r,\n%r,\n %r\n" % (self.__class__, header_unpacked, self._header_field_names,
			[self_getattr(name + "_format") for name in self._header_field_names],
			[self_getattr(name + "_active") for name in self._header_field_names]))
		"""
		for name in self._header_field_names:
			# only set values if active simple field
			if self_getattr(name + "_format") is not None and self_getattr(name + "_active"):
				# logger.debug("unpacking value: %s -> %s" % (name_bytes[0], name_bytes[1]))
				self_setattr(name, header_unpacked[cnt])
				cnt += 1

	def reverse_address(self):
		"""
		Reverse source <-> destination address of THIS packet. This is at minimum defined for: Ethernet, IP, TCP, UDP
		"""
		pass

	def reverse_all_address(self):
		"""
		Reverse source <-> destination address of EVERY packet upwards including this one (reverse_address has to be implemented).
		"""
		current_hndl = self

		while current_hndl is not None:
			current_hndl.reverse_address()
			current_hndl = current_hndl._get_bodyhandler()

	def _init_handler(self, hndl_type, buffer):
		"""
		Called by overwritten "_dissect()":
		Initiate the handler-parser using the given buffer and set it using _set_bodyhandler() later on (lazy
		init). This will use the calling class and given handler type to retrieve the resulting handler.
		On any error this will set raw bytes given for body data.

		hndl_type -- A value to place the handler in the handler-dict like
			dict[Class.__name__][hndl_type] (eg type-id, port-number)
		buffer -- The buffer to be used to create the handler
		"""
		# empty buffer must lead to empty body
		# initiating packets using empty buffer would lead to wrong (default) values
		if len(buffer) == 0:
			# logger.debug("empty buffer given for _init_handler()!")
			return

		try:
			if self._target_unpack_clz is None or self._target_unpack_clz is self.__class__:
				# set lazy handler data, __getattr__() will be called on access to handler (field not yet initiated)
				clz = Packet._handler[self.__class__.__name__][hndl_type]
				clz_name = clz.__name__.lower()
				# logger.debug("setting handler name: %s -> %s" % (self.__class__.__name__, clz_name))
				self._lazy_handler_data = [clz_name, clz, buffer]
				# set name although we don't set a handler (needed for direction() et al)
				self._bodytypename = clz_name
				self._body_bytes = None
				# avoid setting body_bytes by _unpack()
				self._body_changed = True
			else:
				# continue parsing layers, happens on "__getitem__()": avoid unneeded lazy-data handling
				# if specific class must be found
				# logger.debug("--------> direct unpacking in: %s" % (self.__class__.__name__))
				type_instance = Packet._handler[self.__class__.__name__][hndl_type](buffer, self)
				self._set_bodyhandler(type_instance)
		except KeyError:
			logger.info("unknown type for %s: %d, feel free to implement" % (self.__class__, hndl_type))
			self.body_bytes = buffer
			# TODO: comment in
			# raise Exception("1a>>>>>>>>>>> (key unknown)")
		except Exception:
			logger.exception("can't set handler data, type/lazy: %s/%s:" %
				(str(hndl_type), self._target_unpack_clz is None or self._target_unpack_clz is self.__class__))
			# set raw bytes as data (eg handler class not found)
			self.body_bytes = buffer
			# TODO: comment in
			# raise Exception("1b>>>>>>>>>>> %r" % e)

	def _init_triggerlist(self, name, bts, dissect_callback):
		"""
		Inititiate a TriggerList field. It will be dissected ondemand.

		name -- name of the dynamic filed to be initiated
		bts -- bts to be dissected
		dissect_callback -- callback to be used to dissect, signature: callback(bytes) -> returns list of bytes, packets, ...
		"""
		self.__setattr__("_%s" % name, [bts, dissect_callback])
		self._header_format_changed = True

	def direction_all(self, other_packet):
		"""
		Check for direction on ALL layers from this one upwards.
		This continues upwards until no body handler can be found anymore.
		The extending class can overwrite direction() to implement an individual check,
		signature: direction(self, other_packet) return [same as direction_all]

		other_packet -- Packet to be compared with this Packet
		return -- Bitwise OR-concatination of all directions of ALL layers starting from
			this one upwards. Directions are: [DIR_SAME | DIR_REV | DIR_UNKNOWN].
			This can be checked via eg "direction_found & DIR_SAME"
		"""
		try:
			dir_ext = self.direction(next)
		except AttributeError:
			# attribute not set when comparing: no direction known
			dir_ext = Packet.DIR_UNKNOWN

		try:
			# check upper layers and combine current result
			# logger.debug("direction? checking next layer")
			return dir_ext & self._get_bodyhandler().direction_all(next._get_bodyhandler())
		except AttributeError:
			# one of both _bodytypename was None
			# Example: TCP ACK (last step of handshake, no payload) <-> TCP ACK + Telnet
			return dir_ext

	def direction(self, other):
		return Packet.DIR_UNKNOWN

	def is_direction(self, packet2, direction):
		"""
		Same as "direction_all()" but using explicit direction to be checked.
		As direction_all can be DIR_SAME and DIR_REV at the same time, this call
		is more clearly.

		packet2 -- packet to be compared to this packet
		direction -- check for this direction (DIR_...)
		return -- True if direction is found in this packet, False otherwise.
		"""
		return self.direction_all(packet2) & direction == direction

	def bin(self, update_auto_fields=True):
		"""
		Return this header and body (including all upper layers) as byte string
		and reset changed-status.

		update_auto_fields -- if True auto-update fields like checksums, else leave them be
		"""
		# logger.debug("bin for: %s" % self.__class__.__name__)
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

	def _update_header_format(self):
		"""
		Update format of non-static fields and update _header_format
		"""
		header_format = [self._header_format_order]
		self_getattr = self.__getattribute__

		for name in self._header_field_names:
			if not self_getattr(name + "_active"):
				continue

			val = self.__getattribute__(name)

			if val.__class__ in HEADER_TYPES_SIMPLE:		# assume bytes/int/float
				header_format.append(self_getattr(name + "_format"))
				# logger.debug("adding format for (simple): %r, %s, val: %s" % (self.__class__, name, self_getattr(name)))
			else:							# assume TriggerList
				if val.__class__ == list:
					# TriggerList not yet initiated: take cached value
					header_format.append("%ds" % len(val[0]))
					# logger.debug("adding format for: %r, %s, val: %s" % (self.__class__, name, val[0]))
				else:
					header_format.append("%ds" % len(val.bin()))
					# logger.debug("adding format for: %r, %s, val: %s" % (self.__class__, name, val.bin()))
		self._header_format = Struct("".join(header_format))
		self._header_len = self._header_format.size
		self._header_format_changed = False

	def _pack_header(self):
		"""
		Return header as byte string.
		"""
		if not self._header_changed:
			# return cached data if nothing changed
			# logger.warning("returning cached header (hdr changed=%s): %s->%s" %\
			# (self._header_changed, self.__class__.__name__, self._header_cached))
			return self._header_cached

		if not self._unpacked:
			# this happens on: Packet(b"bytes") -> only changes to TriggerList. We need to unpack buffer values
			# to re-read them for header packing
			self._unpack()
		elif self._header_format_changed:
			# _unpack will call _update_header_format() if needed
			# real format needed for correct packing
			self._update_header_format()

		header_values = []
		self_getattr = self.__getattribute__

		for name in self._header_field_names:
			if not self_getattr(name + "_active"):
				continue
			val = self_getattr(name)
			# two options:
			# - simple type (int, bytes, ...)	-> add given value
			# - TriggerList	(found via format None) -> call bin()
			if val.__class__ in HEADER_TYPES_SIMPLE:		# assume bytes/int/float
				header_values.append(val)
			else:					# assume TriggerList
				if val.__class__ == list:
					header_values.append(val[0])
				else:
					header_values.append(val.bin())

		# logger.debug("header bytes for %s: %s = %s" % (self.__class__.__name__, self._header_format.format, header_bytes))
		# info: individual unpacking is about 4 times slower than cumulative
		self._header_cached = self._header_format.pack(*header_values)
		# logger.debug(">>> cached header: %s (%d)" % (self._header_cached, len(self._header_cached)))
		self._header_changed = False

		return self._header_cached

	# readonly access to header
	header_bytes = property(_pack_header)

	def _changed(self):
		"""
		Check if this or any upper layer changed in header or body

		return -- True if header or body changed, else False
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
				listener_cb()
			except Exception as e:
				logger.exception("error when informing listener: %r" % e)

	@classmethod
	def load_handler(clz, clz_add, handler):
		"""
		Load Packet handler using a shared dictionary.

		clz_add -- class for which handler has to be added
		handler -- dict of handlers to be set like { id : class }, id can be a tuple of values
		"""
		clz_name = clz_add.__name__

		if clz_name in Packet._handler:
			logger.debug("handler already loaded: %r" % clz_name)
			return

		# logger.debug("adding classes as handler: [%r] = %r" % (clz_add, handler))

		Packet._handler[clz_name] = {}

		for handler_id, packetclass in handler.items():
			# pypacker.Packet.load_handler(IP, { ID : class } )
			if type(handler_id) is not tuple:
				Packet._handler[clz_name][handler_id] = packetclass
			else:
				# pypacker.Packet.load_handler(IP, { (ID1, ID2, ...) : class } )
				for id_x in handler_id:
					Packet._handler[clz_name][id_x] = packetclass

	def hexdump(self, length=16, only_header=False):
		"""
		length -- amount of bytes per line
		only_header -- if True: just dump header, else header + body (default)

		return -- hexdump output string for this packet (header or header + body).
		"""
		bytepos = 0
		res = []

		if only_header:
			buf = self._pack_header()
		else:
			buf = self.bin()
		buflen = len(buf)

		while bytepos < buflen:
			line = buf[bytepos: bytepos + length]
			hexa = " ".join(["%02x" % x for x in line])
			# line = line.translate(__vis_filter)
			line = re.sub(PROG_VISIBLE_CHARS, b".", line)
			res.append("  %04d:      %-*s %s" % (bytepos, length * 3, hexa, line))
			bytepos += length
		return "\n".join(res)


#
# utility functions
# These could be put into separate modules but this would lead to recursive import problems.
#
def byte2hex(buf):
	"""Convert a bytestring to a hex-represenation:
	b'1234' -> '\x31\x32\x33\x34'"""
	return "\\x" + "\\x".join(["%02X" % x for x in buf])


# MAC address
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


def get_property_mac(varname):
	"""Create a get/set-property for a MAC address as string-representation."""
	# logger.debug("--------------------- returning property")
	return property(
			lambda obj: mac_bytes_to_str(obj.__getattribute__(varname)),
			lambda obj, val: obj.__setattr__(varname, mac_str_to_bytes(val))
	)


# IPv4 address
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


def get_property_ip4(var):
	"""Create a get/set-property for an IP4 address as string-representation."""
	return property(
		lambda obj: ip4_bytes_to_str(obj.__getattribute__(var)),
		lambda obj, val: obj.__setattr__(var, ip4_str_to_bytes(val))
	)


# DNS names
def dns_name_decode(name):
	"""
	DNS domain name decoder (bytes to string)

	name -- example: b"\x03www\x07example\x03com\x00"
	return -- example: "www.example.com."
	"""
	# ["www", "example", "com"]
	name_decoded = []
	off = 1

	while off < len(name):
		# b"xxx" -> "xxx"
		name_decoded.append(name[off: off + name[off - 1]].decode())
		off += name[off - 1] + 1
	return ".".join(name_decoded) + "."


def dns_name_encode(name):
	"""
	DNS domain name encoder (string to bytes)

	name -- example: "www.example.com"
	return -- example: b'\x03www\x07example\x03com'
	"""
	name_encoded = b""
	# "www" -> b"www"
	labels = [part.encode() for part in name.split(".") if len(part) != 0]

	for label in labels:
		# b"www" -> "\x03www"
		name_encoded.append(chr(len(label)).encode() + label)
	return b"".join(name_encoded) + b"\x00"


def get_property_dnsname(var):
	"""Create a get/set-property for a DNS name."""
	return property(
		lambda obj: dns_name_decode(obj.__getattribute__(var)),
		lambda obj, val: obj.__setattr__(var, dns_name_encode(val))
	)
