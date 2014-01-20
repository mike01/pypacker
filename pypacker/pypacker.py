"""Simple packet creation and parsing."""

from . import triggerlist

import socket
import struct
import logging
import array
import random

logging.basicConfig(format="%(levelname)s (%(funcName)s): %(message)s")
#logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.DEBUG)
logger = logging.getLogger("pypacker")
logger.setLevel(logging.WARNING)
#logger.setLevel(logging.INFO)
#logger.setLevel(logging.DEBUG)

class Error(Exception): pass
class UnpackError(Error): pass
class NeedData(UnpackError): pass

# avoid unneeded references for performance reasons
pack = struct.pack
unpack = struct.unpack
calcsize = struct.calcsize
randint = random.randint

class MetaPacket(type):
	"""
	This Metaclass is a more efficient way of setting attributes than using __init__.
	This is done by reading name / format / default out of __hdr__ in every subclass.
	This configuration is set one time when loading the module (not at instatiation).
	Actual values are retrieved using "obj.field" notation.
	CAUTION: list et al are _SHARED_ among all classes! A copy is needed on changes to them.
	General note: __new__ is called before __init__
	"""

	def __new__(cls, clsname, clsbases, clsdict):
		t = type.__new__(cls, clsname, clsbases, clsdict)
		# all header field names (shared)
		t._hdr_fields = []
		# List of tuples of ("name", TriggerListClass) pairs to be added on __init__() of a packet (if any).
		# This way every Packet gets is own copy of dynamic fields: no copies needed but more overhead
		# on __init__(). NOTE: this list is only consistent prio to instantiation!
		t._hdr_dyn = []
		# get header-infos from subclass
		st = getattr(t, "__hdr__", None)

		if st is not None:
			#logger.debug("loading meta for: %s, st: %s" % (clsname, st))
			# all header formats including byte order
			t._hdr_fmt = [ getattr(t, "__byte_order__", ">")]

			for x in st:
				#logger.debug("meta: %s -> %s" % (x[0], x[2]))
				# check if static field (int, bytes etc.) or TriggerList
				t._hdr_fields.append(x[0])

				if type(x[2]) is not type:
					# got a simple type
					# set initial value
					setattr(t, x[0], x[2])
					t._hdr_fmt.append(x[1])
				else:
					# got a TriggerList
					#logger.debug("got dynamic field: %s=%s" % (x[0], x[2]))
					# set initial value
					setattr(t, x[0], None)
					t._hdr_fmt.append(None)
					# remmember for later instantiation
					t._hdr_dyn.append((x[0], x[2]))

			# header fields as set for performance reasons (shared)
			t._hdr_fields_set = set(t._hdr_fields)
			# current format bytestring as string for convenience
			t._hdr_fmtstr = "".join(v for v in t._hdr_fmt if v is not None)
			#logger.debug("formatstring is: %s" % t._hdr_fmtstr)
			t._hdr_len = calcsize(t._hdr_fmtstr)			
			# body as raw byte string (None if handler present)
			t._data = b""
			# name of the attribute which holds the object representing the body aka the body handler
			t._bodytypename = None
			# callback to the next lower layer (eg for checksum on IP->TCP/UDP)
			t._callback = None
			# track changes to header values and data: This is needed for layers like TCP for
			# checksum-recalculation. Set to "True" on changes to header/body values, set to False on "bin()"
			## track changes to header values
			t._header_changed = False
			## track changes to header format. This will happen when adding new header or using TriggerLists
			t._header_format_changed = False
			## track changes to body value like [None | bytes | body-handler] -> [None | bytes | body-handler]
			t._body_changed = False
			# cache header for performance reasons, this will be set to None on every change to header values
			t._header_cached = None
			# objects which get notified on changes on _header_ values via "__setattr__()" (shared)
			# TODO: use sets here
			t._changelistener = []
			# skip parsing upper layers for performance reasons
			# set via Classname.skip_upperlayer = [True|False]
			t.skip_upperlayer = False
			# lazy handler data, format: [name, class, bytes]
			t._lazy_handler_data = None
		return t

class Packet(object, metaclass=MetaPacket):
	"""
	Base packet class, with metaclass magic to generate members from self.__hdr__.
	This class can be instatiated via:

		Packet(byte_array)
		Packet(key1=val1, key2=val2, ...)

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

	A header definition like __hdr__ = (("name", "12s", b"defaultvalue"),) will define a header field having the name
	"name", format "12s" and defaultvalue "defaultvalue" as bytestring. Fields will be added in order of definition.

	Requirements
	============
	
		- Auto-decoding of headers via given format-patterns (defined via __hdr__)
		- Auto-decoding of body-handlers like IP -> parse IP-data -> add TCP-handler to IP -> parse TCP-data..
		- Access of fields via "layer1.key" notation
		- Some members can be set/retrieved using convenient string-represenations beneath the
			byte-represenation (see Ethernet or IP). This is done by appending "_s" to the attributename:
			obj.key_s = "stringval"
			string_var = obj.key_s
			Convenient access should be set via: varname_s = pypacker.Packet._get_property_XXX("varname")
		- Access of higher layers via layer1.layer2.layerX or "layer1[layerX]" notation
		- Concatination via "layer1 + layer2 + layerX"
		- There are two types of headers:
			1) Static (same order, pre-defined header-names, constant format,
				can be extended by inserting new ones at arbitrary positions)
			2) Dynamic (Packet based or textual protocol-headers, changes in format, length and order)
				These header got format "None" (auto-set when adding new header fields)

				Usage with Packet:
				- Define an TriggerList as part of the value in __hdr__ (or add via _XXX_headerfield())
				- Packets in this list can be added/set/removed afterwards
				NOTE: deep-layer packets will be omitted in Packets, adding new headers
				to sub-packets after adding to a TriggerList is not permitted

				Usage for text-based protocols (eg when headername is given by protocol itself like
				"Host: xyz.org" in HTTP, usage):
				- define an TriggerList as part of the value in __hdr__ (or add via _XXX_headerfield())
				- define _pack() in your TriggerList to reassemble packets (see HTTP).
				Single values in this list can be represented as tuples like [(key, value), (key, value), ...]
				- Values in this list can be added/set/removed afterwards

				Examples can be found at the ip and tcp-implementations.
		- Header-values with length < 1 Byte should be set by using properties
		- Header formats can not be updated directly
		- Ability to check direction to other Packets via "direction()"
		- Generic callback for rare cases eg where upper layer needs
			to know about lower ones (like TCP->IP for checksum calculation)
		- No correction of given raw packet-data eg checksums when creating a packet from it
			(exception: if the packet can't be build without correct data -> raise exception).
			The internal state will only be updated on changes to headers or data.
		- No plausability-checks when changing headers/date manually (type-infos have to be set manually)
		- Checksums are auto-recalculated until set manualy
		- General rule: less changes to headers/body-data = more performance


	New Protocols are added by subclassing Packet and defining fields via "__hdr__"
	as a list of (name, format, default value) tuples. __byte_order__ can be set to
	override the default ('>').
	Extending classes should overwrite the "_dissect"-method for diessction the given data.


	Call-flow
	=========
		
		pypacker(__init__) -auto called->
			-> _dissect(): has to be overwritten, get to know/verify the real header-structure
				-> (optional): call _add/remove_headerfield() to change header structure
				-> (optional): call _parse_handler() setting a handler representing an upper-layer
			-auto called-> _unpack(): set all header values and data using the given format.

	Exceptionally a callback can be used for downward leyer signaling like eg TCP -> IP for checksum calculation.
	
	Examples:

	>>> class Foo(Packet):
	...	  __hdr__ = (("foo", "I", 1), ("bar", "H", 2), ("baz", "4s", "quux"))
	...
	>>> foo = Foo(bar=3)
	>>> foo
	Foo(bar=3)
	>>> foo.bin()
	b"\x00\x00\x00\x01\x00\x03quux"
	>>> foo.bar
	3
	>>> foo.baz
	b"quux"
	>>> foo.foo = 7
	>>> foo.baz = "whee"
	>>> foo
	Foo(baz="whee", foo=7, bar=3)
	>>> Foo(b"hello, world!")
	Foo(baz=" wor", foo=1751477356L, bar=28460, data="ld!")
	"""

	"""Dict for saving body datahandler globaly: { Classname : {id : HandlerClass} }"""
	_handler = {}
	"""Basic types allowed for header-values"""
	__TYPES_ALLOWED_BASIC = set([bytes, int, float])
	"""Constants for Packet-directons"""
	"""Same direction"""
	DIR_SAME	= 1	
	"""Reversed direction"""
	DIR_REV		= 2
	"""Direction unknown"""
	DIR_UNKNOWN	= 3
	

	def __init__(self, *args, **kwargs):
		"""
		Packet constructor with (buf) or ([field=val,...]) prototype.

		buf -- packet buffer to unpack as bytes
		keywords -- arguments correspond to header fields to be set
		"""
		# init of dynamic headers. Don't use "_insert_header()" for performance reasons.
		# Format was allready set in MetaClass.
		for name_value in self._hdr_dyn:
			tl_instance = name_value[1](packet=self)
			object.__setattr__(self, name_value[0], tl_instance)

		if args:
			# buffer given: use it to set header fields and body data.
			# Don't allow empty buffer, we got the headerfield-constructor for that.
			# Allowing default-values giving empty buffer would lead to confusion:
			# there is no way do disambiguate "no body" from "default value set".
			# Empty buffer in A for subhandler B (this Packet) should lead to A
			# having (data=b"", bodyhandler=None)
			if len(args[0]) == 0:
				raise NeedData("Empty buffer given!")
		
			try:
				# this is called on the extended class if present
				self._dissect(args[0])
			except AttributeError as e:
				# no implementation given
				#logger.debug("no dissection defined for: %s" % self)
				pass

			try:
				# assign values to this packet
				self._unpack(args[0])
			except UnpackError as ex:
				raise UnpackError("could not unpack %s: %s" % (self.__class__.__name__, ex))
		else:
			# n headerfields given to set (n >= 0)
			# additional parameters given, those overwrite the class-based attributes
			#logger.debug("New Packet with keyword args (%s)" % self.__class__.__name__)
			for k, v in kwargs.items():
				#logger.debug("setting: %s=%s" % (k, v))
				self.__setattr__(k, v)
			# no reset: directly assigned = changed

	def __len__(self):
		"""Return total length (= header + all upper layer data) in bytes."""

		if self._data is not None:
			#logger.debug("returning length from raw bytes in %s" % self.__class__.__name__)
			return self.hdr_len + len(self._data)
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
	# Public access to header length: keep it uptodate
	#
	def __get_hdrlen(self):
		# format changed: recalculate length
		if self._header_format_changed:
			self._update_fmtstr()
		return self._hdr_len

	hdr_len = property(__get_hdrlen)

	#
	# Public access to format string: keep it uptodate
	#
	def __get_fmtstr(self):
		# format changed: rebuild format string
		if self._header_format_changed:
			self._update_fmtstr()
		return self._hdr_fmtstr

	hdr_fmtstr = property(__get_fmtstr)

	# Two types of data can be set: raw bytes or handler, use property for convenient access
	# The following assumption must be fullfilled: (handler=obj, data=None) OR (handler=None, data=b"")
	def __get_data(self):
		"""
		Return raw data bytes or handler bytes (including all upper layers) if present.
		This is the same as calling bin() but excluding this header and without resetting changed-status.
		"""
		if self._lazy_handler_data is not None:
		# no need to parse: raw bytes for all upper layers
			return self._lazy_handler_data[2]
		elif self._bodytypename is not None:
		# some handler was set
			hndl = object.__getattribute__(self, self._bodytypename)
			return hndl.pack_hdr() + hndl.data
		# return raw bytes
		else:
			return self._data

	def __set_data(self, value):
		"""Allow obj.data = [None | b"" | Packet]. None will reset any body handler."""
		if type(value) is bytes:
			if self._bodytypename is not None:
			# reset all handler data
				self._set_bodyhandler(None)
			# track changes to raw data
			self._body_changed = True
			#logger.debug("setting new raw data: %s" % value)
			self._data = value
		else:
			# set body handler (can be None), assume value is a Packet
			# this will set body changed status to True
			self._set_bodyhandler(value)

	data = property(__get_data, __set_data)

	def __get_body_hndl(self):
		"""Return handler object or None if not present."""
		if self._lazy_handler_data is not None:
		# this will parse lazy handler data on the next layer
		# TODO: avoid re-init of lazy data if we know that handler in question is not present here
			return self.__getattr__( self._lazy_handler_data[0] )
		elif self._bodytypename is not None:
		# there is allready an parsed body handler
			return self.__getattribute__(self._bodytypename)
		else:
		# nope, chuck testa
			#logger.debug("returning None")
			return None

	_body_handler = property(__get_body_hndl)

	def __getattr__(self, k):
		"""
		Gets called if there are no fields matching the name k. Check if we got
		lazy handler data set which must get parsed.
		"""
		if self._lazy_handler_data is not None and self._lazy_handler_data[0] == k:
		# lazy handler data was set, parse lazy handler data now!
			#logger.debug("lazy parsing handler: %s" % k)
			handler_data = self._lazy_handler_data
			#buf = handler_data[2][handler_data[3] : handler_data[4]]

			try:
			# instantiate handler class using buffer
				type_instance = handler_data[1]( handler_data[2] )
				self._set_bodyhandler( type_instance )
			except Exception as e:
				logger.warning("could not lazy-parse handler: %s" % e)
				# TODO: set via "self.data"?
				self._bodytypename = None
				self._data = handler_data[2]
				type_instance = None

			self._lazy_handler_data = None
			# this was a lazy init: same as direct parsing -> no body change
			self._body_changed = False
			return type_instance
		else:
			raise AttributeError

	def __setattr__(self, k, v):
		"""
		Set value of an attribute "k" via "a.k=v".
		"""
		# Track changes to header fields
		if k in self._hdr_fields_set:
			#logger.debug("setting header value: %s=%s" % (k,v))

			#logger.debug("setting attribute: %s: %s->%s" % (self.__class__, k, v))
			self._header_changed = True
			self._header_cached = None
			header_val = object.__getattribute__(self, k)

			# set allowed on basic types
			if type(header_val) in Packet.__TYPES_ALLOWED_BASIC:
				#logger.debug("setting static header value: %s=%s" % (k,v))
				object.__setattr__(self, k, v)
			else:
			# assume TriggerList: avoid overwriting dynamic fields when using keyword constructor Class(key=val)
			# triggerlistObj = [ b"" | (KEY_X, VAL) | [(KEY_X, VAL), ...]] => clear current
			# list and add value.
				#logger.debug("adding triggerlist values: %s=%s" % (k,v))
				del header_val[:]
				if type(v) is list:
					header_val.extend(v)
				else:
					header_val.append(v)
			self.__notity_changelistener()
		else:
			object.__setattr__(self, k, v)

	def __getitem__(self, k):
		"""
		Check every layer upwards (inclusive this layer) for the given Packet-Type
		and return the first matched instance or None if nothing was found.

		k -- Packet-type to search for like Ethernet, IP, TCP etc.
		"""
		p_instance = self

		while not type(p_instance) is k:
			# this will auto-parse lazy handler data
			p_instance = p_instance._body_handler

			if p_instance is None:
				break

		#logger.debug("returning found packet-handler: %s->%s" % (type(self), type(p_instance)))
		return p_instance	

	def __add__(self, packet_to_add):
		"""
		Handle concatination of layers like "Ethernet + IP + TCP" and make them accessible
		via "ethernet.ip.tcp" (class names as lowercase). Every "A + B" operation will return A,
		setting B as the handler (of the deepest handler) of A.

		NOTE: changes to A after creating a Packet like "A+B+C+..." will affect the new created Packet itself.
		Create a deep copy to avoid this behaviour.

		packet_to_add -- the packet to be added as new highest layer for this packet
		"""

		# get highest layer from this packet
		highest_layer = self

		while highest_layer is not None:
			if highest_layer._bodytypename is not None:
				highest_layer = highest_layer._body_handler
			else:
				break

		# connect callback from lower (this packet, highest_layer) to upper (packet_to_add) layer eg IP->TCP
		packet_to_add._callback = highest_layer._callback_impl
		highest_layer.data = packet_to_add

		return self

	def __repr__(self):
		"""Verbose represention of this packet as "key=value"."""
		# recalculate fields like checksums, lengths etc
		if self._header_changed or self._body_changed:
			self.bin()

		l = [ "%s=%r" % (k, self.__getattribute__(k))
			for k in self._hdr_fields]
		if self._data is not None:
			l.append("data=%r" % self._data)
		else:
			# assume bodyhandler is set
			#l.append("handler=%s" % self.__getattribute__(self._bodytypename).__class__)
			l.append("handler=%s" % self._bodytypename)
		return "%s(%s)" % (self.__class__.__name__, ", ".join(l))

	#
	# Methods for creating properties for convenient access eg: mac (bytes) -> mac (str), ip (bytes) -> ip (str)
	# Names of propertie fields should be named like: [name_of_variable]_s
	#
	def _get_property_mac(var):
		"""Create a get/set-property for a MAC address as string-representation."""
		return property(lambda self: mac_bytes_to_str(object.__getattribute__(self, var)),
		lambda self, val: self.__setattr__(var, mac_str_to_bytes(val)))

	def _get_property_ip4(var):
		"""Create a get/set-property for an IP4 address as string-representation."""
		return property(lambda self: ip4_bytes_to_str(object.__getattribute__(self, var)),
		lambda self, val: self.__setattr__(var, ip4_str_to_bytes(val)))
	#
	#
	#

	def _unpack(self, buf):
		"""
		Unpack/import a full layer using bytes in buf and set all headers
		and data accordingly. This will use the current state of "_hdr_fields"
		to set all field values. This will also set data if not allready set
		by overwriting class in "dissect()".
		NOTE: This is only called by the Packet class itself!

		buf -- the buffer to be parsed
		"""
		cnt = 1

		try:
			# this will update format for dynamic fields
			self._header_cached = buf[:self.hdr_len]

			for k, v in zip(self._hdr_fields,
					unpack(self.hdr_fmtstr, self._header_cached)):
				# only set non-TriggerList fields
				if self._hdr_fmt[cnt] != None:
					object.__setattr__(self, k, v)
				cnt += 1
		except IndexError:
			 raise NeedData("Not enough data to unpack: buf %d < %d" % (len(buf), self.hdr_len))

		# extending class didn't set data itself, set raw data
		if not self._body_changed:
			self._data = buf[self._hdr_len:]

		#logger.debug("header: %s, body: %s" % (self._hdr_fmtstr, self.data))
		# reset the changed-flags: original unpacked value = no changes
		self.__reset_changed()

	def create_reverse(self):
		"""
		Creata a packet having reverse direction. This is defined for: Ethernet, IP, TCP, UDP.
		Note: This will only set static fields which are responsible for direction. Unknown layers
		will be created using the non-keyword constructor.

		return -- Packet having reverse direction of layers starting from this layer
		"""
		current_hndl	= self
		new_packet	= None

		while current_hndl is not None:
			# cycle through all layers starting at the bottom
			#logger.debug("current handler: %s" % current_hndl)
			name = current_hndl.__class__.__name__
			C = current_hndl.__class__
			new_layer = None

			# create new layer based on retrieved class
			# TODO: use dicts
			if name == "Ethernet":
				new_layer = C(src=current_hndl.dst, dst=current_hndl.src, type=current_hndl.type)
			elif name == "IP":
				new_layer = C(src=current_hndl.dst, dst=current_hndl.src, p=current_hndl.p)
			elif name in [ "TCP", "UDP" ]:
				new_layer = C(sport=current_hndl.dport, dport=current_hndl.sport)
			elif C != "bytes":
				new_layer = C()
			#else:
			#	new_layer = current_hndl

			#logger.debug("new layer is: %s" % new_layer)
			# concat fresh created layer
			if new_packet is not None:
				new_packet = new_packet + new_layer
			else:
				new_packet = new_layer

			# next layer to be copied
			if current_hndl._body_handler is None:
				# upper layer reached: set raw bytes
				new_layer.data = current_hndl.data

			current_hndl = current_hndl._body_handler

		return new_packet

	def _insert_headerfield(self, pos, name, format, value, skip_update=False):
		"""
		Insert a new headerfield into the current defined list.
		The new header field can be accessed via "obj.attrname".
		This should only be called at the beginning of the packet-creation process.

		pos -- position of header
		name -- name of header
		format -- format of header
		skip_update -- skip update of _hdr_fmtstr, new header length won't be correct until update
		"""
		# list of headers via TriggerList (like TCP-options), add packet for status-handling
		if isinstance(value, triggerlist.TriggerList):
			value._packet = self
			# mark this header field as Triggerlist
			format = None
		elif type(value) not in Packet.__TYPES_ALLOWED_BASIC:
			raise Error("can't add this value as new header (no basic type or TriggerList): %s, type: %s" % (value, type(value)))

		object.__setattr__(self, name, value)

		# We need a new shallow copy: these attributes are shared. Only called on first change.
		if not hasattr(self, "__hdr_ind"):
			self._hdr_fields = list( object.__getattribute__(self, "_hdr_fields") )
			self._hdr_fields_set = set(self._hdr_fields)
			self._hdr_fmt = list( object.__getattribute__(self, "_hdr_fmt") )
			self.__hdr_ind = True

		self._hdr_fields.insert(pos, name)
		self._hdr_fields_set.add(name)
		# skip format character
		self._hdr_fmt.insert(pos+1, format)

		# skip update for performance reasons
		if not skip_update:
			self._update_fmtstr()
		else:
			self._header_format_changed = True

	def _del_headerfield(self, pos, skip_update=False):
		"""
		Remove a headerfield from the current defined list.
		The new header field can be accessed via "obj.attrname".
		This should only be called at the beginning of the packet-creation process.

		pos -- position of header
		skip_update -- skip update of _hdr_fmtstr
		"""
		# we need a new shallow copy: these attributes are shared, TODO: more performant
		if not hasattr(self, "__hdr_ind"):
			self._hdr_fields = list( object.__getattribute__(self, "_hdr_fields") )
			self._hdr_fields_set = set(self._hdr_fields)
			self._hdr_fmt = list( object.__getattribute__(self, "_hdr_fmt") )
			self.__hdr_ind = True

		self._hdr_fields_set.remove(self._hdr_fields[pos])
		del self._hdr_fields[pos]
		del self._hdr_fmt[pos+1]

		if not skip_update:
			self._update_fmtstr()
		else:
			self._header_format_changed = True

	def _add_headerfield(self, name, format, value, skip_update=False):
		"""
		Add a new headerfield to the end of all fields. See _insert_headerfield() for more infos.
		"""
		self._insert_headerfield(len(self._hdr_fields), name, format, value, skip_update)

	def _callback_impl(self, id):
		"""
		Generic callback. The calling class must know if/how this callback
		is implemented for this class and which id is needed
		(eg. id "calc_sum" for IP checksum calculation in TCP used of pseudo-header).

		id -- a unique id for the given callback
		"""
		pass

	def _parse_handler(self, type, buffer):
		"""
		Called by overwritten "_dissect()":
		Parse the handler using the given buffer and set it using _set_bodyhandler() later on (Lazy
		init). This will use the calling class and given type to retieve the resulting handler.
		On any error this will set raw bytes given for data.

		type -- A value to place the handler in the handler-dict like
			dict[Class.__name__][type] (eg type-id, port-number)
		buffer -- The buffer to be used to create the handler
		"""
		if self.skip_upperlayer:
			return

		# TODO: check for empty buffer: avoid parsing
		# how much overhead by directly splitting buffer?
		if len(buffer) == 0:
			# no handler set by default, no bytes given -> data = b""
			#logger.debug("empty buffer given for _parse_handler()!")
			return

		try:
			clz = Packet._handler[self.__class__.__name__][type]
			clz_name = clz.__name__.lower()
			#logger.debug("setting handler name: %s -> %s" % (self.__class__.__name__, clz_name))
			self._lazy_handler_data = [clz_name, clz, buffer]
			# set name allthough we don't set a handler (needed for direction() et al)
			self._bodytypename = clz_name
			# avoid setting data by "_unpack"
			self._body_changed = True
			self._data = None
		except Exception as e:
			#logger.debug("can't set lazy handler data in %s: %s" % (self.__class__, e))
			# set raw bytes as data (eg handler class not found)
			#self.data = buffer[offset_start:offset_end]
			self.data = buffer

	def direction(self, next):
		"""
		Every layer can check the direction to the given "next" layer.
		This continues until no body handler can be found anymore.
		The extending class should overwrite _direction() to implement an individual check.

		next -- Packet to be compared with this Packet
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
			return dir_ext & self._body_handler.direction( next._body_handler )
		except AttributeError:
			# one of both _bodytypename was None
			# Example: TCP ACK (last step of handshake, no payload) <-> TCP ACK + Telnet
			return dir_ext

	def is_direction(self, next, dir):
		"""
		Same as "direction()" but using explicit direction to be checked.
		As direction can be DIR_SAME and DIR_REV at the same time, this call
		is more clearly.

		return -- True if direction dir is found in this packet, False otherwise.
		"""
		return self.direction(next) & dir == dir

	def _update_fmtstr(self):
		"""
		Update header format string and length using current fields.
		NOTE: only called if format has changed eg after addin/removing header fields,
		changes in TriggerList etc.
		"""
		# byte-order is set via first character
		hdr_fmt_tmp = [ self._hdr_fmt[0] ]

		# we need to preserve the order of formats / fields
		for idx, field in enumerate(self._hdr_fields):
			# Three options:
			# - value bytes			-> add given format or calculate by length
			# - value TriggerList		(found via format None)
			#	- type Packet		-> a TriggerList of packets, reassemble formats
			#	- type tuple		-> a TriggerList of tuples, call "reassemble" and use format "s"
			#logger.debug("format update with field/type/val: %s/%s/%s" % (field, type(val), val))
			if self._hdr_fmt[1 + idx] is not None:				# bytes/int/float
				hdr_fmt_tmp.append( self._hdr_fmt[1 + idx] )		# skip byte-order character
			else:								# assume TriggerList	
				val = self.__getattribute__(field).bin()

				if len(val) > 0:
					hdr_fmt_tmp.append( "%ds" % len(val) )

		hdr_fmt_tmp = "".join(hdr_fmt_tmp)

		# update header info, avoid recursive calls
		self._hdr_fmtstr = hdr_fmt_tmp
		self._header_format_changed = False
		self._hdr_len = calcsize(hdr_fmt_tmp)

	def _set_bodyhandler(self, hndl):
		"""
		Set handler to decode the actual body data using the given handler
		and make it accessible via layername.addedtype like ethernet.ip.
		This will take the classname of the given handler as lowercase.
		If handler is None any handler will be reset and data will be set to an
		empty byte string.

		hndl -- the handler to be set (None or Packet)
		"""
		if hndl is not None and not isinstance(hndl, Packet):
			raise Error("can't set handler which is not a Packet")

		if hndl is None:
		# switch (handler=obj, data=None) to (handler=None, data=b'')
			self._bodytypename = None
			# avoid (data=None, handler=None)
			self._data = b""
		else:
		# set a new body handler
			# associate ip, arp etc with handler-instance to call "ether.ip", "ip.tcp" etc
			self._bodytypename = hndl.__class__.__name__.lower()
			hndl._callback = self._callback_impl
			object.__setattr__(self, self._bodytypename, hndl)
			self._data = None

		self._lazy_handler_data	= None
		# new body handler means body data changed
		self._body_changed = True

	def bin(self):
		"""
		Return this header and body (including all upper layers) as byte string
		and reset changed-status.
		"""
		# preserve change status until we got all data of all sub-handlers
		# needed for eg IP (changed) -> TCP (check changed for sum).
		if self._lazy_handler_data is not None:
			# no need to parse, just take lazy handler data bytes
			data_tmp = self._lazy_handler_data[2]
		elif self._bodytypename is not None:
			# handler allready parsed
			data_tmp = self._body_handler.bin()
		else:
			# raw bytes
			data_tmp = self._data
		# now every layer got informed about our status, reset it
		self.__reset_changed()
		return self.pack_hdr() + data_tmp

	def pack_hdr(self):
		"""
		Return header as byte string.
		"""
		if self._header_format_changed:
			self._update_fmtstr()
		# return cached data if nothing changed
		elif self._header_cached is not None:
			#logger.warning("returning cached header (hdr changed=%s): %s->%s" %\
			#	(self.header_changed, self.__class__.__name__, self._header_cached))
			return self._header_cached

		try:
			hdr_bytes = []
			# skip fields with value None
			for idx, field in enumerate(self._hdr_fields):
				# don't call self.__getattribute__(obj, field) because some fields are auto-updating
				val = self.__getattribute__(field)
				# three options:
				# - value bytes			-> add given bytes
				# - value TriggerList		(found via format None)
				#	- type Packet		-> a TriggerList of packets, reassemble bytes
				#	- type tuple		-> a Triggerlist of tuples, call "pack"
				#logger.debug("packing header with field/type/val: %s/%s/%s" % (field, type(val), val))
				if self._hdr_fmt[1 + idx] is not None:		# bytes/int/float
					hdr_bytes.append( val )
				else:						# assume TriggerList
					val = val.bin()
					if len(val) > 0:
						hdr_bytes.append( val )
			#logger.debug("header bytes for %s: %s = %s" % (self.__class__.__name__, self._hdr_fmtstr, hdr_bytes))
			self._header_cached = pack( self._hdr_fmtstr, *hdr_bytes )

			return self._header_cached
		except Exception as e:
			logger.warning("error while packing header: %s" % e)

	def _changed(self):
		"""Check if this or any upper layer changed in header or body."""
		changed = False
		p_instance = self

		while p_instance is not None:
			if p_instance._header_changed or p_instance._body_changed:
				changed = True
				p_instance = None
				break
			elif p_instance._lazy_handler_data is None:
			# one layer up, stop if next layer is not yet initiated which means: no change
				p_instance = p_instance._body_handler
			else:
			# no handler but bytes
				p_instance = None
		return changed

	def __reset_changed(self):
		"""Set the header/body changed-flag to False. This won't clear caches."""
		self._header_changed = False
		self._body_changed = False

	def add_change_listener(self, listener_cb):
		"""
		Add a new callback to be called on changes to header or body.
		The only argument is this packet itself.
	
		listener_cb -- the change listener to be added as callback-function
		"""
		if len(self._changelistener) == 0:
			# copy list (shared)
			self._changelistener = []
		# avoid same listener multiple times
		if not listener_cb in self._changelistener:
			self._changelistener.append(listener_cb)

	def remove_change_listener(self, listener_cb, remove_all=False):
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

	def __notity_changelistener(self):
		"""
		Notify listener about changes.
		"""
		for listener_cb in self._changelistener:
			try:
				listener_cb(self)
			except Exception as e:
				logger.warning("error when informing listener: %s" % e)
				#pass

	def __load_handler(clz, clz_add, handler):
		"""
		Load Packet handler using a shared dictionary.

		clz_add -- class to be added
		handler -- dict of handlers to be set like { id : class }, id can be a tuple of values
		"""
		clz_name = clz_add.__name__

		try:
			Packet._handler[clz_name]
			logger.debug(">>> handler already loaded: %s (%d)" % clz_add)
			return
		except KeyError:
			pass

		logger.debug("adding classes as handler: [%s] = %s" % (clz_add, handler))

		Packet._handler[clz_name] = {}

		for k,v in handler.items():
			if type(k) is not tuple:
				Packet._handler[clz_name][k] = v
			else:
				for k_item in k:
					Packet._handler[clz_name][k_item] = v

	load_handler = classmethod(__load_handler)


#
# utility functions
#
def mac_str_to_bytes(mac_str):
	"""Convert mac address AA:BB:CC:DD:EE:FF to byte representation."""
	return b"".join([ bytes.fromhex(x) for x in mac_str.split(":") ])

def mac_bytes_to_str(mac_bytes):
	"""Convert mac address from byte representation to AA:BB:CC:DD:EE:FF."""
	return "%02x:%02x:%02x:%02x:%02x:%02x" % unpack("BBBBBB", mac_bytes)

def get_rnd_mac():
	"""Create random mac address as bytestring"""
	return pack("BBBBBB", randint(0,255), randint(0,255), randint(0,255), randint(0,255), randint(0,255), randint(0,255))

def ip4_str_to_bytes(ip_str):
	"""Convert ip address 127.0.0.1 to byte representation."""
	ips = [ int(x) for x in ip_str.split(".")]
	return pack("BBBB", ips[0], ips[1], ips[2], ips[3])

def ip4_bytes_to_str(ip_bytes):
	"""Convert ip address from byte representation to 127.0.0.1."""
	return "%d.%d.%d.%d" % unpack("BBBB", ip_bytes)

def get_rnd_ipv4():
	"""Create random ipv4 adress as bytestring"""
	return pack("BBBB", randint(0,255), randint(0,255), randint(0,255), randint(0,255))

def byte2hex(buf):
	"""Convert a bytestring to a hex-represenation:
	b'1234' -> '\x31\x32\x33\x34'"""
	return "\\x"+"\\x".join( [ "%02X" % x for x in buf ] )

# XXX - ''.join([(len(`chr(x)`)==3) and chr(x) or '.' for x in range(256)])
__vis_filter = """................................ !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[.]^_`abcdefghijklmnopqrstuvwxyz{|}~................................................................................................................................."""

def hexdump(buf, length=16):
	"""Return a hexdump output string of the given buffer."""
	n = 0
	res = []
	while buf:
		line, buf = buf[:length], buf[length:]
		hexa = " ".join(["%02x" % ord(x) for x in line])
		line = line.translate(__vis_filter)
		res.append("  %04d:	 %-*s %s" % (n, length * 3, hexa, line))
		n += length
	return "\n".join(res)

#
# Checksum functions
#

def in_cksum_add(s, buf):
	"""Add checksum value to the given value s."""
	n = len(buf)
	#logger.debug("buflen for checksum: %d" % n)
	cnt = int(n / 2) * 2
	#logger.debug("slicing at: %d, %s" % (cnt, type(cnt)))
	a = array.array("H", buf[:cnt])
	#logger.debug("2-byte values: %s" % a)
	#logger.debug(buf[-1].to_bytes(1, byteorder='big'))

	if cnt != n:
		a.append(unpack("H", buf[-1].to_bytes(1, byteorder="big") + b"\x00")[0])
	return s + sum(a)

def in_cksum_done(s):
	"""Complete checksum building."""
	# add carry to sum itself
	s = (s >> 16) + (s & 0xffff)
	s += (s >> 16)
	# return complement of sums
	return socket.ntohs(~s & 0xffff)

def in_cksum(buf):
	"""Return computed Internet Protocol checksum."""
	return in_cksum_done(in_cksum_add(0, buf))
