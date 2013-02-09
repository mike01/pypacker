# $Id: pypacker.py 43 2007-08-02 22:42:59Z jon.oberheide $

"""Simple packet creation and parsing."""

import copy
import itertools
import socket
import struct
import logging
import copy

import pypacker
logging.basicConfig(format="%(levelname)s (%(funcName)s): %(message)s")
#logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.DEBUG)
logger = logging.getLogger("pypacker")
#logger.setLevel(logging.INFO)
logger.setLevel(logging.DEBUG)


class Error(Exception): pass
class UnpackError(Error): pass
class NeedData(UnpackError): pass
class PackError(Error): pass


class MetaPacket(type):
	"""This Metaclass is a more efficient way of setting attributes than
	using __init__. This is done by reading name / format / default out
	of __hdr__ in every subclass. This configuration is set one time
	when loading the module (not at instatiation).
	A default of None means: skip this field per default.
	This can be changed by setting not-None values in "unpack()" of an
	extending class using "self.key = ''" BEFORE calling the super implementation.
	Actual values are retrieved using "obj.field" notation.
	"""
	def __new__(cls, clsname, clsbases, clsdict):
		t = type.__new__(cls, clsname, clsbases, clsdict)
		# get header-infos from subclass
		st = getattr(t, "__hdr__", None)

		if st is not None:
			#t = type.__new__(cls, clsname, clsbases, clsdict)
			logger.debug("loading meta for: %s, st: %s" % (clsname, st))
			#clsdict["__slots__"] = [ x[0] for x in st ] + [ "data" ]
			# set fields for name/format/default
			#for x in st:
			#	print(">>> %s" % str(x[0]))
			t.__hdr_fields__ = [ x[0] for x in st ]				# all header field names (shared)
			t.__hdr_fmt__ = [ getattr(t, "__byte_order__", ">")]		# all header formats including byte order
			fmt_str_not_none_list = [ getattr(t, "__byte_order__", ">")]
			t.__hdr_fields_not_none__ = []					# track fields with value None for performance reasons (shared)

			for x in st:
				#logger.debug("meta: %s -> %s" % (x[0], x[2]))
				setattr(t, x[0], x[2])					# make header fields accessible
				t.__hdr_fmt__ += [x[1]]
				if x[2] is not None:
					fmt_str_not_none_list += [x[1]]
					t.__hdr_fields_not_none__ += [x[0]]

			#logger.debug("format/not none: %s/%s" % (fmt_str_not_none_list, t.__hdr_fields_not_none__))

			t.__hdr_fmtstr__ = "".join(fmt_str_not_none_list)		# current formatstring without None values as string for convenience
			t.__hdr_len__ = struct.calcsize(t.__hdr_fmtstr__)			
			# body as raw byte-array
			t.data = b""
			# name of the attribute which holds the object representing the body
			t.bodytypename = None
			# callback to the next lower layer (eg for checksum on IP->TCP/UDP)
			t.callback = None
			# track changes to header and data. This is needed for caching or layers like TCP for
			# checksum-recalculation set to "True" on __set_attribute() or format changes,
			# set to False on "__str__()" or "bin()"
			#t.packet_changed = False
			t.header_changed = False	# track changes to values and format
			t.body_changed = False		# track changes like None -> [bytes, body-handler] and vise versa
			# cache header for performance reasons
			t._header_cached = None
			# objects which get notified on changes on _header_ values via "__setattr__()" (shared)
			t._changelistener = []
		return t

class Packet(object, metaclass=MetaPacket):
	"""Base packet class, with metaclass magic to generate members from
	self.__hdr__. This class can be instatiated via:

		Packet(byte_array)
		Packet(key1=val1, key2=val2, ...)

	Requirements
	============
		- Auto-decoding of headers via given format-patterns
		- Access of fields via "layer1.key" notation
		- Access of higher layers via layer1.layer2.layerX or "layer1[layerX]" notation
		- Concatination via "layer1 + layer2 + layerX"
		- There are two types of headers:
			1) static (same order, pre-defined header-names, constant format,
				can be optionally removed by setting value to None,
				can be extended by appending new ones to the end)
				Note: static fields can be packets itself for fields of same kind (eg TCP-options), usage:
				- define an TriggerList of packets and add relevant header/values to each of them via "_add_headerfield()" (see IP and TCP options)
				- add this TriggerList to the packet-header using "_add_headerfield"
				- Packets cn be added/set/removed afterwards
				NOTE: data-values and deep-layer packets will be omitted in Packets, adding new headers
					to sub-packets after adding to a TriggerList is not permitted
			2) dynamic (textual based protocol-headers, changes in format, length and order,
				headername is given by protocol itself like "Host: xyz.org" in HTTP), usage:
				- subclass a TriggerList and define "__init__()" and "pack()" to dissect/reassemble
					packets (see HTTP). "__init__()" should dissect the packet using tupels like ("key", "val")
				- add TriggerList to the packet-header using "_add_headerfield"
		- Enable/disable specific header fields (optional fields) by setting value to None
		- Header formats can not be updated
		- Ability to check for relation to other layers via "is_related()"
		- Generic callback for rare cases eg where upper layer needs
			to know about lower ones (like TCP->IP for checksum calculation)
		- No correction of given raw packet-data eg checksums when creating a
			packet from it (exception: if the packet can't be build without
			correct data -> raise exception). The internal state will only
			be updated on changes to headers or data or output-methods like "bin()".
		- Note: when changing headers/date manually (in contrast to unpacked data via raw data)
			there are no plausability-checks!
		- General rule: less changes to data = more performance

	Every packet got an optional header and an optional body.
	Body-data can be raw byte-array OR a packet itself
	which stores the data. This way a multi-layered Packet can be archieved easyly.
	The following schema illustrates the structure of a Packet:

	Packet structure
	================
	[headerfield1]
	[headerfield2]
	...
	[headerfieldN]
	...
	[Packet
		[Packet
		... 
			[Packet: raw data]
	]]

	New Protocols are added by subclassing Packet and defining fields via "__hdr__"
	as a list of (name, structfmt, default value) tuples. __byte_order__ can be set to
	override the default ('>').
	Extending classes should have their own "unpack"-method, which itself
	must call pypacker.Packet.unpack(self, buf) to decode the full header.
	By calling unpack of the subclass first, we can handle optional (set default
	header value, eg VLAN in ethernet) or dynamic (using TriggerList) header-fields.
	The full header MUST be defined using __hdr__ or _add_hdrfield() after finishing
	"unpack" in the extending class.

	Call-flow
	=========
		pypacker(__init__) -auto calls-> sub(unpack): get to know/verify the real header-structure
			an change values/formats if needed (set values for static fields, add fields via
			"_add_headerfield()", set data handler)	-manually call-> pypacker
			(parse all header fields and set data) -> ...

		without overwriting unpack in sub:
		pypacker(__init__) -auto calls-> pypacker(parse static parts)

	Exceptionally a callback can be used for backward signaling this purposes.
	The following methods must be called in Packet itself via pypacker.Packet.xyz() if overwritten:
		unpack()
		__setattr__()
	
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

	def __init__(self, *args, **kwargs):
		"""Packet constructor with ([buf], [field=val,...]) prototype.
		Arguments:

		buf - optional packet buffer to unpack as bytes
		keywords - arguments correspond to members to set
		"""
		if args:
			# buffer given: use it to set header fields and body data
			#logger.debug("New Packet with buf (%s): %s" % (self.__class__.__name__, args[0]))
			# Don't allow empty buffer, we got the headerfield-constructor for that.
			# Allowing default-values giving empty buffer would lead to confusion:
			# there is no way do disambiguate "no body" from "default value set".
			# So in a nutshell: empty buffer for subhandler = (data=b"", bodyhandler=None)
			if len(args[0]) == 0:
				raise NeedData("empty buffer given, nothing to unpack!")

			try:
				# this is called on the extended class if present
				# which can enable/disable static fields and add optional ones
				self.unpack(args[0])
			except struct.error:
				if len(args[0]) < self.__hdr_len__:
					raise NeedData
				raise UnpackError("invalid %s: %r" % (self.__class__.__name__, args[0]))
		else:
			# n headerfields given to set (n >= 0)
			#logger.debug("New Packet with keyword args (%s)" % self.__class__.__name__)
			# additional parameters given, those overwrite the class-based attributes
			for k, v in kwargs.items():
				#logger.debug("setting: %s=%s" % (k, v))
				object.__setattr__(self, k, v)

	def __len__(self):
		"""Return total length (= header + all upper layer data) in bytes."""
		return self.__hdr_len__ + \
			(len(self.data) if self.data is not None else \
			len(object.__getattribute__(self, self.bodytypename))
			)

	#def hdrlen(self):
	#	"""Return the header length."""
	#	return self.__hdr_len__

	def __setattr__(self, k, v):
		"""Set value of an attribute "k" via "a.k=v". Track changes to fields for later packing."""
		# the following assumption must be fullfilled: (handler=obj, data=None) OR (handler=None, data=b"")
		if k is not "data":
			# change header
			if k in self.__hdr_fields__:
				oldval = object.__getattribute__(self, k)
				object.__setattr__(self, k, v)

				# changes which affect format
				if v is None and oldval is not None or \
				v is not None and oldval is None:
					# TODO: NoneType?
					if not type(v) in [bytes, type(None), int, float] and not isinstance(v, TriggerList):
						raise Error("Attempt to set headervalue which is not of bytes/None/TriggerList: %s=%s" % (type(v), v))
					logger.debug("format update needed: %s->%s" % (k, v))
					self.__update_fmtstr()
				# track relevant changes to header fields and body data
				object.__setattr__(self, "header_changed", True)
				self.__notity_changelistener()
			else:
				# change value of other member
				object.__setattr__(self, k, v)
		else:
			# change data
			#logger.debug("data, type: %s/%s" % (self.data, self.bodytypename))
			if not type(v) in [bytes, type(None)]:
				raise Error("attempt to set data to other value then bytes/None: %s:%s, %s" % (k, v, self.bodytypename))
			elif v is None and self.bodytypename is None:
				raise Error("attempt to set data to None on layer without handler: %s:%s, %s" % (k, v, self.bodytypename))
			else:
				# switch from (handler=obj, data=None) to (handler=None, data=b"")
				if None not in [self.bodytypename, v]:
						self._set_bodyhandler(None)
				# track changes to raw data
				object.__setattr__(self, "body_changed", True)
				#logger.debug("setting new raw data: %s (type=%s)" % (v, self.bodytypename))
				object.__setattr__(self, k, v)

	def __getitem__(self, k):
		"""Check every layer upwards (inclusive this layer) for the given Packet-Type
		and return the first matched instance or None if nothing was found."""
		p_instance = self

		while not type(p_instance) in [k, type(None)]:
			if p_instance.bodytypename is not None:
				# one layer up
				p_instance = getattr(p_instance, p_instance.bodytypename)
			else:
				p_instance = None
				break
		#logger.debug("returning found packet-handler: %s->%s" % (type(self), type(p_instance)))
		return p_instance	

	def __add__(self, v):
		"""Handle concatination of layers like "ethernet + ip + tcp. Every "A + B" operation
		will return a deep copy of A, setting B as the handler (of the deepest handler) of A.
		This won't change anything but inner body-handlers and will reset all change states to unchanged.
		To auto-update checksums/header-length make changes to any field."""
		logger.debug("div called: %s/%s" % (self.__class__.__name__, v.__class__.__name__, ))

		if type(v) is bytes:
			raise Error("Can not concat bytes")
		# get deepest handler from this
		hndl = copy.deepcopy(self)
		hndl_deep = hndl

		while hndl_deep is not None:
			hndl_deep.__reset_changed()
			if hndl_deep.bodytypename is not None:
				hndl_deep = object.__getattribute__(hndl_deep, hndl_deep.bodytypename)
			else:
				break

		v_copy = copy.deepcopy(v)
		v_copy.__reset_changed()
		hndl_deep._set_bodyhandler(v_copy)
		# reset changes occured by setting handler
		hndl_deep.__reset_changed()

		return hndl

	def __repr__(self):
		"""Unique represention of this packet."""
		l = [ "%s=%r" % (k, object.__getattribute__(self, k))
			for k in self.__hdr_fields__]
		if self.data:
			l.append("data=%r" % self.data)
		return "%s(%s)" % (self.__class__.__name__, ", ".join(l))

	def add_change_listener(self, obj):
		"""Add a new callback to be called on changes to header. There are no parameters given."""
		if len(self._changelistener) == 0:
			# re-init new list, meta-list is shared!
			self._changelistener = []
		# avoid same listener multiple times
		if not obj in self._changelistener:
			self._changelistener += [ obj ]

	def remove_change_listener(self, obj):
		"""Remove callback from the list of listeners."""
		self._changelistener.remove(obj)

	def __notity_changelistener(self):
		try:
			for o in self._changelistener:
				o(self)
		except Exceptio as e:
			logger.debug("error when informing listener: %s" % s)

	def callback_impl(self, id):
		"""Generic callback. The calling class must know if/how this callback
		is implemented for this class and which id is needed
		(eg. id "calc_sum" for IP checksum calculation in TCP used of pseudo-header)"""
		pass

	def is_related(self, next):
		"""Every layer can check if the given layer (of the next packet) is related
		to itself and continues this on the next upper layer if there is a relation.
		This stops if there is no relation or the body data is not a Packet.
		The extending class should call the super implementation on overwriting.
		This will return True if the body (self or next) is just raw bytes."""
		# raw bytes as body, assume it's related as default
		if self.bodytypename is None or next.bodytypename is None:
			return True
		else:
			# body is a Packet and this layer is related, we must go deeper on Packets
			body_p_this = object.__getattribute__(self, self.bodytypename)
			body_p_next = object.__getattribute__(next, next.bodytypename)

			return body_p_this.is_related(body_p_next)

	def _add_headerfield(self, name, format, value):
		"""Append a new headerfield to the end of the current
		defined list. The new header field can be accessed via "obj.attrname".
		This should only be called at the beginning of the packet-creation process.
		"""
		# list of headers via TriggerList (like TCP-optios), add packet for status-handling
		if isinstance(value, TriggerList):
			value.packet = self
			value.format_cb = self.__update_fmtstr
		elif type(value) not in [bytes, int, float]:
			raise Error("can't add this value as new header: %s, type: %s" % (value, type(value)))
		# allow format None: auto-set based on value
		elif format is None:
			format = "%ds" % len(value)
		# Update internal header data. This won't break anything because
		# all field-informations are allready initialized via metaclass.
		# We need a new shallow copy: these attributes are shared, TODO: more performant
		self.__hdr_fields__ = list(self.__hdr_fields__) + [name]
		self.__hdr_fmt__ = list(self.__hdr_fmt__) + [format]
		object.__setattr__(self, name, value)
		# fields with value None won't change format string
		#if value is not None:
		self.__update_fmtstr()
		self.__notity_changelistener()

	# TODO: check if needed and remove
	#def _set_headerformat(self, name, format):
	#	"""Set format of an allready present header field."""
	#	if not name in self.__hdr_fields__:
	#		raise Error("headerfiled not present: %s" % name)
	#	
	#	# we need a new shallow copy: these attributes are shared
	#	self.__hdr_fmt__ = list(self.__hdr_fmt__)
	#	# get index using header-names (+1 offset) and assign new format
	#	self.__hdr_fmt__[ 1 + self.__hdr_fields__.index(name) ] = format
	#	logger.debug("new headerformat was set: %s" % self.__hdr_fmt__)
	#	# format has changed, update needed
	#	self.__update_fmtstr()

	def __update_fmtstr(self):
		"""Update header format string (+field status, +header length) using fields whose value
		are not None."""
		st = object.__getattribute__(self, "__hdr_fields__")
		fields_not_none = []
		hdr_fmt_tmp = [ self.__hdr_fmt__[0] ]	# byte-order is set via first character

		# we need to preserve the order of formats / fields
		for idx, field in enumerate(st):
			val = object.__getattribute__(self, field)
			if val is None:
				continue
			#logger.debug("NOT none: %s" % field)
			fields_not_none += [field]
			# Three options:
			# - value bytes			-> add given format
			# - value TriggerList
			#	- type Packet		-> a TriggerList of packets, reassemble formats
			#	- other Type		-> type of dynamic headers, call "reassemble" and use format "s"
			#logger.debug("format update with field/type/val: %s/%s/%s" % (field, type(val), val))
			if isinstance(val, (bytes, int, float)):			# bytes/int/float
				hdr_fmt_tmp += [ self.__hdr_fmt__[1 + idx] ]	# skip byte-order character
			elif isinstance(val, TriggerList):
				if isinstance(val[0], Packet):				# Packet
					for p in val:
						hdr_fmt_tmp += [p.get_formatstr()[1:]]	# skip byte-order character
				elif isinstance(val[0], tuple):				# tuple
					hdr_fmt_tmp += ["%ds" % len(val.pack_cb())]
				else:
					raise Error("Invalid value in TriggerList, check headers! type/val = %s/%s" % (type(val[0]), val[0]))
			else:
				raise Error("Invalid value found, check headers! type/val = %s/%s" % (type(val), val))

		hdr_fmt_tmp = "".join(hdr_fmt_tmp)

		#logger.debug("updated formatstring, format/not_none: %s/%s" % (hdr_fmt_tmp, fields_not_none))
		# update header info, avoid circular dependencies
		object.__setattr__(self, "__hdr_fields_not_none__", fields_not_none)
		object.__setattr__(self, "__hdr_fmtstr__", hdr_fmt_tmp)
		object.__setattr__(self, "__hdr_len__", struct.calcsize(hdr_fmt_tmp))

	def get_formatstr(self):
		"""Get the current format-string of the full header."""
		return self.__hdr_fmtstr__

	def _set_bodyhandler(self, obj, track_changes=False):
		"""Set handler to decode the actual body data using the given obj
		and make it accessible via layername.addedtype like ethernet.ip.
		If obj is None any handler will be reset and data will be set to an
		empty byte-array.
		"""
		try:
			#if obj is not None or not isinstance(obj, pypacker.Packet):
			# allow None handler and handler extended from Packet
			if obj is not None and not isinstance(obj, pypacker.Packet):
				raise Error("can't set handler which is not a Packet")
			last_cb = None
			# remove previous handler and switch over the callback
			if self.bodytypename is not None:
				last_cb =  getattr(self, self.bodytypename).callback
				delattr(self, self.bodytypename)
			# switch (handler=obj, data=None) to (handler=None, data=b'')
			if obj is None:
				object.__setattr__(self, "bodytypename", None)
				# avoid (data=None, handler=None)
				if self.data is None:
					object.__setattr__(self, "data", b"")
			else:
				# associate ip, arp etc with handler-instance to call "ether.ip", "ip.tcp" etc
				object.__setattr__(self, "bodytypename", obj.__class__.__name__.lower())
				# copy over callback from last handler
				# this is needed for handler-changes like: IP/TCP -> IP/UDP
				# to avoid this the callback must be set explicitly AFTER concatination
				if last_cb is not None:
					obj.callback = last_cb
				object.__setattr__(self, self.bodytypename, obj)
				object.__setattr__(self, "data", None)
		except (KeyError, pypacker.UnpackError):
			logger.warning("pypacker _set_bodyhandler except")
		
		# new body handler means body data changed
		object.__setattr__(self, "body_changed", True)

	def bin(self):
		"""Convert header and body to a byte-array."""
		#logger.debug(">>> BIN: %s" % self)
		# full header bytes
		header_bin = self.pack_hdr()
		# don't mind if this data is a handler: it will be reset itself
		self.__reset_changed()

		# body is raw data, return without change
		if self.bodytypename is None:
			assert self.data is not None	# no raw data AND no Packet as data?
			return header_bin + self.data
		else:
			assert self.data is None	# raw data AND Packet as data?
			# we got a complex type (eg. ip) set via _set_bodyhandler, call bin() itself
			return header_bin + object.__getattribute__(self, self.bodytypename).bin()

	def _changed(self):
		"""Check if this or any upper layer changed in header or body."""
		changed = False

		p_instance = self
		while p_instance is not None:
			if p_instance.header_changed or p_instance.body_changed:
				changed = True
				p_instance = None
			elif p_instance.bodytypename is not None:
				p_instance = object.__getattribute__(p_instance, p_instance.bodytypename)
			else:
				p_instance = None
		return changed

	def __reset_changed(self):
		"""Set the header/body changed-flag to False."""
		object.__setattr__(self, "header_changed", False)
		object.__setattr__(self, "body_changed", False)


	def pack_hdr(self, raw=False):
		"""Return header as byte-string in order of appearance in __hdr_fields__. Header with
		value None will be skipped.
		raw = don't format the values, return them as list."""
		# return cached data if nothing changed
		if not raw and self._header_cached is not None and not self.header_changed:
			#logger.debug(">>>>>>>>>>>>>>>>>> returning cached header: %s->%s" % (self.__class__.__name__, self._header_cached))
			return self._header_cached

		try:
			hdr_bytes = []
			# skip fields with value None
			for field in self.__hdr_fields_not_none__:
				val = object.__getattribute__(self, field)
				# Three options:
				# - value bytes			-> add given format
				# - value TriggerList
				#	- type Packet		-> a TriggerList of packets, reassemble formats
				#	- other Type		-> type of dynamic headers, call "reassemble" and use format "s"
				#logger.debug("packing header with field/type/val: %s/%s/%s" % (field, type(val), val))
				if isinstance(val, (bytes, int, float)):			# bytes/int/float
					hdr_bytes += [ val ]
				elif isinstance(val, TriggerList):
					if isinstance(val[0], Packet):				# Packet
						for p in val:
							hdr_bytes += p.pack_hdr(raw=True)	# list of bytes
					elif isinstance(val[0], tuple):				# tuple
						hdr_bytes += [ val.pack_cb() ]
					else:
						raise Error("Invalid value in TriggerList, check headers! type/val = %s/%s" % (type(val[0]), val[0]))
				else:
					raise Error("Invalid value found, check headers! type/val = %s/%s" % (type(val), val))

			#hdr_bytes = [object.__getattribute__(self, k) for k in self.__hdr_fields_not_none__]
			#logger.debug("header bytes for %s: %s = %s" % (self.__class__.__name__, self.__hdr_fmtstr__, hdr_bytes))
			self._header_cached = struct.pack(self.__hdr_fmtstr__, *hdr_bytes )
			if not raw:
				return self._header_cached
			else:
				return hdr_bytes
		except Error as e:
			logger.warning("error while packing header: %s" % e)

	# TODO: make protected
	def unpack(self, buf):
		"""Unpack/import a full layer using bytes in buf and set all headers
		and data appropriate. This will use the current state of "__hdr_fields_not_none__"
		to set all field values (and skip any with a value of None).
		This can be called multiple times, eg to retrieve data to
		parse dynamic headers afterwards (Note: avoid this for performance reasons)."""
		if len(buf) < self.__hdr_len__:
			raise UnpackError("not enough data to unpack header: %d < %d" % (len(buf), self.__hdr_len__))

		for k, v in zip(self.__hdr_fields_not_none__,
				struct.unpack(self.__hdr_fmtstr__, buf[:self.__hdr_len__])):
			# TODO: Triggerlists must not be overwritten!
			# TODO: performant way to check if value of k is a Triggerlist?
			if type(object.__getattribute__(self, k)) in [bytes, int, float]:
				#logger.debug("initial attribute: %s=%s" % (k, v))
				object.__setattr__(self, k, v)
			else:
				pass
				#logger.debug(">>>> skipping type: %s" % type(object.__getattribute__(self, k)))

		self._header_cached = buf[:self.__hdr_len__]
		# extending class didn't set a handler, set raw data
		if self.bodytypename is None:
			object.__setattr__(self, "data", buf[self.__hdr_len__:])

		#logger.debug("header: %s, body: %s" % (self.__hdr_fmtstr__, self.data))
		# reset the changed-flags: original unpacked = no changes
		self.__reset_changed()


	def __load_handler(cls, glob, class_ref_add, globalvar_prefix, modnames):
		"""Set type-handler callbacks using globals. Given the global var
		XYZ_TYPE (prefix is XYZ_) this will search for (XYZ_)TYPE -> type -> type.py
		in the current directory or appending an optional module prefix.
		Class handler will be saved in "_handler" as _handler[Classname][id] = Class

		glob = globals at the current file
		class_ref_add = ref to the class to update handler
		prefix = prefix of the constant like PREFIX_[FILENAMEOFTYPE]
		modnames = module names to be added like "modname.filenameoftype".
			This must NOT be empty!
		"""
		# avoid RuntimeError because of changing globals -> use copy of globals:
		# fix https://code.google.com/p/pypacker/issues/detail?id=35

		# just call once, skip if allready present
		#print("handler is: %s" % Packet._handler)
		logger.info("loading handler: class/prefix/modnames: %s/%s/%s" % (class_ref_add, globalvar_prefix, modnames))

		try:
			Packet._handler[class_ref_add.__name__]
			logger.info("handler allready loaded: %s (%d)" %
				(class_ref_add, len(Packet._handler[class_ref_add.__name__])))
			return
		except:
			pass

		Packet._handler[class_ref_add.__name__] = {}
		prefix_len = len(globalvar_prefix)
		# get the pypacker module
		#pypacker_obj = getattr(__import__("pypacker", glob), "pypacker")
		#print(vars(pypacker_mod))

		for k, v in glob.items():
			# just globals with specific prefix: [IP_PROTO_]TCP
			if not k.startswith(globalvar_prefix):
				continue

			classname = k[prefix_len:]	# the classname to be loaded uppercase: IP_PROTO_[TCP]
			modname = classname.lower()	# filename of submodule lowercase without ".py": IP_PROTO_[tcp]
			#logger.debug(vars(pypacker_mod))

			# check every given layer
			for pref in modnames:
				#logger.debug("trying to import %s.%s.%s" % (pref, modname, classname))

				try:
					# get module and then inner Class and assign it to dict
					# this will trigger imports itself
					mod = __import__("%s.%s" % (pref, modname), globals(), [], [classname])
					logger.debug("got module: %s" % mod)
					clz = getattr(mod, classname)
#					logger.debug("adding class as handler: [%s][%s][%s]" % (class_ref_add.__class__.__name__, v, clz))
					logger.debug("adding class as handler: [%s][%s][%s]" % (class_ref_add.__name__, v, clz))
					# UDP_PROTO_[dns] = 54
					if type(v) != list:
						Packet._handler[class_ref_add.__name__][v] = clz
					else:
						# TCP_PROTO_[http] = [80, 8080]
						logger.debug("got list for handler-loading: %s -> %s" % (clz, v))
						for vk in v:
							#logger.debug("list: %s -> %s" % (vk, clz))
							Packet._handler[class_ref_add.__name__][vk] = clz
							
					logger.info("loaded: %s" % classname)
					# successfully loaded class, continue with next given global var
					break
				except ImportError as e:
					#logger.debug(e)
					# don't care if not loaded
					pass

	load_handler = classmethod(__load_handler)


class TriggerList(list):
	"""List with trigger-capabilities for static list-based and dynamic headers.
	Calls a given trigger "format_cb" whenever a value is added/set/removed and
	tracks those changes.
	Static header:
	Use Packets after adding all relevant headers. Changes to format eg via "add_headerfield"
	aren't allowed after adding. Only changes to values will be tracked by this TriggerList.
	Dynamic header:
	Use immutables tuples to define headers like ("key", "value")."""
	def __init__(self, lst=[]):
		self.__cached_result = None
		self.packet = None
		self.format_cb = None

		# add this TriggerList as change-listeners to new packets
		if len(lst) > 0 and isinstance(lst[0], Packet):
			for l in lst:
				l.add_change_listener(self.__notify_change)	

		super().__init__(lst)			

	def __iadd__(self, k):
		super().__iadd__(k)
		self.__handle_mod(k)
		return self

	def __delitem__(self, k):
		o = self[k]
		super().__delitem__(k)
		o.remove_change_listener(self.__notify_change)
		self.__format()

	def __setitem__(self, k, v):
		# TODO: remove old listener on overwriting?
		#logger.debug("setting item")
		super().__setitem__(k, v)
		self.__handle_mod(v)

	def __handle_mod(self, val):
		"""Do some sanity checks and needed configurations on
		modifitcations: add listener, update format"""
		if isinstance(val, Packet):
			val.add_change_listener(self.__notify_change)
		#elif type(val) is tuple:
		#	pass
		#else:
		#	raise Exception("Attempt to set a non-Packet/tuple as header: %s/%s" % (type(val), val))
		self.__format()
			
	def __notify_change(self, obj):
		"""Called by Packet on changes which affect header-values."""
		self.packet.header_changed = True

	def __format(self):
		"""Called on changes which affect the format."""
		# new format = old cached value is invalid
		self.__cached_result = None

		try:
			self.packet.header_changed = True
			self.format_cb()
		except:
			#logger.debug("no callback was set: %s/%s" % (self.packet, self.format_cb))
			pass

	def pack_cb(self):
		if self.__cached_result is None:
			self.__cached_result = self.pack()

		return self.__cached_result

	def pack(self):
		"""This must be overwritten to pack dynamic headerfields."""
		pass

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

try:
	import dnet
	def in_cksum_add(s, buf):
		return dnet.ip_cksum_add(buf, s)
	def in_cksum_done(s):
		return socket.ntohs(dnet.ip_cksum_carry(s))
except ImportError:
	import array
	def in_cksum_add(s, buf):
		n = len(buf)
		#logger.debug("buflen for checksum: %d" % n)
		cnt = int(n / 2) * 2
		#logger.debug("slicing at: %d, %s" % (cnt, type(cnt)))
		a = array.array("H", buf[:cnt])
		#logger.debug("2-byte values: %s" % a)
		#logger.debug(buf[-1].to_bytes(1, byteorder='big'))

		if cnt != n:
			a.append(struct.unpack("H", buf[-1].to_bytes(1, byteorder="big") + b"\x00")[0])
			##a.append(buf[-1].to_bytes(1, byteorder="big") + b"\x00")
		return s + sum(a)
	def in_cksum_done(s):
		# add carry to sum itself
		s = (s >> 16) + (s & 0xffff)
		s += (s >> 16)
		# return complement of sums
		return socket.ntohs(~s & 0xffff)

def in_cksum(buf):
	"""Return computed Internet Protocol checksum."""
	return in_cksum_done(in_cksum_add(0, buf))
