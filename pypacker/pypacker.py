# $Id: pypacker.py 43 2007-08-02 22:42:59Z jon.oberheide $

"""Simple packet creation and parsing."""

import copy
import itertools
import socket
import struct
import logging
import pypacker

logging.basicConfig(format='%(levelname)s (%(funcName)s): %(message)s')
#logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.DEBUG)
logger = logging.getLogger("pypacker")
#logger.setLevel(logging.INFO)
logger.setLevel(logging.DEBUG)


class Error(Exception): pass
class UnpackError(Error): pass
class NeedData(UnpackError): pass
class PackError(Error): pass


class MetaPacket(type):
	def __init__(cls, name, bases, dic):
		print("__INIT__")
		type.__init__(cls, name, bases, dic)

	"""This Metaclass is a more efficient way of setting attributes than
	using __init__. This is done
	by reading name / format / default out of __hdr__ in every subclass.
	This configuration is set one time when loading the module (not
	at instatiation). Every new instance will share the same values.
	A default of None means: skip this field per default.
	This can be changed by setting not-None values in "unpack()" of an
	extending class using "self.key = ''" BEFORE calling the super implementation.
	Actual values are retrieved using "obj.field" notation.
	More complex fields like TCP-options need their own parsing
	in sub-classes.

	TODO: check if header-switches are needed in different cases eg ABC -> ACB
	"""
	def __new__(cls, clsname, clsbases, clsdict):
		print("MetaPacket __new__: %s" % clsname)
		t = type.__new__(cls, clsname, clsbases, clsdict)
		# get header-infos from subclass
		st = getattr(t, '__hdr__', None)

		if st is not None:
			logger.debug("loading meta for: %s" % clsname)
			# XXX - __slots__ only created in __new__()
			clsdict['__slots__'] = [ x[0] for x in st ] + [ 'data' ]
			t = type.__new__(cls, clsname, clsbases, clsdict)
			# set fields for name/format/default
			t.__hdr_fields__ = [ x[0] for x in st ]				# all header field names
#			t.__hdr_fmt__ = getattr(t, '__byte_order__', '>') + \
#				# skip format if default value is None
#				''.join([ x[1] if x[2] not None else pass for x in st ])
			t.__hdr_fmt__ = [ getattr(t, '__byte_order__', '>')]		# all header formats including byte order
			fmt_str_not_none_list = [ getattr(t, '__byte_order__', '>')]
			t.__hdr_fields_not_none__ = []					# track fields with value None for performance reasons

			for x in st:
				logger.debug("meta: %s -> %s" % (x[0], x[2]))
				setattr(t, x[0], x[2])					# make header fields accessible
				t.__hdr_fmt__ += [x[1]]

				if x[2] is not None:
					fmt_str_not_none_list += [x[1]]
					t.__hdr_fields_not_none__ += [x[0]]

			logger.debug("format/not none: %s/%s" % (fmt_str_not_none_list, t.__hdr_fields_not_none__))

			t.__hdr_fmtstr__ = "".join(fmt_str_not_none_list)		# current formatstring without None values as string for convenience
#			t.__hdr_defaults__ = dict(list(zip(
#				t.__hdr_fields__, [ x[2] for x in st ])))
			t.__hdr_len__ = struct.calcsize(t.__hdr_fmtstr__)
			
			# body as raw byte-array
			t.data = b''
			# name of the attribute which holds the object which represents the body
			t.bodytypename = None
			# callback for other layers
			t.callback = None
			# track changes to header and data. Layers like TCP need this eg for checksum-recalculation
			# TODO: to be implemented
			# set to "True" on __set_attribute(), set to False on "__str__()" or "bin()"
			t.packet_changed = False
		return t

class Packet(object, metaclass=MetaPacket):
	"""Base packet class, with metaclass magic to generate members from
	self.__hdr__. This class can be instatiated via:

		Packet(byte_array)
		Packet(key1=val1, key2=val2, ...)

	Requirements:
		- Auto-decoding of static headers via given format-patterns
		- Enable/disable specific header fields (optional fields)
		- Add dynamic header fields
		- Header formats can't be updated (neither static nore dynamic ones)
		- Access of fields via "layer1.key" notation
		- Concatination via "layer1/layer2"
			Note: layer1 could save wrong information about layer2
			like type information in ethernet. This won't be checked.
		- Ability to check for relation to other layers via "is_related()"
		- Generic callback for rare cases eg where upper layer needs
			to know about lower ones (like TCP->IP for checksum calculation)

	Every packet got an optional header and an optional body.
	Body-data can be raw byte-array OR a packet itself
	which stores the data. The following schema illustrates the structure of a Packet:

	Packet structure
	================
	[headerfield1]
	[headerfield2]
	[headerfield13]
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
	header value, eg VLAN in ethernet) or dynamic (update via "_add_hdrfield",
	eg TCP-options)	header-fields. The full header MUST be defined using __hdr__
	or _add_hdrfield() after finishing "unpack" in the extending class.

	Call-flow:
	==========
		pypacker(__init__) -auto calls-> sub(unpack): manipulate if needed (set values
			for static fields, add fields via "_add_headerfield()", set data handler)
			-manually call-> pypacker(parse all header fields and set data) -> ...

		without overwriting unpack in sub:
		pypacker(__init__) -auto calls-> pypacker(parse static parts)


	All data up to the transport layer should be auto decoded like
		e = Ethernet(raw_data) # get tcp via e.ip.tcp, will be None if not present
	Higher layers should be accessed via
		http = Http(tcp.data)
	Exceptionally a callback can be used for backward signaling this purposes.
	The following methods must be called in Packet itself via pypacker.Packet.xyz() if overwritten:
		unpack()
		__setattr__()
	
	Example::

	>>> class Foo(Packet):
	...	  __hdr__ = (('foo', 'I', 1), ('bar', 'H', 2), ('baz', '4s', 'quux'))
	...
	>>> foo = Foo(bar=3)
	>>> foo
	Foo(bar=3)
	>>> str(foo)
	'\x00\x00\x00\x01\x00\x03quux'
	>>> foo.bar
	3
	>>> foo.baz
	'quux'
	>>> foo.foo = 7
	>>> foo.baz = 'whee'
	>>> foo
	Foo(baz='whee', foo=7, bar=3)
	>>> Foo(b'hello, world!')
	Foo(baz=' wor', foo=1751477356L, bar=28460, data='ld!')
	"""

	"""Dict for saving body datahandler globaly: { Classname : {id : HandlerClass} }"""
	_handler = {}

	def __init__(self, *args, **kwargs):
		"""Packet constructor with ([buf], [field=val,...]) prototype.

		Arguments:

		buf -- optional packet buffer to unpack as bytes

		Optional keyword arguments correspond to members to set
		(matching fields in self.__hdr_fields__ or Packet ref-name as data).
		"""
		if args:
			# buffer given: use it to set header fields and body data
			logger.debug("Packet args: %s" % args[0])
			# Don't allow empty buffer, we got the headerfield-constructor for that.
			# Allowing default-values giving empty buffer would lead to confusion:
			# there is no way do disambiguate "no body" from "default value set".
			# So in a nutshell: empty buffer = (data=b'', bodyhandler=None)
			if len(args[0]) == 0:
				raise NeedData("empty buffer given, nothing to unpack!")

			try:
				# this is called on the extended class if present
				# which can enable/disable static fields and add optional ones
				self.unpack(args[0])
			except struct.error:
				if len(args[0]) < self.__hdr_len__:
					raise NeedData
				raise UnpackError('invalid %s: %r' % (self.__class__.__name__, args[0]))
		else:
		# n headerfields given to set (n >= 0)
			logger.debug("Packet no args")
			# set default attributes
			#for k in self.__hdr_fields__:
			#	object.__setattr__(self, k, copy.copy(self.__hdr_defaults__[k]))
			# additional parameters given, those can overwrite the class-based attributes
			for k, v in kwargs.items():
				object.__setattr__(self, k, v)

	def __len__(self):
		"""Return total (= header + data) length in bytes."""
		# no need to call sub-handler if there is a handler and no raw data
		return self.__hdr_len__ + \
			(len(self.data) if self.data is not None else \
			len(object.__getattribute__(self, self.bodytypename))
			)

	def hdrlen(self):
		"""Return header length in bytes."""
		return self.__hdr_len__

	def __setattr__(self, k, v, update_fmt=True):
		"""Set value of an attribute a via "a.k=v". Track changes to fields for later packing."""
		# the following assumption must be fullfilled: (handler=obj, data=None) OR (handler=None, data=b'')
		if k is not "data":
			if k in self.__hdr_fields__:
				oldval = object.__getattribute__(self, k)
				object.__setattr__(self, k, v)

				# changes which affect format
				if v is None and oldval is not None or \
				v is not None and oldval is None:
					logger.debug("format update needed: %s->%s" % (k, v))
					self.__update_fmtstr()
			else:
				object.__setattr__(self, k, v)
		else:
			#logger.debug("data, type: %s/%s" % (self.data, self.bodytypename))
			if v is None and self.bodytypename is None:
				raise Error("attempt to set data to None on layer without handler: %s:%s, %s" % (k, v, self.bodytypename))
			else:
				# switch from (handler=obj, data=None) to (handler=None, data=b'')
				# or (handler=None, data=b'A') to (handler=None, data=b'A')
				if v is not None and self.bodytypename is not None:
					self._set_bodyhandler(None)
				#logger.debug("setting new raw data: %s (type=%s)" % (v, self.bodytypename))
				object.__setattr__(self, k, v)

		# TODO: reset on output
		object.__setattr__(self, "packet_changed", True)


	def __truediv__(self, v):
		"""Handle concatination of layers like "ethernet/ip/tcp. Every "A/B" operation
		will set B as the deepest handler of A and return A: this will return the top Packet 
		given like "ethernet/ip/tcp -> ethernet, ..ip/tcp -> ethernet"""
		logger.debug("div called: %s/%s" % (self.__class__.__name__, v.__class__.__name__, ))

		if type(v) is bytes:
			raise Error("Can not concat bytes")
		# get deepest handler from this
		hndl_deep = self

		while hndl_deep is not None:
			if hndl_deep.bodytypename is not None:
				hndl_deep = object.__getattribute__(hndl_deep, hndl_deep.bodytypename)
			else:
				break

		hndl_deep._set_bodyhandler(v)
		return self

	def __repr__(self):
		"""Unique represention of this packet."""
		l = [ '%s=%r' % (k, object.__getattribute__(self, k))
			for k in self.__hdr_fields__]
		if self.data:
			l.append('data=%r' % self.data)
		return '%s(%s)' % (self.__class__.__name__, ', '.join(l))


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
		"""Append a new (dynamic) header field to the current defined list of headers.
		Optional header fields are not stored in __hdr__ but can be accessed
		via "obj.attrname" after all.
		"""
		# Update internal header data. This won't break anything because
		# all field-informations are allready initialized via metaclass.
		self.__hdr_fields__ += [name]
		self.__hdr_fmt__ += [format]
		object.__setattr__(self, name, value)

		# fields with value None won't change format string
		if value is not None:
			self.__update_fmtstr()

	def __update_fmtstr(self):
		"""Update header format string using fields whose value are not None.
		take __hdr_fields__ and not __hdr__: optional headers could have been added"""
		st = getattr(self, '__hdr_fields__', None)
		fields_not_none = []
		hdr_fmt_tmp = [ self.__hdr_fmt__[0] ]	# byte-order is set via first character

		# we need to preserve the order of formats / fields
		for idx, field in enumerate(st):
			if object.__getattribute__(self, field) is not None:
				#logger.debug("NOT none: %s" % field)
				fields_not_none += [field]
				hdr_fmt_tmp += [ self.__hdr_fmt__[1 + idx] ]	# skip byte-order character

		hdr_fmt_tmp = "".join(hdr_fmt_tmp)

		logger.debug("updated formatstring: %s/%s" % (hdr_fmt_tmp, fields_not_none))
		# update header info, avoid circular dependencies
		object.__setattr__(self, "hdr_fields_not_none", fields_not_none)
		object.__setattr__(self, "hdr_fmtstr", hdr_fmt_tmp)
		object.__setattr__(self, "hdr_len", struct.calcsize(hdr_fmt_tmp))
		
	def _set_bodyhandler(self, obj):
		"""Set handler to decode the actual body data using the given obj
		and make it accessible via layername.addedtype like ethernet.ip.
		If obj is None any handler will be reset and data will be set to an
		empty byte-array.
		The following assumption is true for the first three layers:
			layer1(layer1_layer2_data) == layer1(layer1_data) / layer2(layer2_data)
		"""
		try:
			#if obj is not None or not isinstance(obj, pypacker.Packet):
			# allow None handler and handler extended from Packet
			if obj is not None and not isinstance(obj, pypacker.Packet):
				raise Error("can't set handler which is not a Packet")
			callbackimpl_tmp = None
			# remove previous handler
			if self.bodytypename is not None:
				callbackimpl_tmp =  getattr(self, self.bodytypename).callback
				delattr(self, self.bodytypename)
			# switch (handler=obj, data=None) to (handler=None, data=b'')
			if obj is None:
				object.__setattr__(self, "bodytypename", None)
				# avoid (data=None, handler=None)
				if self.data is None:
					object.__setattr__(self, "data", b"")
				# handler was removed, nothing to do here anymore
				return
			# associate ip, arp etc with handler-instance to call "ether.ip", "ip.tcp" etc
			object.__setattr__(self, "bodytypename", obj.__class__.__name__.lower())
			obj.callback = callbackimpl_tmp
			object.__setattr__(self, self.bodytypename, obj)
			object.__setattr__(self, "data", None)
		except (KeyError, pypacker.UnpackError):
			logger.warning("pypacker _set_bodyhandler except")

	def bin(self):
		"""Convert header and body to a byte-array."""
		#logger.debug(">>> BIN: %s" % self)
		# full header bytes, skip fields with value None
		header_bin = b""
		# TODO: more performant
		header_bin = self.pack_hdr()

		# body is raw data, return without change
		if self.bodytypename is None:
			assert self.data is not None	# no raw data AND no Packet as data?
			return header_bin + self.data
		else:
			assert self.data is None	# data AND Packet as data?
			# we got a complex type (eg. ip) set via _set_bodyhandler, call bin() itself
			hndlr = object.__getattribute__(self, self.bodytypename)
			return header_bin + hndlr.bin()


	def pack_hdr(self):
		"""Return header as hex-represenation like \x00\x01\x02.
		Headers ar added in order of appearance in __hdr_fields__. Header with
		value None will be skipped."""
		try:
			# skip fields with value None
			hdr_bytes = [object.__getattribute__(self, k) for k in self.__hdr_fields_not_none__]
			logger.debug("header bytes for %s: %s = %s" % (self.__class__.__name__, self.__hdr_fmtstr__, hdr_bytes))
			return struct.pack(self.__hdr_fmtstr__, *hdr_bytes )
		except Error as e:
			logger.warning("error while packing header: %s (trying plan B)" % e)
			vals = []

			for k in self.__hdr_fields_not_none__:
				v = getattr(self, k)
				if isinstance(v, tuple):
					vals.extend(v)
				else:
					vals.append(v)
				#format.append()

			try: # EAFP: this is likely to work
				return struct.pack(self.__hdr_fmtstr__, vals)
			except Error as e:
				raise PackError(str(e))

	def pack(self):
		"""Pack/export packed header + data as hexstring."""
		return str(self)

	def unpack(self, buf):
		"""Unpack/import a full layer using bytes in buf and set all headers
		and data appropriate. This will use the current state of "__hdr_fields__"
		to set all field values and skip any with a value of None.
		This can be called multiple times, eg to retrieve data to
		parse dynamic headers afterwards (Note: avoid this for performance reasons)."""
		for k, v in zip(self.__hdr_fields_not_none__,
				struct.unpack(self.__hdr_fmtstr__, buf[:self.__hdr_len__])):
			object.__setattr__(self, k, v)

		# extending class didn't set a handler, set raw data
		if self.bodytypename is None:
			object.__setattr__(self, "data", buf[self.__hdr_len__:])

		logger.debug("header: %s, body: %s" % (self.__hdr_fmtstr__, self.data))


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
		# avoid RuntimeError because of changing globals.
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
		pypacker_obj = getattr(__import__("pypacker", glob), "pypacker")
		#print(vars(pypacker_mod))

		for k, v in glob.items():
			if not k.startswith(globalvar_prefix):
				continue

			classname = k[prefix_len:]	# the classname to be loaded (uppercase)
			modname = classname.lower()	# filename of submodule (lowercase without ".py")
			#logger.debug(vars(pypacker_mod))
			#return

			for pref in modnames:
				#logger.debug("trying to import %s.%s.%s" % (pref, modname, classname))

				try:
					#mod = __import__("pypacker.%s.%s" % (pref, modname), glob)
					#print(vals(mod))
					# get module and then inner Class and assign it to dict
					# this will trigger imports itself
					mod = __import__("%s.%s" % (pref, modname), globals(), [], [classname])
					logger.debug("got module: %s" % mod)
					clz = getattr(mod, classname)
#					logger.debug("adding class as handler: [%s][%s][%s]" % (class_ref_add.__class__.__name__, v, clz))
					logger.debug("adding class as handler: [%s][%s][%s]" % (class_ref_add.__name__, v, clz))
					Packet._handler[class_ref_add.__name__][v] = clz
					logger.info("loaded: %s" % classname)
					# successfully loaded class, continue with next given global var
					break
				except ImportError as e:
					#logger.debug(e)
					# don't care if not loaded
					pass

	load_handler = classmethod(__load_handler)

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
		hexa = ' '.join(['%02x' % ord(x) for x in line])
		line = line.translate(__vis_filter)
		res.append('  %04d:	 %-*s %s' % (n, length * 3, hexa, line))
		n += length
	return '\n'.join(res)

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
		cnt = int((n / 2) * 2)
		#logger.debug("slicing at: %d, %s" % (cnt, type(cnt)))
		a = array.array('H', buf[:cnt])
		#logger.debug("2-byte values: %s" % a)

		if cnt != n:
			#a.append(struct.unpack('H', buf[-1] + '\x00')[0])
			a.append(buf[-1] + "\x00")
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
