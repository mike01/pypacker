import struct
import logging

logger = logging.getLogger("pypacker")

FIELD_FLAG_AUTOUPDATE	= 1
FIELD_FLAG_IS_TYPEFIELD	= 2


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
		Set value for a simple field

		value -- bytes, int or None
		"""
		if obj._unpacked is not None and not obj._unpacked:
			# obj._unpacked = None means: dissect not yet finished
			obj._unpack()
		if value is None and obj.__getattribute__(varname_shadowed + "_active"):
			# deactivate active field
			object.__setattr__(obj, varname_shadowed + "_active", False)
			obj._header_format_changed = True
			# logger.debug("deactivating field: %s" % varname_shadowed)
		elif value is not None and not obj.__getattribute__(varname_shadowed + "_active"):
			# activate inactive field
			object.__setattr__(obj, varname_shadowed + "_active", True)
			obj._header_format_changed = True
			# logger.debug("activating field: %s" % varname_shadowed)

		if value is not None and not is_field_static:
			# simple dynamic field: update format
			format_new = "%ds" % len(value)
			# logger.debug(">>> changing format for dynamic field: %r / %s / %s" %
			# (obj.__class__, varname_shadowed, format_new))
			object.__setattr__(obj, varname_shadowed + "_format", format_new)
			obj._header_format_changed = True

		#logger.debug("setting simple field: %r=%r" % (varname_shadowed, value))
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
			tl = obj._header_fields_dyn_dict[varname_shadowed](obj,
							dissect_callback=tl[1],
							buffer=tl[0],
							headerfield_name=varname_shadowed)
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
		# logger.debug("getting simple field: %r=%r" %
		# (varname_shadowed, obj.__getattribute__(varname_shadowed)))
		return obj.__getattribute__(varname_shadowed)

	def getfield_triggerlist(obj):
		tl = obj.__getattribute__(varname_shadowed)
		# logger.debug(">>> getting Triggerlist for %r: %r" % (obj.__class__, tl))

		if type(tl) is list:
			# _triggerlistName = [b"bytes", callback] or
			# _triggerlistName = [b"", callback] (default initiation)
			tl = obj._header_fields_dyn_dict[varname_shadowed](obj,
							dissect_callback=tl[1],
							buffer=tl[0],
							headerfield_name=varname_shadowed)
			object.__setattr__(obj, varname_shadowed, tl)

		return tl

	if is_field_type_simple:
		return getfield_simple
	else:
		return getfield_triggerlist


def configure_packet_header(t, hdrs, header_fmt):
	if hdrs is None:
		return

	# Create a property for every field: property a -> get/set access to _a_shadowed.
	# Using properties will slow down access to header fields but it's needed:
	# This way we get informed about get-access (needed to check for unpack)
	# more efficiently than using __getattribute__ (slow access for header
	# fields vs. slow access for ALL class members).
	for hdr in hdrs:
		# every header field will get two additional values set:
		# var_active = indicates if header is active
		# var_format = indicates the header format
		if len(hdr) > 4:
			logger.warning("field definition length > 4: %s has length %d", hdr[0], len(hdr))

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
			# ("name", None, [None, b"xxx"]) = dynamic
			# -> Format given = static, Format None = dynamic
			is_field_type_simple = True

			if hdr[1] is None:
				# assume simple dynamic field
				is_field_static = False

		setattr(t, shadowed_name + "_format", hdr[1])

		if is_field_type_simple:
			# assume simple static or simple dynamic type
			fmt = hdr[1]

			if hdr[2] is not None:
				# value given: field is active
				if fmt is None:
					# dynamic field
					fmt = "%ds" % len(hdr[2])
					setattr(t, shadowed_name + "_format", fmt)
				header_fmt.append(fmt)
				t._header_cached.append(hdr[2])
				# logger.debug("--------> field is active: %r" % hdr[0])
			else:
				setattr(t, shadowed_name + "_active", False)

			# only simple fields can get deactivated
			setattr(t, shadowed_name + "_active", True if hdr[2] is not None else False)

			# check for auto-update
			if len(hdr) == 4:
				field_flags = hdr[3]

				if field_flags & FIELD_FLAG_IS_TYPEFIELD != 0:
					#logger.debug("setting _id_fieldname: %r" % (hdr[0]))
					setattr(t, "_id_fieldname", hdr[0])
					# xxx__au_active must be set: read by _update_bodyhandler_id
					field_flags |= FIELD_FLAG_AUTOUPDATE

				if field_flags & FIELD_FLAG_AUTOUPDATE != 0:
					#logger.debug("marking %s as auto-update" % hdr[0])
					# remember which fields are auto-update ones, default is active
					setattr(t, hdr[0] + "_au_active", True)

			# set initial value via shadowed variable:
			# _varname <- varname [optional in subclass: <- varname_s]
			# setting/getting value is done via properties.
			# logger.debug("init simple type: %s=%r" % (shadowed_name, hdr[2]))
			setattr(t, shadowed_name, hdr[2])
			setattr(t, hdr[0], property(
					get_getter(hdr[0], is_field_type_simple=True),
					get_setter(hdr[0], is_field_type_simple=True,
						is_field_static=is_field_static)
				)
					)
		else:
			# assume TriggerList
			# Triggerlists don't have initial default values (and can't get deactivated)
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


def configure_packet_header_sub(t, hdrs_sub):
	if hdrs_sub is None:
		return

	for name_cbget_cbset in hdrs_sub:
		if len(name_cbget_cbset) < 2:
			logger.warning("subheader length < 2: %d", len(name_cbget_cbset))
			continue
		# logger.debug("setting subheader: %s", name_cbget_cbset[0])

		# (name, cb_get, cb_set)
		if len(name_cbget_cbset) == 3:
			setattr(t, name_cbget_cbset[0], property(name_cbget_cbset[1], name_cbget_cbset[2]))
		# (name, cb_get)
		else:
			setattr(t, name_cbget_cbset[0], property(name_cbget_cbset[1]))


class MetaPacket(type):
	"""
	This Metaclass is a more efficient way of setting attributes than using __init__.
	This is done by reading name, format and default value out of a mendatory __hdr__
	tuple in every subclass. This configuration is set one time when loading the module
	(not at instantiation). Attributes can be normally accessed using "obj.field" notation.
	General note: Callflaw is: __new__ (loading module) -> __init__ (initiate class)

	Header defintition example:
	__hdr__ = (
		("header1", "H", 123), # simple static field
		("header2", "H", None), # simple static field, inactive
		("header3", None, b"xxx"), # simple dynamic field
		("header4", None, None), # simple dynamic field, inactive
		("header5", None, Triggerlist) # TriggerList field
	)

	For values <1 byte a subheader definition eases up setting/getting those values:

	__hdr_sub__ = (
		("header1_sub",
			lambda val: val & 1							# callback to retrieve value
			lambda obj, val: obj.__setattr__(val & 1)	# callback to set value
		),
		...
	)

	CAUTION:
	- List et al are _SHARED_ among all instantiated classes! A copy is needed on
	changes to them without side effects
	- New protocols: header field names must be unique among other variable and method names
	"""
	@staticmethod
	def configure_slots(dct, bases, clsname):
		is_packet_class = True if clsname == "Packet" and bases[0] == object\
			else False
		#return
		if is_packet_class:
			print("Packet class? %r %r" % (bases, clsname))
			# static members (eg properties) are not affected
			vars = {
				"_header_fields_dyn_dict", "_header_cached", "_header_field_names", "_header_format_order",
				"_id_fieldname", "_header_format", "_header_len", "_header_format_changed",
				"_header_cached", "_body_bytes", "_bodytypename", "_lower_layer",
				"_header_changed", "_body_changed", "_changelistener", "_lazy_handler_data",
				"_target_unpack_clz", "_unpacked", "_fragmented", "_errors"
			}
		else:
			print("No Packet class? %r %r" % (bases, clsname))
			vars = set()

		for dct_hdr_names in ["__hdr__", "__hdr_sub__"]:
			header_names_tuples = dct.get(dct_hdr_names, tuple())

			for tpl in header_names_tuples:
				varname = tpl[0]
				#print("init name: %r" % varname)
				vars.add("_%s" % varname)
				vars.add("_%s_active" % varname)
				vars.add("_%s_format" % varname)

		dct["__slots__"] = tuple(var for var in vars)
		print(dct["__slots__"])

	def __new__(mcs, clsname, clsbases, clsdict):
		# Slots can't be used because:
		# Setting default values (eg for _header_fields_dyn_dict) must
		# be done in __init__ which increases delay (init for every instantiation...)
		# Sidenote: Setting default values here creates readonly exception later:
		# __slots__ = ("var", ...) -> t.var = None -> p = Clz() -> p.var = 123 won't work (var is readonly)
		# See: https://stackoverflow.com/questions/820671/python-slots-and-attribute-is-read-only
		#MetaPacket.configure_slots(clsdict, clsbases, clsname)
		t = type.__new__(mcs, clsname, clsbases, clsdict)
		# dictionary of TriggerLists: name -> TriggerListClass
		t._header_fields_dyn_dict = {}
		# cache header for performance reasons, will be set to bytes later on
		t._header_cached = []
		# all header names
		t._header_field_names = []
		t._header_format_order = getattr(t, "__byte_order__", ">")
		# all header formats including byte order
		header_fmt = [t._header_format_order]

		# varname holding the fieldname containing the id associated with body handler
		# eg Ethernet -> "type" or IP -> "p"
		t._id_fieldname = None

		# get header-infos: [("name", "format", value), ...]
		hdrs = getattr(t, "__hdr__", None)
		configure_packet_header(t, hdrs, header_fmt)

		# get sub-header-infos: [("name", cb_get, cb_set), ...]
		hdrs_sub = getattr(t, "__hdr_sub__", None)
		configure_packet_header_sub(t, hdrs_sub)

		# get handler classes, assume Packet class has no member "__handler__"
		handler = getattr(t, "__handler__", None)

		if handler is not None and len(handler) > 0:
			if handler.__class__ is not dict:
				print("Invalid format of __handler__: not a dictionary! %r", handler)
			else:
				t.load_handler(t, handler)

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
		# needs to be None do identify none-initialized variable
		# TODO: use sets here
		t._changelistener = None
		# lazy handler data: [name, class, bytes]
		t._lazy_handler_data = None
		# Indicates the most top layer until which should be unpacked
		# (vs. lazy dissecting = just next upper layer)
		# Setting this to an unknown class will keep the next-layer-parsing going on
		t._target_unpack_clz = None
		# inicates if static header values got already unpacked
		# [True|False] = Status after dissect, None = pre-dissect (not unpacked)
		t._unpacked = None
		# indicates if this packet contains fragmented data saved as body bytes
		t._fragmented = False
		# concatination of errors, see pypacker.py -> ERROR_...
		t._errors = 0
		return t
