import logging

logger = logging.getLogger("pypacker")
from_bytes = int.from_bytes


def _get_der_tlv(der_bts):
	off = 0
	tagstart = off
	#logger.debug("tagstart: %d" % tagstart)
	# is_hightag = False
	is_primitive = (der_bts[off] & 0x20) == 0
	#logger.debug("primitive: %r" % is_primitive)

	# high tag number form
	if (der_bts[off] & 0x1F) == 0x1F:
		#logger.debug("got high tag form")
		# is_hightag = True
		off += 1

		while (der_bts[off] & 0x80) != 0:
			off += 1
	off += 1

	lenstart = off
	#logger.debug("lenstart: %d" % lenstart)
	vlen = der_bts[off]
	is_lenshort = (vlen & 0x80) == 0

	if not is_lenshort:
		len_octets = vlen & 0x7F
		lenbts = der_bts[lenstart + 1: lenstart + 1 + len_octets]
		vlen = from_bytes(lenbts, byteorder="big", signed=False)
		#logger.debug("length longform, bytes: %r (%d) = %d" % (lenbts, len_octets, vlen))
		off += len_octets
	off += 1
	valuestart = off
	return lenstart - tagstart, valuestart - lenstart, vlen, is_primitive


def decode_der(der_bts, result=None, extract_cb=None, _firstrun=True, _level=0):
	off = 0
	end = len(der_bts)

	if _firstrun:
		#logger.debug(">>> first run")
		try:
			taglen, lenlen, vlen, prim = _get_der_tlv(der_bts)
		except IndexError:
			result.append(None)
			return
		end = taglen + lenlen + vlen

	while off < end:
		try:
			taglen, lenlen, vlen, prim = _get_der_tlv(der_bts[off:])
		except IndexError:
			result.append(None)
			break

		value = der_bts[off + taglen + lenlen: off + taglen + lenlen + vlen]

		if not prim:
			result_tmp = []
			#logger.debug("sub calling: %d %d %d %d %r" % (off, taglen, lenlen, vlen, _firstrun))
			try:
				decode_der(value, result=result_tmp, extract_cb=extract_cb, _firstrun=False, _level=_level + 1)
			except:
				# None indicates decoding error
				result_tmp = [None]
			value = result_tmp

		result.append([
			der_bts[off: off + taglen],
			der_bts[off + taglen: off + taglen + lenlen],
			value]
		)
		off += (taglen + lenlen + vlen)

	try:
		extract_cb(result)
	except:
		#logger.exception(ex)
		pass
