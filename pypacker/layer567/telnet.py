"""Telnet."""

from .. import pypacker

import struct


IAC	= 255	# interpret as command:
DONT	= 254	# you are not to use option
DO	= 253	# please, you use option
WONT	= 252	# I won"t use option
WILL	= 251	# I will use option
SB	= 250	# interpret as subnegotiation
GA	= 249	# you may reverse the line
EL	= 248	# erase the current line
EC	= 247	# erase the current character
AYT	= 246	# are you there
AO	= 245	# abort output--but let prog finish
IP	= 244	# interrupt process--permanently
BREAK	= 243	# break
DM	= 242	# data mark--for connect. cleaning
NOP	= 241	# nop
SE	= 240	# end sub negotiation
EOR	= 239	# end of record (transparent mode)
ABORT	= 238	# Abort process
SUSP	= 237	# Suspend process
xEOF	= 236	# End of file: EOF is already used...

SYNCH	= 242	# for telfunc calls

class Telnet(pypacker.Packet):
	__hdr__ = (
		)

	def _unpack(self, buf):
                telnet_tl = TelnetTriggerList(buf)
                self._add_headerfield("telnet_data", "", telnet_tl)

                pypacker.Packet._unpack(self, buf)


class TelnetTriggerList(pypacker.TriggerList):
	def __init__(self, buf):
		"""Init the TriggerList representing the Telnet data
		as tuples parsed from a byte-string."""
		super().__init__([])
		if len(buf) == 0:
			#logger.debug("empty buf 1")
			return

		off = 0
		t_len = len(buf)

		TELNET_OPTION_START	= b"\xff\xaa"
		TELNET_OPTION_END	= b"\xff\x00"
		
		# parse telnet data:
		# fffaXX = start of options
		# fff0 = end of options
		while off < t_len:
			if buf[off : off+2] == TELNET_OPTION_START:
				# add start marker
				self.append(buf[off : off+3])
				off += 3
				# find end of option
				idx_end = buf.find(TELNET_OPTION_END, off)
				# add option data
				self.append( buf[off : idx_end+1] )
				# add end marker
				self.append(TELNET_OPTION_END)
				off = idx_end + 2
			else:
				# add command
				self.append(buf[off : off+3])
				off += 3


def strip_options(buf):
	"""Return a list of lines and dict of options from telnet data."""
	l = buf.split(struct.pack("B", IAC))
	#print l
	b = []
	d = {}
	subopt = False
	for w in l:
		if not w:
			continue
		o = w[0]
		if o > SB:
			#print "WILL/WONT/DO/DONT/IAC", `w`
			w = w[2:]
		elif o == SE:
			#print "SE", `w`
			w = w[1:]
			subopt = False
		elif o == SB:
			#print "SB", `w`
			subopt = True
			for opt in (b"USER", b"DISPLAY", b"TERM"):
				p = w.find(opt + b"\x01")
				if p != -1:
					d[opt] = w[p + len(opt) + 1:].split(b"\x00", 1)[0]
			w = None
		elif subopt:
			w = None
		if w:
			w = w.replace(b"\x00", b"\n").splitlines()
			if not w[-1]: w.pop()
			b.extend(w)
	return b, d
