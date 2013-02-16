import struct

"""Telnet."""

IAC	= 255	# interpret as command:
DONT	= 254	# you are not to use option
DO	= 253	# please, you use option
WONT	= 252	# I won't use option
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

def strip_options(buf):
	"""Return a list of lines and dict of options from telnet data."""
	l = buf.split(struct.pack('B', IAC))
	#print l
	b = []
	d = {}
	subopt = False
	for w in l:
		if not w:
			continue
		o = w[0]
		if o > SB:
			#print 'WILL/WONT/DO/DONT/IAC', `w`
			w = w[2:]
		elif o == SE:
			#print 'SE', `w`
			w = w[1:]
			subopt = False
		elif o == SB:
			#print 'SB', `w`
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
