# $Id: esp.py 23 2006-11-08 15:45:33Z dugsong $

"""Encapsulated Security Protocol."""

import pypacker as pypacker

class ESP(pypacker.Packet):
	__hdr__ = (
		("spi", "I", 0),
		("seq", "I", 0)
		)
