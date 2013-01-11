# $Id: pmap.py 23 2006-11-08 15:45:33Z dugsong $

"""Portmap / rpcbind."""

from . import pypacker

PMAP_PROG = 100000
PMAP_PROCDUMP = 4
PMAP_VERS = 2

class Pmap(pypacker.Packet):
	__hdr__ = (
		('prog', 'I', 0),
		('vers', 'I', 0),
		('prot', 'I', 0),
		('port', 'I', 0),
		)
