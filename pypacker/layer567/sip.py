"""Session Initiation Protocol."""

import pypacker as pypacker
from pypacker.layer567 import http

class SIP(http.HTTP):
	pass
