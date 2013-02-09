# $Id: 80211.py 53 2008-12-18 01:22:57Z jon.oberheide $

"""IEEE 802.11."""

import pypacker as pypacker
import socket, struct

class IEEE80211(pypacker.Packet):
	__hdr__ = (
		('framectl', 'H', 0),
		('duration', 'H', 0)
		)

	def _get_version(self): return (self.framectl & _VERSION_MASK) >> _VERSION_SHIFT
	def _set_version(self, val): self.framectl = (val << _VERSION_SHIFT) | (self.framectl & ~_VERSION_MASK)
	def _get_type(self): return (self.framectl & _TYPE_MASK) >> _TYPE_SHIFT
	def _set_type(self, val): self.framectl = (val << _TYPE_SHIFT) | (self.framectl & ~_TYPE_MASK)
	def _get_subtype(self): return (self.framectl & _SUBTYPE_MASK) >> _SUBTYPE_SHIFT
	def _set_subtype(self, val): self.framectl = (val << _SUBTYPE_SHIFT) | (self.framectl & ~_SUBTYPE_MASK)
	def _get_to_ds(self): return (self.framectl & _TO_DS_MASK) >> _TO_DS_SHIFT
	def _set_to_ds(self, val): self.framectl = (val << _TO_DS_SHIFT) | (self.framectl & ~_TO_DS_MASK)
	def _get_from_ds(self): return (self.framectl & _FROM_DS_MASK) >> _FROM_DS_SHIFT
	def _set_from_ds(self, val): self.framectl = (val << _FROM_DS_SHIFT) | (self.framectl & ~_FROM_DS_MASK)
	def _get_more_frag(self): return (self.framectl & _MORE_FRAG_MASK) >> _MORE_FRAG_SHIFT
	def _set_more_frag(self, val): self.framectl = (val << _MORE_FRAG_SHIFT) | (self.framectl & ~_MORE_FRAG_MASK)
	def _get_retry(self): return (self.framectl & _RETRY_MASK) >> _RETRY_SHIFT
	def _set_retry(self, val): self.framectl = (val << _RETRY_SHIFT) | (self.framectl & ~_RETRY_MASK)
	def _get_pwr_mgt(self): return (self.framectl & _PWR_MGT_MASK) >> _PWR_MGT_SHIFT
	def _set_pwr_mgt(self, val): self.framectl = (val << _PWR_MGT_SHIFT) | (self.framectl & ~_PWR_MGT_MASK)
	def _get_more_data(self): return (self.framectl & _MORE_DATA_MASK) >> _MORE_DATA_SHIFT
	def _set_more_data(self, val): self.framectl = (val << _MORE_DATA_SHIFT) | (self.framectl & ~_MORE_DATA_MASK)
	def _get_wep(self): return (self.framectl & _WEP_MASK) >> _WEP_SHIFT
	def _set_wep(self, val): self.framectl = (val << _WEP_SHIFT) | (self.framectl & ~_WEP_MASK)
	def _get_order(self): return (self.framectl & _ORDER_MASK) >> _ORDER_SHIFT
	def _set_order(self, val): self.framectl = (val << _ORDER_SHIFT) | (self.framectl & ~_ORDER_MASK)

	version = property(_get_version, _set_version)
	type = property(_get_type, _set_type)
	subtype = property(_get_subtype, _set_subtype)
	to_ds = property(_get_to_ds, _set_to_ds)
	from_ds = property(_get_from_ds, _set_from_ds)
	more_frag = property(_get_more_frag, _set_more_frag)
	retry = property(_get_retry, _set_retry)
	pwr_mgt = property(_get_pwr_mgt, _set_pwr_mgt)
	more_data = property(_get_more_data, _set_more_data)
	wep = property(_get_wep, _set_wep)
	order = property(_get_order, _set_order)

	def unpack_ies(self, buf):
		self.ies = []

		ie_decoder = {
		IE_SSID:	('ssid',	self.IE),
		IE_RATES:	('rate',	self.IE),
		IE_FH:		('fh',		self.FH),
		IE_DS:		('ds',		self.DS),
		IE_CF:		('cf',		self.CF),
		IE_TIM:		('tim',		self.TIM),
		IE_IBSS:	('ibss',	self.IBSS),
		IE_HT_CAPA:	('ht_capa', self.IE),
		IE_ESR:		('esr',		self.IE),
		IE_HT_INFO:	('ht_info', self.IE)
		}

		# each IE starts with an ID and a length
		while len(buf):
			ie_id = struct.unpack('B',(buf[0]))[0]
			try:
				parser = ie_decoder[ie_id][1]
				name = ie_decoder[ie_id][0] 
			except KeyError:
				parser = self.IE
				name = 'ie_' + str(ie_id)
			ie = parser(buf)

			ie.data = buf[2:2+ie.len]
			setattr(self, name, ie)
			self.ies.append(ie)
			buf = buf[2+ie.len:]

	class Capability:
		def __init__(self, field):
			self.ess = field & 1
			self.ibss = (field >> 1) & 1
			self.cf_poll = (field >> 2) & 1
			self.cf_poll_req = (field >> 3) & 1
			self.privacy = (field >> 4) & 1
			self.short_preamble = (field >> 5) & 1
			self.pbcc = (field >> 6) & 1
			self.hopping = (field >> 7) & 1
			self.spec_mgmt = (field >> 8) & 1
			self.qos = (field >> 9) & 1
			self.short_slot = (field >> 10) & 1
			self.apsd = (field >> 11) & 1
			self.dsss = (field >> 13) & 1
			self.delayed_blk_ack = (field >> 14) & 1
			self.imm_blk_ack = (field >> 15) & 1

	def unpack(self, buf):
		pypacker.Packet.unpack(self, buf)
		self.data = buf[self.__hdr_len__:]

		m_decoder = {
			M_BEACON:	('beacon',		self.Beacon),
			M_ASSOC_REQ:	('assoc_req',	self.Assoc_Req),
			M_ASSOC_RESP:	('assoc_resp',	self.Assoc_Resp),
			M_DISASSOC:	('diassoc',		self.Disassoc),
			M_REASSOC_REQ:	('reassoc_req', self.Reassoc_Req),
			M_REASSOC_RESP: ('reassoc_resp',self.Assoc_Resp),
			M_AUTH:		('auth',		self.Auth),
			M_PROBE_RESP:	('probe_resp',	self.Beacon),
			M_DEAUTH:	('deauth',		self.Deauth)
		}

		c_decoder = {
			C_RTS:		('rts',			self.RTS),
			C_CTS:		('cts',			self.CTS),
			C_ACK:		('ack',			self.ACK),
			C_BLOCK_ACK_REQ:('bar',			self.BlockAckReq),
			C_BLOCK_ACK:	('back',		self.BlockAck)
		}

		d_dsData = {
			0		:	self.Data,
			FROM_DS_FLAG	:	self.DataFromDS,
			TO_DS_FLAG	:	self.DataToDS,
			INTER_DS_FLAG	:	self.DataInterDS
		}


		# For now decode everything with DATA. Haven't checked about other QoS
		# additions
		d_decoder = {
			# modified the decoder to consider the ToDS and FromDS flags
			# Omitting the 11 case for now
			D_DATA:		('data_frame',	d_dsData),
			D_NULL:		('data_frame',	d_dsData),
			D_QOS_DATA:	('data_frame',	d_dsData),
			D_QOS_NULL:	('data_frame',	d_dsData)
		}

		decoder = {
			MGMT_TYPE:m_decoder,
			CTL_TYPE:c_decoder,
			DATA_TYPE:d_decoder
		}

		if self.type == MGMT_TYPE:
			self.mgmt = self.MGMT_Frame(self.data)
			self.data = self.mgmt.data
			if self.subtype == M_PROBE_REQ:
				self.unpack_ies(self.data)
				return
			if self.subtype == M_ATIM:
				return

		try:
			parser = decoder[self.type][self.subtype][1]
			name = decoder[self.type][self.subtype][0]
		except KeyError:
			print("Key error:", self.type, self.subtype)
			return

		if self.type == DATA_TYPE:
			# need to grab the ToDS/FromDS info
			parser = parser[self.to_ds*10+self.from_ds]

		if self.type == MGMT_TYPE:
			field = parser(self.mgmt.data)
		else:
			field = parser(self.data)
			self.data = field

		setattr(self, name, field)

		if self.type == MGMT_TYPE:
			self.ies = self.unpack_ies(field.data)
			if self.subtype == M_BEACON or self.subtype == M_ASSOC_RESP or\
				self.subtype == M_ASSOC_REQ or self.subtype == M_REASSOC_REQ:
				self.capability = self.Capability(socket.ntohs(field.capability))

		if self.type == DATA_TYPE and self.subtype == D_QOS_DATA:
			self.qos_data = self.QoS_Data(field.data)
			field.data = self.qos_data.data

		self.data = field.data

	class BlockAckReq(pypacker.Packet):
		__hdr__ = (
			('ctl', 'H', 0),
			('seq', 'H', 0),
			)

	class BlockAck(pypacker.Packet):
		__hdr__ = (
			('ctl', 'H', 0),
			('seq', 'H', 0),
			('bmp', '128s', '\x00' *128)
			)

	class RTS(pypacker.Packet):
		__hdr__ = (
			('dst', '6s', '\x00' * 6),
			('src', '6s', '\x00' * 6)
			)

	class CTS(pypacker.Packet):
		__hdr__ = (
			('dst', '6s', '\x00' * 6),
			)

	class ACK(pypacker.Packet):
		__hdr__ = (
			('dst', '6s', '\x00' * 6),
			)

	class MGMT_Frame(pypacker.Packet):
		__hdr__ = (
			('dst', '6s', '\x00' *6),
			('src', '6s', '\x00' *6),
			('bssid', '6s', '\x00' *6),
			('frag_seq', 'H', 0)
			)

	class Beacon(pypacker.Packet):
		__hdr__ = (
			('timestamp', 'Q', 0),
			('interval', 'H', 0),
			('capability', 'H', 0)
			)

	class Disassoc(pypacker.Packet):
		__hdr__ = (
			('reason', 'H', 0),
			)

	class Assoc_Req(pypacker.Packet):
		__hdr__ = (
			('capability', 'H', 0),
			('interval', 'H', 0)
			)

	class Assoc_Resp(pypacker.Packet):
		__hdr__ = (
			('capability', 'H', 0),
			('status', 'H', 0),
			('aid', 'H', 0)
			)

	class Reassoc_Req(pypacker.Packet):
		__hdr__ = (
			('capability', 'H', 0),
			('interval', 'H', 0),
			('current_ap', '6s', '\x00'*6)
			)

	# This obviously doesn't support any of AUTH frames that use encryption
	class Auth(pypacker.Packet):
		__hdr__ = (
			('algorithm', 'H', 0),
			('auth_seq', 'H', 0),
			)

	class Deauth(pypacker.Packet):
		__hdr__ = (
			('reason', 'H', 0),
			)

	class Data(pypacker.Packet):
		__hdr__ = (
			('dst', '6s', '\x00'*6),
			('src', '6s', '\x00'*6),
			('bssid', '6s', '\x00'*6),
			('frag_seq', 'H', 0)
			)


	class DataFromDS(pypacker.Packet):
		__hdr__ = (
			('dst', '6s', '\x00'*6),
			('bssid', '6s', '\x00'*6),
			('src', '6s', '\x00'*6),
			('frag_seq', 'H', 0)
			)


	class DataToDS(pypacker.Packet):
		__hdr__ = (
			('bssid', '6s', '\x00'*6),
			('src', '6s', '\x00'*6),
			('dst', '6s', '\x00'*6),
			('frag_seq', 'H', 0)
			)

	class DataInterDS(pypacker.Packet):
		__hdr__ = (
			('dst', '6s', '\x00'*6),
			('src', '6s', '\x00'*6),
			('da', '6s', '\x00'*6),
			('frag_seq', 'H', 0),
			('sa', '6s', '\x00'*6)
			)

	class QoS_Data(pypacker.Packet):
		__hdr__ = (
			('control', 'H', 0),
			)

	class IE(pypacker.Packet):
		__hdr__ = (
			('id', 'B', 0),
			('len', 'B', 0)
			)
		def unpack(self, buf):
			pypacker.Packet.unpack(self, buf)
			self.info = buf[2:self.len+ 2]

	class FH(pypacker.Packet):
		__hdr__ = (
			('id', 'B', 0),
			('len', 'B', 0),
			('tu', 'H', 0),
			('hopset', 'B', 0),
			('hoppattern', 'B', 0),
			('hopindex', 'B', 0)
			)

	class DS(pypacker.Packet):
		__hdr__ = (
			('id', 'B', 0),
			('len', 'B', 0),
			('ch', 'B', 0)
			)

	class CF(pypacker.Packet):
		__hdr__ = (
			('id', 'B', 0),
			('len', 'B', 0),
			('count', 'B', 0),
			('period', 'B', 0),
			('max', 'H', 0),
			('dur', 'H', 0)
			)

	class TIM(pypacker.Packet):
		__hdr__ = (
			('id', 'B', 0),
			('len', 'B', 0),
			('count', 'B', 0),
			('period', 'B', 0),
			('ctrl', 'H', 0)
			)
		def unpack(self, buf):		 
			pypacker.Packet.unpack(self, buf)
			self.bitmap = buf[5:self.len+ 2]

	class IBSS(pypacker.Packet):
		__hdr__ = (
			('id', 'B', 0),
			('len', 'B', 0),
			('atim', 'H', 0) 
			)

# Frame Types
MGMT_TYPE		= 0
CTL_TYPE		= 1
DATA_TYPE		= 2

# Frame Sub-Types
M_ASSOC_REQ		= 0
M_ASSOC_RESP		= 1
M_REASSOC_REQ		= 2
M_REASSOC_RESP		= 3
M_PROBE_REQ		= 4
M_PROBE_RESP		= 5
M_DISASSOC		= 10
M_AUTH			= 11
M_DEAUTH		= 12
M_BEACON		= 8
M_ATIM			= 9
C_BLOCK_ACK_REQ		= 8
C_BLOCK_ACK		= 9
C_PS_POLL		= 10
C_RTS			= 11
C_CTS			= 12
C_ACK			= 13
C_CF_END		= 14
C_CF_END_ACK		= 15
D_DATA			= 0
D_DATA_CF_ACK		= 1
D_DATA_CF_POLL		= 2
D_DATA_CF_ACK_POLL	= 3
D_NULL			= 4
D_CF_ACK		= 5
D_CF_POLL		= 6
D_CF_ACK_POLL		= 7
D_QOS_DATA		= 8
D_QOS_CF_ACK		= 9
D_QOS_CF_POLL		= 10
D_QOS_CF_ACK_POLL	= 11
D_QOS_NULL		= 12
D_QOS_CF_POLL_EMPTY	= 14

TO_DS_FLAG		= 10
FROM_DS_FLAG		= 1
INTER_DS_FLAG		= 11

# Bitshifts for Frame Control
_VERSION_MASK		= 0x0300
_TYPE_MASK		= 0x0c00
_SUBTYPE_MASK		= 0xf000
_TO_DS_MASK		= 0x0001
_FROM_DS_MASK		= 0x0002
_MORE_FRAG_MASK		= 0x0004
_RETRY_MASK		= 0x0008
_PWR_MGT_MASK		= 0x0010
_MORE_DATA_MASK		= 0x0020
_WEP_MASK		= 0x0040
_ORDER_MASK		= 0x0080
_VERSION_SHIFT		= 8
_TYPE_SHIFT		= 10
_SUBTYPE_SHIFT		= 12
_TO_DS_SHIFT		= 0
_FROM_DS_SHIFT		= 1
_MORE_FRAG_SHIFT	= 2
_RETRY_SHIFT		= 3
_PWR_MGT_SHIFT		= 4
_MORE_DATA_SHIFT	= 5
_WEP_SHIFT		= 6
_ORDER_SHIFT		= 7

# IEs
IE_SSID			= 0
IE_RATES		= 1
IE_FH			= 2
IE_DS			= 3
IE_CF			= 4
IE_TIM			= 5
IE_IBSS			= 6
IE_HT_CAPA		= 45
IE_ESR			= 50
IE_HT_INFO		= 61
