"""
Controller Area Network, ISO 11898-1, see https://en.wikipedia.org/wiki/CAN_bus
SocketCAN message format handling

API examples:
https://github.com/rhyttr/SocketCAN/tree/3c46872d9af0885b42526b70853400c6d94b7c54/can-utils
"""

from pypacker import pypacker
from pypacker import triggerlist

import logging
import struct

logger = logging.getLogger("pypacker")
pack_I = struct.Struct(">I").pack
unpack_I_n = struct.Struct("=I").unpack
unpack_H = struct.Struct(">H").unpack

"""
OBDII modes:

01 	Show current data
02 	Show freeze frame data
03 	Show stored Diagnostic Trouble Codes
04 	Clear Diagnostic Trouble Codes and stored values
05 	Test results, oxygen sensor monitoring (non CAN only)
06 	Test results, other component/system monitoring (Test results, oxygen sensor monitoring for CAN only)
07 	Show pending Diagnostic Trouble Codes (detected during current or last driving cycle)
08 	Control operation of on-board component/system
09 	Request vehicle information
0A 	Permanent Diagnostic Trouble Codes (DTCs) (Cleared DTCs)
"""

OBD2_MODE_SHOW_CURRENT_DATA			= 0x01
OBD2_MODE_SHOWFREEZE_DATA			= 0x02
OBD2_MODE_SHOW_STORED_TROUBLECODES		= 0x03
OBD2_MODE_CLEAR_DIAGNOSTIC_TROUBLECODES		= 0x04
OBD2_MODE_TEST_RESULTS_OXYGEN			= 0x05
OBD2_MODE_TEST_RESULTS_OTHER			= 0x06
OBD2_MODE_SHOW_PENDING_DIAGNOSTIC_TROUBLECODES	= 0x07
OBD2_MODE_CONTROL_OPERATION			= 0x08
OBD2_MODE_REQUEST_VEHICLE_INFO			= 0x09
OBD2_MODE_PERMANENT_DIAGNOSTIC_TROUBLECODES	= 0x0A


OBD2_MODE_DESCR = {
	OBD2_MODE_SHOW_CURRENT_DATA			: "OBD2_MODE_SHOW_CURRENT_DATA",
	OBD2_MODE_SHOWFREEZE_DATA			: "OBD2_MODE_SHOW_CURRENT_DATA",
	OBD2_MODE_SHOW_STORED_TROUBLECODES		: "OBD2_MODE_SHOW_STORED_TROUBLECODES",
	OBD2_MODE_CLEAR_DIAGNOSTIC_TROUBLECODES		: "OBD2_MODE_CLEAR_DIAGNOSTIC_TROUBLECODES",
	OBD2_MODE_TEST_RESULTS_OXYGEN			: "OBD2_MODE_TEST_RESULTS_OXYGEN",
	OBD2_MODE_TEST_RESULTS_OTHER			: "OBD2_MODE_TEST_RESULTS_OTHER",
	OBD2_MODE_SHOW_PENDING_DIAGNOSTIC_TROUBLECODES	: "OBD2_MODE_SHOW_PENDING_DIAGNOSTIC_TROUBLECODES",
	OBD2_MODE_CONTROL_OPERATION			: "OBD2_MODE_CONTROL_OPERATION",
	OBD2_MODE_REQUEST_VEHICLE_INFO			: "OBD2_MODE_REQUEST_VEHICLE_INFO",
	OBD2_MODE_PERMANENT_DIAGNOSTIC_TROUBLECODES	: "OBD2_MODE_PERMANENT_DIAGNOSTIC_TROUBLECODES"
}

# Diagnostic and Communications Management
UDS_SID_DIAGNOSTIC_SESSION_CONTORL	= 0x10
UDS_SID_ECU_RESET			= 0x11
UDS_SID_SECURITY_ACCESS			= 0x27
UDS_SID_COMMUNICATION_CONTROL		= 0x28
UDS_SID_TESTER_PRESENT			= 0x3E
UDS_SID_SECURED_TRANSMISSION		= 0x84
UDS_SID_CONTORL_DTC_SETTING		= 0x85
UDS_SID_RESPONSE_ON_EVENT		= 0x86
UDS_SID_LINK_CONTORL			= 0x87
# Data Transmission
UDS_SID_READ_DATA_BY_ID			= 0x22
UDS_SID_READ_MEMORY_BY_ADDRESS		= 0x23
UDS_SID_READ_SCALING_DATA_BY_ID		= 0x24
UDS_SID_READ_DATA_BY_PERIODIC_ID	= 0x2A
UDS_SID_DYNAMICALLY_DEFINE_DATA_ID	= 0x2C
UDS_SID_WRITE_DATA_BY_ID		= 0x2E
UDS_SID_WRITE_MEMORY_BY_ADDRESS		= 0x3D
# Stored Data Transmission
UDS_SID_CLEAR_DIAGNOSTIC_INFORMATION	= 0x14
UDS_SID_READ_DTC_INFORMATION		= 0x19
# Input/Output Control
UDS_SID_IO_CONTORL_BY_ID		= 0x2F
# Remote Activation of Routine
UDS_SID_ROUTINE_CONTROL			= 0x31
# Upload/Download
UDS_SID_REQUEST_DOWNLOAD		= 0x34
UDS_SID_REQUEST_UPLOAD			= 0x35
UDS_SID_TRANSFER_DATA			= 0x36
UDS_SID_REQUEST_TANSFER_EXIT		= 0x37
UDS_SID_REQUEST_FILE_TRANSFER		= 0x38

UDS_SID_DESCR = {
	UDS_SID_DIAGNOSTIC_SESSION_CONTORL	: "UDS_SID_DIAGNOSTIC_SESSION_CONTORL",
	UDS_SID_ECU_RESET			: "UDS_SID_ECU_RESET",
	UDS_SID_SECURITY_ACCESS			: "UDS_SID_SECURITY_ACCESS",
	UDS_SID_COMMUNICATION_CONTROL		: "UDS_SID_COMMUNICATION_CONTROL",
	UDS_SID_TESTER_PRESENT			: "UDS_SID_TESTER_PRESENT",
	UDS_SID_SECURED_TRANSMISSION		: "UDS_SID_SECURED_TRANSMISSION",
	UDS_SID_CONTORL_DTC_SETTING		: "UDS_SID_CONTORL_DTC_SETTING",
	UDS_SID_RESPONSE_ON_EVENT		: "UDS_SID_RESPONSE_ON_EVENT",
	UDS_SID_LINK_CONTORL			: "UDS_SID_LINK_CONTORL",
	UDS_SID_READ_DATA_BY_ID			: "UDS_SID_READ_DATA_BY_ID",
	UDS_SID_READ_MEMORY_BY_ADDRESS		: "UDS_SID_READ_MEMORY_BY_ADDRESS",
	UDS_SID_READ_SCALING_DATA_BY_ID		: "UDS_SID_READ_SCALING_DATA_BY_ID",
	UDS_SID_READ_DATA_BY_PERIODIC_ID	: "UDS_SID_READ_DATA_BY_PERIODIC_ID",
	UDS_SID_DYNAMICALLY_DEFINE_DATA_ID	: "UDS_SID_DYNAMICALLY_DEFINE_DATA_ID",
	UDS_SID_WRITE_DATA_BY_ID		: "UDS_SID_WRITE_DATA_BY_ID",
	UDS_SID_WRITE_MEMORY_BY_ADDRESS		: "UDS_SID_WRITE_MEMORY_BY_ADDRESS",
	UDS_SID_CLEAR_DIAGNOSTIC_INFORMATION	: "UDS_SID_CLEAR_DIAGNOSTIC_INFORMATION",
	UDS_SID_READ_DTC_INFORMATION		: "UDS_SID_READ_DTC_INFORMATION",
	UDS_SID_IO_CONTORL_BY_ID		: "UDS_SID_IO_CONTORL_BY_ID",
	UDS_SID_ROUTINE_CONTROL			: "UDS_SID_ROUTINE_CONTROL",
	UDS_SID_REQUEST_DOWNLOAD		: "UDS_SID_REQUEST_DOWNLOAD",
	UDS_SID_REQUEST_UPLOAD			: "UDS_SID_REQUEST_UPLOAD",
	UDS_SID_TRANSFER_DATA			: "UDS_SID_TRANSFER_DATA",
	UDS_SID_REQUEST_TANSFER_EXIT		: "UDS_SID_REQUEST_TANSFER_EXIT",
	UDS_SID_REQUEST_FILE_TRANSFER		: "UDS_SID_REQUEST_FILE_TRANSFER"
}

# UDS = 0x7F [SID_requested] [NRC]
UDS_NRC_GENERAL_REJECT				= 0x10
UDS_NRC_SERVICE_NOT_SUPPORTED			= 0x11
UDS_NRC_SUBFUNCTION_NOT_SUPPORTED		= 0x12
UDS_NRC_INCORRECT_MESSAGE_LENGTH_OR_FORMAT	= 0x13
UDS_NRC_RESPONSE_TOO_BIG			= 0x14
UDS_NRC_BUSY_REPEAT_REQUEST			= 0x21
UDS_NRC_CONDITION_NOT_CORRECT			= 0x22
UDS_NRC_REQUEST_SEQUENCE_ERROR			= 0x24
UDS_NRC_NONRESPONSE_FROM_SUBNET_COMPONENT	= 0x25
UDS_NRC_FAILURE_PREVENTS_EXEC_OR_ACTION		= 0x26
UDS_NRC_REQUEST_OUT_OF_RANGE			= 0x31
UDS_NRC_SECURITY_ACCESS_DENIED			= 0x33
UDS_NRC_INVALID_KEY				= 0x35
UDS_NRC_EXCEEDED_NUMBER_OF_ATTEMPTS		= 0x36
UDS_NRC_REQUIRED_TIME_DELEAY_NOT_EXPIRED	= 0x37
UDS_NRC_UPLOAD_DOWNLOAD_NOT_ACCEPTED		= 0x70
UDS_NRC_TRANSFER_DATA_SUSPENDED			= 0x71
UDS_NRC_GENERAL_PROGRAMMING_FAILURE		= 0x72
UDS_NRC_WRONG_BLOCK_SEQUENCE_COUNTER		= 0x73
UDS_NRC_REQUEST_CORRECTLY_RESPONSE_PENDING	= 0x78
UDS_NRC_SUBFUNCTION_NOT_SUPPORTED_IN_SESSION	= 0x7E
UDS_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION	= 0x7F


UDS_NRC_DESCR = {
	UDS_NRC_GENERAL_REJECT				: "UDS_NRC_GENERAL_REJECT",
	UDS_NRC_SERVICE_NOT_SUPPORTED			: "UDS_NRC_SERVICE_NOT_SUPPORTED",
	UDS_NRC_SUBFUNCTION_NOT_SUPPORTED		: "UDS_NRC_SUBFUNCTION_NOT_SUPPORTED",
	UDS_NRC_INCORRECT_MESSAGE_LENGTH_OR_FORMAT	: "UDS_NRC_INCORRECT_MESSAGE_LENGTH_OR_FORMAT",
	UDS_NRC_RESPONSE_TOO_BIG			: "UDS_NRC_RESPONSE_TOO_BIG",
	UDS_NRC_BUSY_REPEAT_REQUEST			: "UDS_NRC_BUSY_REPEAT_REQUEST",
	UDS_NRC_CONDITION_NOT_CORRECT			: "UDS_NRC_CONDITION_NOT_CORRECT",
	UDS_NRC_REQUEST_SEQUENCE_ERROR			: "UDS_NRC_REQUEST_SEQUENCE_ERROR",
	UDS_NRC_NONRESPONSE_FROM_SUBNET_COMPONENT	: "UDS_NRC_NONRESPONSE_FROM_SUBNET_COMPONENT",
	UDS_NRC_FAILURE_PREVENTS_EXEC_OR_ACTION		: "UDS_NRC_FAILURE_PREVENTS_EXEC_OR_ACTION",
	UDS_NRC_REQUEST_OUT_OF_RANGE			: "UDS_NRC_REQUEST_OUT_OF_RANGE",
	UDS_NRC_SECURITY_ACCESS_DENIED			: "UDS_NRC_SECURITY_ACCESS_DENIED",
	UDS_NRC_INVALID_KEY				: "UDS_NRC_INVALID_KEY",
	UDS_NRC_EXCEEDED_NUMBER_OF_ATTEMPTS		: "UDS_NRC_EXCEEDED_NUMBER_OF_ATTEMPTS",
	UDS_NRC_REQUIRED_TIME_DELEAY_NOT_EXPIRED	: "UDS_NRC_REQUIRED_TIME_DELEAY_NOT_EXPIRED",
	UDS_NRC_UPLOAD_DOWNLOAD_NOT_ACCEPTED		: "UDS_NRC_UPLOAD_DOWNLOAD_NOT_ACCEPTED",
	UDS_NRC_TRANSFER_DATA_SUSPENDED			: "UDS_NRC_TRANSFER_DATA_SUSPENDED",
	UDS_NRC_GENERAL_PROGRAMMING_FAILURE		: "UDS_NRC_GENERAL_PROGRAMMING_FAILURE",
	UDS_NRC_WRONG_BLOCK_SEQUENCE_COUNTER		: "UDS_NRC_WRONG_BLOCK_SEQUENCE_COUNTER",
	UDS_NRC_REQUEST_CORRECTLY_RESPONSE_PENDING	: "UDS_NRC_REQUEST_CORRECTLY_RESPONSE_PENDING",
	UDS_NRC_SUBFUNCTION_NOT_SUPPORTED_IN_SESSION	: "UDS_NRC_SUBFUNCTION_NOT_SUPPORTED_IN_SESSION",
	UDS_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION	: "UDS_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION"
}


class OBD2(pypacker.Packet):
	__hdr__ = (
		("mode", "B", 0),
		("pid", "B", 0)
	)


class UDS(pypacker.Packet):
	__hdr__ = (
		("sid", "B", 0),
		("lev", "B", 0)
	)

	def _dissect(self, buf):
		# TODO: lev not always present
		return 2


ISOTP_TYPE_SF	= 0x00  # single frame
ISOTP_TYPE_FF	= 0x01  # first frame
ISOTP_TYPE_CF	= 0x02  # consecutive frame
ISOTP_TYPE_FC	= 0x03  # flow control


types_isotp_offset_upper = {
	ISOTP_TYPE_SF: 1,
	ISOTP_TYPE_FF: 2,
	ISOTP_TYPE_CF: 1,
	ISOTP_TYPE_FC: 3
}

types_isotp_offset_upper_got_type = set([ISOTP_TYPE_SF, ISOTP_TYPE_FF])


class ISOTPBase(pypacker.Packet):
	def __get_sig(self):
		return (self.pci & 0xF0) >> 4

	def __set_sig(self, value):
		self.pci = (value & 0xF) << 4 | (self.pci & 0xF)

	sig = property(__get_sig, __set_sig)

	def _dissect(self, buf):
		#logger.debug("dissect in base class")
		# OBD/UDS can one be differentiated in ISOTP_TYPE_SF and ISOTP_TYPE_FF
		sig = buf[0] >> 4
		#logger.debug("bytes in ISOTP: %r" % buf)
		#logger.debug("ISOTP type: %X, offset: %d" % (sig, types_isotp_offset_upper[sig]))
		#logger.debug("upper bytes: %r" % buf[types_isotp_offset_upper[sig]: ])

		# check by request/response SID, on bith OBD2 and UDS response will be SID+0x40
		if sig in types_isotp_offset_upper_got_type or (sig - 0x40) in types_isotp_offset_upper_got_type:
			obd_mode = buf[types_isotp_offset_upper[sig]]

			if obd_mode in OBD2_MODE_DESCR:
				# assume OBD2
				#logger.debug("got OBD2")
				self._init_handler(0, buf[types_isotp_offset_upper[sig]:])
			else:
				# assume UDS
				#logger.debug("got UDS, will use bytes: %r" % buf[types_isotp_offset_upper[sig]: ])
				self._init_handler(1, buf[types_isotp_offset_upper[sig]:])

		return types_isotp_offset_upper[sig]


class ISOTPSingleFrame(ISOTPBase):
	__hdr__ = (
		("pci", "B", ISOTP_TYPE_SF),
	)

	def __get_dl(self):
		return self.pci & 0xF

	def __set_dl(self, value):
		self.pci = (self.pci & 0xF0) | (value & 0xF)

	dl = property(__get_dl, __set_dl)


class ISOTPFirstFrame(ISOTPBase):
	__hdr__ = (
		("pci", "H", ISOTP_TYPE_FF),
	)

	def __get_sig(self):
		return (self.pci & 0xF000) >> 12

	def __set_sig(self, value):
		self.pci = (value & 0xF) << 12 | (self.pci & 0xFFF)

	sig = property(__get_sig, __set_sig)

	def __get_dl(self):
		return (self.pci & 0xFFF)

	def __set_dl(self, value):
		self.pci = (self.pci & 0xF000) | (value & 0xFFF)

	dl = property(__get_dl, __set_dl)


class ISOTPConsecutiveFrame(ISOTPBase):
	__hdr__ = (
		("pci", "B", ISOTP_TYPE_CF),
	)

	def __get_sn(self):
		return self.pci & 0xF

	def __set_sn(self, value):
		self.pci = (self.pci & 0xF0) | (value & 0xF)

	sn = property(__get_sn, __set_sn)


class ISOTPFlowControl(ISOTPBase):
	__hdr__ = (
		("pci", "B", ISOTP_TYPE_FC),
		("pci_blocksize", "B", 0),
		("pci_minsep", "B", 0),
	)

	def __get_flowstatus(self):
		return self.pci & 0xF

	def __set_flowstatus(self, value):
		self.pci = (self.pci & 0xF0) | (value & 0xF)

	flowstatus = property(__get_flowstatus, __set_flowstatus)

pypacker.Packet.load_handler(ISOTPSingleFrame,
	{0: OBD2, 1: UDS}
)

pypacker.Packet.load_handler(ISOTPFirstFrame,
	{0: OBD2, 1: UDS}
)

pypacker.Packet.load_handler(ISOTPConsecutiveFrame,
	{0: OBD2, 1: UDS}
)

pypacker.Packet.load_handler(ISOTPFlowControl,
	{0: OBD2, 1: UDS}
)

isotp_type_class = {
	ISOTP_TYPE_SF: ISOTPSingleFrame,
	ISOTP_TYPE_FF: ISOTPFirstFrame,
	ISOTP_TYPE_CF: ISOTPConsecutiveFrame,
	ISOTP_TYPE_FC: ISOTPFlowControl
}


class CAN(pypacker.Packet):
	"""
	SocketCan Packet, see https://www.kernel.org/doc/Documentation/networking/can.txt
	Format:


	struct can_frame {
		canid_t can_id;  /* 32 bit CAN_ID + EFF/RTR/ERR flags */
		__u8    can_dlc; /* frame payload length in byte (0 .. 8) */
		__u8    __pad;   /* padding */
		__u8    __res0;  /* reserved / padding */
		__u8    __res1;  /* reserved / padding */
		__u8    data[8] __attribute__((aligned(8)));
	};
	special address description flags for the CAN_ID
		CAN_EFF_FLAG 0x80000000U /* EFF/SFF is set in the MSB */
		CAN_RTR_FLAG 0x40000000U /* remote transmission request */
		CAN_ERR_FLAG 0x20000000U /* error message frame */



	Native CAN structure (on wire):

	CAN lengths (11-bit ID):
	- Arbitration Field (12)
	-- ID: unique id/prio (11)
	-- Remote transmission request: 0/dominant for data, 1 for remote request (1)
	- Control (6)
	-- ID ext.: 0 for 11-bit ID (1)
	-- Reserved: must be 0 (1)
	-- Data length code: Number of bytes, 0 up to 8 (4)
	- Data: 0 up to 8 bytes (8)

	CAN lengths (29-bit ID):
	- Arbitration Field (40)
	-- ID: unique id/prio (11)
	-- Substitute remote request, must be 1 (1)
	-- Identifier extension bit: must be 1 (1)
	-- ID: unique id/prio (18)
	-- Remote transmission request: 0/dominant for data, 1 for remote request (1)
	- Control (6)
	-- Reserved: must be 0 (2)
	-- Data length code: Number of bytes, 0 up to 8 (4)
	- Data: 0 up to 8 bytes (8)

	"""
	__hdr__ = (
		("flag_id", "I", 0),
		("dlc", "B", 0),
		("pad", "B", 0),
		("res1", "B", 0),
		("res2", "B", 0)
	)

	__byte_order__ = "="

	def __get_extended(self):
		return 0 if (self.flag_id & 0x80000000) == 0 else 1

	def __set_extended(self, value):
		self.flag_id |= (value & ~0x80000000) | (value << 3 * 8 + 4 + 3)

	extended = property(__get_extended, __set_extended)

	def __get_rtr(self):
		return 0 if (self.flag_id & 0x40000000) == 0 else 1

	def __set_rtr(self, value):
		self.flag_id |= (value & ~0x40000000) | (value << 3 * 8 + 4 + 2)

	rtr = property(__get_rtr, __set_rtr)

	def __get_err(self):
		return 0 if (self.flag_id & 0x20000000) == 0 else 1

	def __set_err(self, value):
		self.flag_id |= (value & ~0x20000000) | (value << 3 * 8 + 4 + 1)

	err = property(__get_err, __set_err)

	def __get_id(self):
		return self.flag_id & 0x7FFFFFFF

	def __set_id(self, value):
		self.flag_id |= (value & ~0x1FFFFFFF) | value

	id = property(__get_id, __set_id)

	def _dissect(self, buf):
		# assume ISO-TP
		isotp_type = (buf[8] & 0xF0) >> 4
		#logger.debug("got ISOTP type: %d, class will be: %r" % (isotp_type, isotp_type_class[isotp_type]))
		self._init_handler(isotp_type, buf[8:])
		return 8


pypacker.Packet.load_handler(CAN,
	{
		ISOTP_TYPE_SF: ISOTPSingleFrame,
		ISOTP_TYPE_FF: ISOTPFirstFrame,
		ISOTP_TYPE_CF: ISOTPConsecutiveFrame,
		ISOTP_TYPE_FC: ISOTPFlowControl
	}
)
