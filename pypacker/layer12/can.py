"""
Controller Area Network, ISO 11898-1, see https://en.wikipedia.org/wiki/CAN_bus
SocketCAN message format handling

API examples:
https://github.com/rhyttr/SocketCAN/tree/3c46872d9af0885b42526b70853400c6d94b7c54/can-utils
"""
import logging
import struct
import sys

from pypacker import pypacker

logger = logging.getLogger("pypacker")
pack_I = struct.Struct(">I").pack
unpack_I_n = struct.Struct("=I").unpack
unpack_H = struct.Struct(">H").unpack

module_this = sys.modules[__name__]


"""
OBDII modes:

01 	Show current data
02 	Show freeze frame data
03 	Show stored Diagnostic Trouble Codes
04 	Clear Diagnostic Trouble Codes and stored values
05 	Test results, oxygen sensor monitoring (non CAN only)
06 	Test results, other component/system monitoring
07 	Show pending Diagnostic Trouble Codes (detected during current or last driving cycle)
08 	Control operation of on-board component/system
09 	Request vehicle information
0A 	Permanent Diagnostic Trouble Codes (DTCs) (Cleared DTCs)
"""


OBD2_MODE_01_PIDS = {
	0x00	: "PIDS_SUPPORTED_1_20",
	0x01	: "MONITOR_STATUS",
	0x02	: "FREEZE_DTC",
	0x03	: "FUEL_SYSTEM_STATUS",
	0x04	: "CALCULATED_ENGINE_LOAD",
	0x05	: "ENGINE_COOLANT_TEMP",
	0x06	: "SHORT_TERM_FUEL_BANK1",
	0x07	: "LONG_TERM_FUEL_BANK1",
	0x08	: "SHORT_TERM_FUEL_BANK2",
	0x09	: "LONG_TERM_FUEK_BANK2",
	0x0A	: "FUELPRESSURE",
	0x0B	: "INTAKE_MANIFOLD_PRESSURE",
	0x0C	: "ENGINE_RPM",
	0x0D	: "VEHICLE_SPEED",
	0x0E	: "TIMING_ADVANCE",
	0x0F	: "INTAKGE_AIR_TEMP",
	0x10	: "MAF_AIR_FLOW",
	0x11	: "THROTTLE_POS",
	0x12	: "COMMANDED_SECONDARY_AIR_STATUS",
	0x13	: "OXYGEN_SENSORS_PRESENT",
	0x14	: "OXYGEN_SENSOR1",
	0x15	: "OXYGEN_SENSOR2",
	0x16	: "OXYGEN_SENSOR3",
	0x17	: "OXYGEN_SENSOR4",
	0x18	: "OXYGEN_SENSOR5",
	0x19	: "OXYGEN_SENSOR6",
	0x1A	: "OXYGEN_SENSOR7",
	0x1B	: "OXYGEN_SENSOR8",
	0x1C	: "OBD_STANDARDS_",
	0x1D	: "OXYGEN_SENSORS",
	0x1E	: "AUXILIARY_INPUT_STATUS",
	0x1F	: "RUNTIME_SINCE_ENGINE",
	0x20	: "PIDS_SUPPORTED_21_40",
	0x21	: "DISTANCE_TRAVELED_WITH_MALFUNCTION",
	0x22	: "FUEL_RAIL_PRESSURE",
	0x23	: "FUEL_RAIL_GAUGE_PRESSURE",
	0x24	: "OXYGEN_SENSOR1",
	0x25	: "OXYGEN_SENSOR2",
	0x26	: "OXYGEN_SENSOR3",
	0x27	: "OXYGEN_SENSOR4",
	0x28	: "OXYGEN_SENSOR5",
	0x29	: "OXYGEN_SENSOR6",
	0x2A	: "OXYGEN_SENSOR7",
	0x2B	: "OXYGEN_SENSOR8",
	0x2C	: "COMMANDED_EGR",
	0x2D	: "EGR_ERROR",
	0x2E	: "COMMANDED_EVAPORATIVE_PURGE",
	0x2F	: "FUEL_TANK_LEVEL_INPUT",
	0x30	: "WARMUPS_SINCE_CODES_CLEARED",
	0x31	: "DISTANCE_TRAVELED_SINCE_CODES_CLEARED",
	0x32	: "EVAP_SYSTEM_VAPOR_PRESSURE",
	0x33	: "ABSOLUTE_BAROMETIC_PRESSURE",
	0x34	: "OXYGEN_SENSOR1_FUELAIR",
	0x35	: "OXYGEN_SENSOR2_FUELAIR",
	0x36	: "OXYGEN_SENSOR3_FUELAIR",
	0x37	: "OXYGEN_SENSOR4_FUELAIR",
	0x38	: "OXYGEN_SENSOR5_FUELAIR",
	0x39	: "OXYGEN_SENSOR6_FUELAIR",
	0x3A	: "OXYGEN_SENSOR7_FUELAIR",
	0x3B	: "OXYGEN_SENSOR8_FUELAIR",
	0x3C	: "CATALYST_TEMP_B1S1",
	0x3D	: "CATALYST_TEMP_B2S1",
	0x3E	: "CATALYST_TEMP_B1S2",
	0x3F	: "CATALYST_TEMP_B2S2",
	0x40	: "PIDS_SUPPORTED_41_60",
	0x41	: "MONITOR_STATUS_",
	0x42	: "CTRL_MODULE_VOLTAGE",
	0x43	: "ABS_LOAD_VALUE",
	0x44	: "FUEL_AIR_COMMANDED",
	0x45	: "RELATIVE_THROTTLE_POS",
	0x46	: "AMBIENT_AIR_TEMP",
	0x47	: "ABSOLUTE_THROTTLE_POS_B",
	0x48	: "ABSOLUTE_THROTTLE_POS_C",
	0x49	: "ABSOLUTE_THROTTLE_POS_D",
	0x4A	: "ABSOLUTE_THROTTLE_POS_E",
	0x4B	: "ABSOLUTE_THROTTLE_POS_F",
	0x4C	: "COMMANDED_THROTTLE_ACTUATOR",
	0x4D	: "TIME_RUN_WITH_MIL",
	0x4E	: "TIME_SINCE_TROUBLE_CODES_CLEARED",
	0x4F	: "MAX_FUEL_AIR_EQ_RATIO",
	0x50	: "MAX_AIR_FLOW",
	0x51	: "FUEL_TYPE",
	0x52	: "ETHANOL_FUEL",
	0x53	: "ABS_EVAP_SYSTEM_VAPOR_PRESSURE",
	0x54	: "EVAP_SYSTEM_VAPOR_PRESSURE",
	0x55	: "SHORT_TERM_SECONDARY_OXYGEN_1_3",
	0x56	: "LONG_TERM_SECONDARY_OXYGEN_1_3",
	0x57	: "SHORT_TERM_SECONDARY_OXYGEN_2_4",
	0x58	: "LONG_TERM_SECONDARY_OXYGEN_2_4",
	0x59	: "FUEL_RAIL_ABS_PRESSURE",
	0x5A	: "RELATIVE_ACCELERATOR",
	0x5B	: "HYBRID_BATTERY_PACK",
	0x5C	: "ENGINE_OIL_TEMP",
	0x5D	: "FUEL_INJECTION_TIMING",
	0x5E	: "ENGINE_FUEL_RATE",
	0x5F	: "EMISSION_REQUIREMENTS",
	0x60	: "PIDS_SUPPORTED_61_80",
	0x61	: "DEMAND_ENGINE",
	0x62	: "ACTUAL_ENGINE",
	0x63	: "ENGINE_REF_TORQUE",
	0x64	: "ENGINE_PERCENT_TORQUE",
	0x65	: "AUXILIARY_INPUT",
	0x66	: "MASS_AIR_FLOW_SENSOR",
	0x67	: "ENGINE_COOLANT_TEMP",
	0x68	: "INTAKE_AIR_TEMP_SENSOR",
	0x69	: "COMMANDED_EGR_ERROR",
	0x6A	: "COMMANDED_DIESEL_INTAKE",
	0x6B	: "EXHAUST_GAS_RECIRCULATION",
	0x6C	: "COMMANDED_THROTTLE_ACTUATOR",
	0x6D	: "FUEL_PRESSURE_CONTROL_SYSTEM",
	0x6E	: "INJECTION_PRESSURE_CONTROL_SYSTEM",
	0x6F	: "TURBOCHARGER_COMPRESSOR",
	0x70	: "BOOST_PRESSURE",
	0x71	: "VARIABLE_GEOMETRY",
	0x72	: "WASTEGATE_CONTROL",
	0x73	: "EXHAUST_PRESSURE",
	0x74	: "TURBOCHARGER_RPM",
	0x75	: "TURBOCHARGER_TEMP",
	0x76	: "TURBOCHARGER_TEMP",
	0x77	: "CHARGER_AIR_COOLER_TEMP",
	0x78	: "EXHAUST_GAS_TEMP",
	0x79	: "EXHAUST_GAS_TEMP",
	0x7A	: "DIESEL_PARTICULATE_FILTER",
	0x7B	: "DIESEL_PARTICULATE_FILTER",
	0x7C	: "DIESEL_PARTICULATE_FILTER_TEMP",
	0x7D	: "NOX_CTRL_AREA",
	0x7E	: "PM_NTE_CTLR_AREA",
	0x7F	: "ENGINE_RUN_TIME",
	0x80	: "PIDS_SUPPORTED_81_A0",
	0x81	: "ENGINE_RUNTIME_AUXILIARY",
	0x82	: "ENGINE_RUNTIME_AUXILIARY",
	0x83	: "NOX_SENSOR",
	0x84	: "MANIFOLD_SURFACE_TEMP",
	0x85	: "NOX_REAGENT_SYSTEM",
	0x86	: "PARTICULATE_MATTER_SENSOR",
	0x87	: "INTAKE_MANIFOLD_PRESSURE",
	0xA0	: "PIDS_SUPPORTED_A1_C0",
	0xC0	: "PIDS_SUPPORTED_C1_E0",
	0xC3	: "?",
	0xC4	: "?"
}

OBD2_MODE_02_PIDS = {
	0x02	: "DTC_FREEZE_STORED",
}

OBD2_MODE_05_PIDS = {
	0x0100	: "OBD_MONITOR_IDS",
	0x0101	: "O2_SENSOR_1_1",
	0x0102	: "O2_SENSOR_1_2",
	0x0103	: "O2_SENSOR_1_3",
	0x0104	: "O2_SENSOR_1_4",
	0x0105	: "O2_SENSOR_2_1",
	0x0106	: "O2_SENSOR_2_2",
	0x0107	: "O2_SENSOR_2_3",
	0x0108	: "O2_SENSOR_2_4",
	0x0109	: "O2_SENSOR_3_1",
	0x010A	: "O2_SENSOR_3_2",
	0x010B	: "O2_SENSOR_3_3",
	0x010C	: "O2_SENSOR_3_4",
	0x010D	: "O2_SENSOR_4_1",
	0x010E	: "O2_SENSOR_4_2",
	0x010F	: "O2_SENSOR_4_3",
	0x0110	: "O2_SENSOR_4_4",
	0x0201	: "O2_SENSOR_1_1",
	0x0202	: "O2_SENSOR_1_2",
	0x0203	: "O2_SENSOR_1_3",
	0x0204	: "O2_SENSOR_1_4",
	0x0205	: "O2_SENSOR_2_1",
	0x0206	: "O2_SENSOR_2_2",
	0x0207	: "O2_SENSOR_2_3",
	0x0208	: "O2_SENSOR_2_4",
	0x0209	: "O2_SENSOR_3_1",
	0x020A	: "O2_SENSOR_3_2",
	0x020B	: "O2_SENSOR_3_3",
	0x020C	: "O2_SENSOR_3_4",
	0x020D	: "O2_SENSOR_4_1",
	0x020E	: "O2_SENSOR_4_2",
	0x020F	: "O2_SENSOR_4_3",
	0x0210	: "O2_SENSOR_4_4"
}

OBD2_MODE_0A_PIDS = {
	0x00	: "MODE_9_SUPPORTED_PIDS_1_20",
	0x01	: "VIN_MESSAGE_COUNT",
	0x02	: "VIN",
	0x03	: "CALIBRATION_ID_MESSAGE_COUNT",
	0x04	: "CALLIBRATION_ID",
	0x05	: "CVN_MESSAGE_COUNT",
	0x06	: "CVN",
	0x07	: "PERFORMANCE_TRACKING_MESSAGE_COUNT",
	0x08	: "PERFORMANCE_TRACKING",
	0x09	: "ECU_NAME_MESSAGE_COUNT",
	0x0A	: "ECU_NAME",
	0x0B	: "PERFORMANCE_TRACKING_COMPRESSION"
}

OBD2_MODE_DESCR = {
	0x01	: "OBD2_MODE_SHOW_CURRENT_DATA1",
	0x02	: "OBD2_MODE_SHOW_CURRENT_DATA2",
	0x03	: "OBD2_MODE_SHOW_STORED_TROUBLECODES",
	0x04	: "OBD2_MODE_CLEAR_DIAGNOSTIC_TROUBLECODES",
	0x05	: "OBD2_MODE_TEST_RESULTS_OXYGEN",
	0x06	: "OBD2_MODE_TEST_RESULTS_OTHER",
	0x07	: "OBD2_MODE_SHOW_PENDING_DIAGNOSTIC_TROUBLECODES",
	0x08	: "OBD2_MODE_CONTROL_OPERATION",
	0x09	: "OBD2_MODE_REQUEST_VEHICLE_INFO",
	0x0A	: "OBD2_MODE_PERMANENT_DIAGNOSTIC_TROUBLECODES"
}

for obdid, name in OBD2_MODE_DESCR.items():
	setattr(module_this, name, obdid)

# Diagnostic and Communications Management
UDS_SID_DESCR = {
	0x10	: "UDS_SID_DIAGNOSTIC_SESSION_CONTORL",
	0x11	: "UDS_SID_ECU_RESET",
	0x12	: "UDS_SID_GMLAN_READ_FAILURE_RECORD",
	0x14	: "UDS_SID_CLEAR_DIAGNOSTIC_INFORMATION",
	0x19	: "UDS_SID_READ_DTC_INFORMATION",
	0x1A	: "UDS_SID_GMLAN_READ_DIAGNOSTIC_ID",
	0x20	: "UDS_SID_RETURN_TO_NORMAL",
	0x22	: "UDS_SID_READ_DATA_BY_ID",
	0x23	: "UDS_SID_READ_MEMORY_BY_ADDRESS",
	0x24	: "UDS_SID_READ_SCALING_DATA_BY_ID",
	0x27	: "UDS_SID_SECURITY_ACCESS",
	0x28	: "UDS_SID_COMMUNICATION_CONTROL",
	0x2A	: "UDS_SID_READ_DATA_BY_PERIODIC_ID",
	0x2C	: "UDS_SID_DYNAMICALLY_DEFINE_DATA_ID",
	0x2D	: "UDS_SID_DEFINE_PID_BY_MEMORY_ADDRESS",
	0x2E	: "UDS_SID_WRITE_DATA_BY_ID",
	0x2F	: "UDS_SID_IO_CONTORL_BY_ID",
	0x31	: "UDS_SID_ROUTINE_CONTROL",
	0x34	: "UDS_SID_REQUEST_DOWNLOAD",
	0x35	: "UDS_SID_REQUEST_UPLOAD",
	0x36	: "UDS_SID_TRANSFER_DATA",
	0x37	: "UDS_SID_REQUEST_TANSFER_EXIT",
	0x38	: "UDS_SID_REQUEST_FILE_TRANSFER",
	0x3B	: "UDS_SID_GMLAN_WRITE_DID",
	0x3D	: "UDS_SID_WRITE_MEMORY_BY_ADDRESS",
	0x3E	: "UDS_SID_TESTER_PRESENT",
	0x83	: "UDS_SID_ACCESS_TIMING_PARAMETER",
	0x84	: "UDS_SID_SECURED_TRANSMISSION",
	0x85	: "UDS_SID_CONTORL_DTC_SETTING",
	0x86	: "UDS_SID_RESPONSE_ON_EVENT",
	0x87	: "UDS_SID_LINK_CONTORL",
	0xA2	: "UDS_SID_GMLAN_REPORT_PROGRAMMING_STATE",
	0xA5	: "UDS_SID_GMLAN_ENTER_PROGRAMMING_MODE",
	0xA9	: "UDS_SID_GMLAN_CHECK_CODES",
	0xAA	: "UDS_SID_GMLAN_READ_DPID",
	0xAE	: "UDS_SID_GMLAN_DEVICE_CONTROL",
}

for udsid, name in UDS_SID_DESCR.items():
	setattr(module_this, name, udsid)

# UDS = 0x7F [SID_requested] [NRC]
UDS_NRC_DESCR = {
	0x10	: "UDS_NRC_GENERAL_REJECT",
	0x11	: "UDS_NRC_SERVICE_NOT_SUPPORTED",
	0x12	: "UDS_NRC_SUBFUNCTION_NOT_SUPPORTED",
	0x13	: "UDS_NRC_INCORRECT_MESSAGE_LENGTH_OR_FORMAT",
	0x14	: "UDS_NRC_RESPONSE_TOO_BIG",
	0x21	: "UDS_NRC_BUSY_REPEAT_REQUEST",
	0x22	: "UDS_NRC_CONDITION_NOT_CORRECT",
	0x24	: "UDS_NRC_REQUEST_SEQUENCE_ERROR",
	0x25	: "UDS_NRC_NONRESPONSE_FROM_SUBNET_COMPONENT",
	0x26	: "UDS_NRC_FAILURE_PREVENTS_EXEC_OR_ACTION",
	0x31	: "UDS_NRC_REQUEST_OUT_OF_RANGE",
	0x33	: "UDS_NRC_SECURITY_ACCESS_DENIED",
	0x35	: "UDS_NRC_INVALID_KEY",
	0x36	: "UDS_NRC_EXCEEDED_NUMBER_OF_ATTEMPTS",
	0x37	: "UDS_NRC_REQUIRED_TIME_DELEAY_NOT_EXPIRED",
	0x70	: "UDS_NRC_UPLOAD_DOWNLOAD_NOT_ACCEPTED",
	0x71	: "UDS_NRC_TRANSFER_DATA_SUSPENDED",
	0x72	: "UDS_NRC_GENERAL_PROGRAMMING_FAILURE",
	0x73	: "UDS_NRC_WRONG_BLOCK_SEQUENCE_COUNTER",
	0x78	: "UDS_NRC_REQUEST_CORRECTLY_RESPONSE_PENDING",
	0x7E	: "UDS_NRC_SUBFUNCTION_NOT_SUPPORTED_IN_SESSION",
	0x7F	: "UDS_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION"
}

for x in range(0x38, 0x4F):
	UDS_NRC_DESCR[x] = "UDS_NRC_RESERVED_%X" % x

for udsid, name in UDS_NRC_DESCR.items():
	setattr(module_this, name, udsid)


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

types_isotp_offset_upper_got_type = {ISOTP_TYPE_SF, ISOTP_TYPE_FF}


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

		# check by request/response SID, on both OBD2 and UDS response will be SID+0x40
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

	__handler__ = {
		0: OBD2, 1: UDS
	}


class ISOTPFirstFrame(ISOTPBase):
	__hdr__ = (
		("pci", "H", ISOTP_TYPE_FF),
	)

	__handler__ = {
		0: OBD2, 1: UDS
	}

	def __get_sig(self):
		return (self.pci & 0xF000) >> 12

	def __set_sig(self, value):
		self.pci = (value & 0xF) << 12 | (self.pci & 0xFFF)

	sig = property(__get_sig, __set_sig)

	def __get_dl(self):
		return self.pci & 0xFFF

	def __set_dl(self, value):
		self.pci = (self.pci & 0xF000) | (value & 0xFFF)

	dl = property(__get_dl, __set_dl)


class ISOTPConsecutiveFrame(ISOTPBase):
	__hdr__ = (
		("pci", "B", ISOTP_TYPE_CF),
	)

	__handler__ = {
		0: OBD2, 1: UDS
	}

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

	__handler__ = {
		0: OBD2, 1: UDS
	}

	def __get_flowstatus(self):
		return self.pci & 0xF

	def __set_flowstatus(self, value):
		self.pci = (self.pci & 0xF0) | (value & 0xF)

	flowstatus = property(__get_flowstatus, __set_flowstatus)


isotp_type_class = {
	ISOTP_TYPE_SF: ISOTPSingleFrame,
	ISOTP_TYPE_FF: ISOTPFirstFrame,
	ISOTP_TYPE_CF: ISOTPConsecutiveFrame,
	ISOTP_TYPE_FC: ISOTPFlowControl
}

# CAN flags
CAN_FLAG_EFF	= 0x80000000
CAN_FLAG_RTR	= 0x40000000
CAN_FLAG_ERR	= 0x20000000


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

	__handler__ = {
		ISOTP_TYPE_SF: ISOTPSingleFrame,
		ISOTP_TYPE_FF: ISOTPFirstFrame,
		ISOTP_TYPE_CF: ISOTPConsecutiveFrame,
		ISOTP_TYPE_FC: ISOTPFlowControl
	}

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
		return self.flag_id & 0x1FFFFFFF

	def __set_id(self, value):
		self.flag_id |= (value & ~0x1FFFFFFF) | value

	id = property(__get_id, __set_id)

	def _dissect(self, buf):
		# assume ISO-TP
		isotp_type = (buf[8] & 0xF0) >> 4
		#logger.debug("got ISOTP type: %d, class will be: %r" %
		#(isotp_type, isotp_type_class[isotp_type]))
		self._init_handler(isotp_type, buf[8:])
		return 8
