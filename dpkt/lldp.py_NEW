# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2012 Isaku Yamahata <yamahata at private email ne jp>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Link Layer Discovery Protocol(LLDP, IEEE 802.1AB)
http://standards.ieee.org/getieee802/download/802.1AB-2009.pdf


basic TLV format

octets | 1          | 2             | 3 ...             n + 2 |
       --------------------------------------------------------
       | TLV type | TLV information | TLV information string  |
       | (7bits)  | string length   | ( 0 <= n <= 511 octets) |
       |          | (9bits)         |                         |
       --------------------------------------------------------
bits   |8        2|1|8             1|


LLDPDU format

 ------------------------------------------------------------------------
 | Chassis ID | Port ID | TTL | optional TLV | ... | optional TLV | End |
 ------------------------------------------------------------------------

Chasis ID, Port ID, TTL, End are mandatory
optional TLV may be inserted in any order
"""

import dpkt
import logging
import struct
from dpkt import ethernet


LOG = logging.getLogger(__name__)


# LLDP destination MAC address
LLDP_MAC_NEAREST_BRIDGE = '\x01\x80\xc2\x00\x00\x0e'
LLDP_MAC_NEAREST_NON_TPMR_BRIDGE = '\x01\x80\xc2\x00\x00\x03'
LLDP_MAC_NEAREST_CUSTOMER_BRIDGE = '\x01\x80\xc2\x00\x00\x00'


# LLDP ethertype
ETH_TYPE_LLDP = 0x88cc


LLDP_TLV_TYPELEN_STR = '!H'
LLDP_TLV_SIZE = 2
LLDP_TLV_TYPE_MASK = 0xfe00
LLDP_TLV_TYPE_SHIFT = 9
LLDP_TLV_LENGTH_MASK = 0x01ff


# LLDP TLV type
LLDP_TLV_END = 0                        # End of LLDPDU
LLDP_TLV_CHASSIS_ID = 1                 # Chassis ID
LLDP_TLV_PORT_ID = 2                    # Port ID
LLDP_TLV_TTL = 3                        # Time To Live
LLDP_TLV_PORT_DESCRIPTION = 4           # Port Description
LLDP_TLV_SYSTEM_NAME = 5                # System Name
LLDP_TLV_SYSTEM_DESCRIPTION = 6         # System Description
LLDP_TLV_SYSTEM_CAPABILITIES = 7        # System Capabilities
LLDP_TLV_MANAGEMENT_ADDRESS = 8         # Management Address
LLDP_TLV_ORGANIZATIONALLY_SPECIFIC = 127  # organizationally Specific TLVs


class LLDPBasicTLV(dpkt.Packet):
    LEN_MIN = 0
    LEN_MAX = 511
    tlv_type = None

    __hdr__ = (
        ('typelen', 'H', LLDP_TLV_END),
        )

    def __init__(self, *args, **kwargs):
        self.typelen = None
        self.len = None
        super(LLDPBasicTLV, self).__init__(*args, **kwargs)

    @staticmethod
    def get_type(buf):
        (typelen, ) = struct.unpack(LLDP_TLV_TYPELEN_STR, buf[:LLDP_TLV_SIZE])
        return (typelen & LLDP_TLV_TYPE_MASK) >> LLDP_TLV_TYPE_SHIFT

    @staticmethod
    def set_tlv_type(subcls, tlv_type):
        assert issubclass(subcls, LLDPBasicTLV)
        subcls.tlv_type = tlv_type

    def _len_valid(self):
        return self.LEN_MIN <= self.len and self.len <= self.LEN_MAX

    def unpack(self, buf):
        super(LLDPBasicTLV, self).unpack(buf)
        tlv_type = (self.typelen & LLDP_TLV_TYPE_MASK) >> LLDP_TLV_TYPE_SHIFT
        assert tlv_type == self.tlv_type
        self.len = self.typelen & LLDP_TLV_LENGTH_MASK
        if not self._len_valid():
            raise dpkt.UnpackError('invalid len %d' % self.len)

        last_len = self.len + LLDP_TLV_SIZE
        if len(buf) < last_len:
            raise dpkt.NeedData
        self.data = buf[self.__hdr_len__:last_len]

    def _typelen(self):
        tlv_len = self.__hdr_len__ - LLDPBasicTLV.__hdr_len__ + len(self.data)
        if self.len is None:
            self.len = tlv_len
        assert self.len == tlv_len
        if not self._len_valid():
            raise dpkt.PackError('invalid len %d' % self.len)
        self.typelen = (self.tlv_type << LLDP_TLV_TYPE_SHIFT) | self.len

    def __str__(self):
        self._typelen()
        return super(LLDPBasicTLV, self).__str__()


class LLDP(dpkt.Packet):
    __hdr__ = ()
    _tlv_parsers = {}
    tlvs = ()

    # at least it must have chassis id, port id, ttl and end
    def _tlvs_len_valid(self):
        return len(self.tlvs) >= 4

    # chassis id, port id, ttl and end
    def _tlvs_valid(self):
        return (self.tlvs[0].tlv_type == LLDP_TLV_CHASSIS_ID and
                self.tlvs[1].tlv_type == LLDP_TLV_PORT_ID and
                self.tlvs[2].tlv_type == LLDP_TLV_TTL and
                self.tlvs[-1].tlv_type == LLDP_TLV_END)

    def __str__(self):
        if not self._tlvs_len_valid():
            raise dpkt.PackError('too short tlvs')
        if not self._tlvs_valid():
            raise dpkt.PackError('missing tlv')
        return ''.join(str(tlv) for tlv in self.tlvs)

    def unpack(self, buf):
        super(LLDP, self).unpack(buf)
        self.tlvs = []

        while buf:
            tlv_type = LLDPBasicTLV.get_type(buf)
            basic_tlv = self._tlv_parsers[tlv_type](buf)
            self.tlvs.append(basic_tlv)
            buf = buf[len(basic_tlv):]
            if ((len(buf) > 0 and basic_tlv.tlv_type == LLDP_TLV_END) or
                (len(buf) == 0 and basic_tlv.tlv_type != LLDP_TLV_END)):
                raise dpkt.UnpackError('invalid tlv len %d type %d' %
                                       (len(buf), basic_tlv.tlv_type))

        if not self._tlvs_len_valid():
            raise dpkt.UnpackError('too short tlv')
        if not self._tlvs_valid():
            raise dpkt.UnpackError('missing tlv')

    @classmethod
    def set_type(cls, tlv_cls):
        cls._tlv_parsers[tlv_cls.tlv_type] = tlv_cls

    @classmethod
    def get_type(cls, tlv_type):
        return cls._tlv_parsers[tlv_type]

    @classmethod
    def set_tlv_type(cls, tlv_type):
        def _set_type(tlv_cls):
            tlv_cls.set_tlv_type(tlv_cls, tlv_type)
            cls.set_type(tlv_cls)
            return tlv_cls
        return _set_type


@LLDP.set_tlv_type(LLDP_TLV_END)
class End(LLDPBasicTLV):
    __hdr__ = (
        ('typelen', 'H', LLDP_TLV_END),
        )


@LLDP.set_tlv_type(LLDP_TLV_CHASSIS_ID)
class ChassisID(LLDPBasicTLV):
    # subtype id(1 octet) + chassis id length(1 - 255 octet)
    LEN_MIN = 2
    LEN_MAX = 256

    # Chassis ID subtype
    SUB_CHASSIS_COMPONENT = 1   # EntPhysicalAlias (IETF RFC 4133)
    SUB_INTERFACE_ALIAS = 2     # IfAlias (IETF RFC 2863)
    SUB_PORT_COMPONENT = 3      # EntPhysicalAlias (IETF RFC 4133)
    SUB_MAC_ADDRESS = 4         # MAC address (IEEE std 802)
    SUB_NETWORK_ADDRESS = 5     # networkAddress
    SUB_INTERFACE_NAME = 6      # IfName (IETF RFC 2863)
    SUB_LOCALLY_ASSIGNED = 7    # local

    __hdr__ = (
        ('typelen', 'H', LLDP_TLV_CHASSIS_ID),
        ('subtype', 'B', SUB_CHASSIS_COMPONENT),
        )

    @property
    def chassis_id(self):
        return self.data

    @chassis_id.setter
    def chassis_id(self, value):
        self.data = value


@LLDP.set_tlv_type(LLDP_TLV_PORT_ID)
class PortID(LLDPBasicTLV):
    # subtype id(1 octet) + port id length(1 - 255 octet)
    LEN_MIN = 2
    LEN_MAX = 256

    # Port ID subtype
    SUB_INTERFACE_ALIAS = 1     # ifAlias (IETF RFC 2863)
    SUB_PORT_COMPONENT = 2      # entPhysicalAlias (IETF RFC 4133)
    SUB_MAC_ADDRESS = 3         # MAC address (IEEE Std 802)
    SUB_NETWORK_ADDRESS = 4     # networkAddress
    SUB_INTERFACE_NAME = 5      # ifName (IETF RFC 2863)
    SUB_AGENT_CIRCUIT_ID = 6    # agent circuit ID(IETF RFC 3046)
    SUB_LOCALLY_ASSIGNED = 7    # local

    __hdr__ = (
        ('typelen', 'H', LLDP_TLV_PORT_ID),
        ('subtype', 'B', SUB_INTERFACE_ALIAS),
        )

    @property
    def port_id(self):
        return self.data

    @port_id.setter
    def port_id(self, value):
        self.data = value


@LLDP.set_tlv_type(LLDP_TLV_TTL)
class TTL(LLDPBasicTLV):
    TTL_STR = 'H'
    TTL_SIZE = 2
    LEN_MIN = TTL_SIZE
    LEN_MAX = TTL_SIZE

    __hdr__ = (
        ('typelen', 'H', LLDP_TLV_TTL),
        ('ttl', TTL_STR, 0),
        )


@LLDP.set_tlv_type(LLDP_TLV_PORT_DESCRIPTION)
class PortDescription(LLDPBasicTLV):
    LEN_MAX = 255

    __hdr__ = (
        ('typelen', 'H', LLDP_TLV_PORT_DESCRIPTION),
        )

    @property
    def port_description(self):
        return self.data

    @port_description.setter
    def port_description(self, value):
        self.data = value


@LLDP.set_tlv_type(LLDP_TLV_SYSTEM_NAME)
class SystemName(LLDPBasicTLV):
    LEN_MAX = 255

    __hdr__ = (
        ('typelen', 'H', LLDP_TLV_SYSTEM_NAME),
        )

    @property
    def system_name(self):
        return self.data

    @system_name.setter
    def system_name(self, value):
        self.data = value


@LLDP.set_tlv_type(LLDP_TLV_SYSTEM_DESCRIPTION)
class SystemDescription(LLDPBasicTLV):
    LEN_MAX = 255

    __hdr__ = (
        ('typelen', 'H', LLDP_TLV_SYSTEM_DESCRIPTION),
        )

    @property
    def system_description(self):
        return self.data

    @system_description.setter
    def system_description(self, value):
        self.data = value


@LLDP.set_tlv_type(LLDP_TLV_SYSTEM_CAPABILITIES)
class SystemCapabilities(LLDPBasicTLV):
    # chassis subtype(1) + system cap(2) + enabled cap(2)
    LEN_MIN = 5
    LEN_MAX = 5
    CAP_STR = 'H'

    # System Capabilities
    CAP_REPEATER = (1 << 1)             # IETF RFC 2108
    CAP_MAC_BRIDGE = (1 << 2)           # IEEE Std 802.1D
    CAP_WLAN_ACCESS_POINT = (1 << 3)    # IEEE Std 802.11 MIB
    CAP_ROUTER = (1 << 4)               # IETF RFC 1812
    CAP_TELEPHONE = (1 << 5)            # IETF RFC 4293
    CAP_DOCSIS = (1 << 6)               # IETF RFC 4639 and IETF RFC 4546
    CAP_STATION_ONLY = (1 << 7)         # IETF RFC 4293
    CAP_CVLAN = (1 << 8)                # IEEE Std 802.1Q
    CAP_SVLAN = (1 << 9)                # IEEE Std 802.1Q
    CAP_TPMR = (1 << 10)                # IEEE Std 802.1Q

    __hdr__ = (
        ('typelen', 'H', LLDP_TLV_SYSTEM_CAPABILITIES),
        ('subtype', 'B', ChassisID.SUB_CHASSIS_COMPONENT),
        ('system_cap', CAP_STR, 0),
        ('enabled_cap', CAP_STR, 0),
        )


@LLDP.set_tlv_type(LLDP_TLV_MANAGEMENT_ADDRESS)
class ManagementAddress(LLDPBasicTLV):
    LEN_MIN = 9
    LEN_MAX = 167

    ADDR_STR = '!BB'    # address string length, address subtype
    ADDR_SIZE = 2
    ADDR_LEN_MIN = 1
    ADDR_LEN_MAX = 31

    INTF_STR = '!BIB'   # interface subtype, interface number, oid length
    INTF_SIZE = 6
    OID_LEN_MIN = 0
    OID_LEN_MAX = 128

    __hdr__ = (
        ('typelen', 'H', LLDP_TLV_MANAGEMENT_ADDRESS),
        )

    def __init__(self, *args, **kwargs):
        self.addr_len = None
        self.addr_subtype = None
        self.addr = None
        self.intf_subtype = None
        self.intf_num = None
        self.oid_len = None
        self.oid = None
        super(ManagementAddress, self).__init__(*args, **kwargs)

    def _addr_len_valid(self):
        return (self.ADDR_LEN_MIN <= self.addr_len or
                self.addr_len <= self.ADDR_LEN_MAX)

    def _oid_len_valid(self):
        return (self.OID_LEN_MIN <= self.oid_len and
                self.oid_len <= self.OID_LEN_MAX)

    # addr_len
    # addr_subtype
    # addr
    # intf_subtype
    # intf_num
    # oid_len
    # oid
    def unpack(self, buf):
        super(ManagementAddress, self).unpack(buf)
        (self.addr_len, self.addr_subtype) = struct.unpack(
            self.ADDR_STR, self.data[:self.ADDR_SIZE])
        if not self._addr_len_valid():
            raise dpkt.UnpackError('invalid addr len')
        offset = self.ADDR_SIZE + self.addr_len
        self.addr = self.data[self.ADDR_SIZE:offset]

        (self.intf_subtype,
         self.intf_num,
         self.oid_len) = struct.unpack(
            self.INTF_STR, self.data[offset:offset + self.INTF_SIZE])
        if not self._oid_len_valid():
            raise dpkt.UnpackError('invalid oid len')

        offset = offset + self.INTF_SIZE
        self.oid = self.data[offset:]

    def __str__(self):
        self.addr_len = len(self.addr)
        if not self._addr_len_valid():
            raise dpkt.PackError('invalid addr len')
        addr_hdr = struct.pack(self.ADDR_STR, self.addr_len, self.addr_subtype)

        self.oid_len = len(self.oid)
        if not self._oid_len_valid():
            raise dpkt.PackError('invalid oid len')
        intf_hdr = struct.pack(self.INTF_STR,
                               self.intf_subtype, self.intf_num, self.oid_len)

        self.data = addr_hdr + self.addr + intf_hdr + self.oid
        return super(ManagementAddress, self).__str__(self)


@LLDP.set_tlv_type(LLDP_TLV_ORGANIZATIONALLY_SPECIFIC)
class OrganizationallySpecific(LLDPBasicTLV):
    LEN_MIN = 4
    LEN_MAX = 511

    __hdr__ = (
        ('typelen', 'H', LLDP_TLV_ORGANIZATIONALLY_SPECIFIC),
        ('oui', '3B', 0),
        ('subtype', 'B', 0),
        )


# Register LLDP ether type
ethernet.Ethernet.set_type(ETH_TYPE_LLDP, LLDP)

if __name__ == '__main__':
    import unittest

    class LLDPTestCase(unittest.TestCase):
        # TODO:XXX more test cases

        def test_lldp(self):
            data = '\x02\x11\x07' + "deadbeefcafecafe" \
                   '\x04\x05\x07' + "0008" \
                   '\x06\x02\x00\x3c' \
                   '\x00\x00'
            lldp = LLDP(data)
            if (data != lldp.pack()):
                raise dpkt.PackError

        def test_eth_lldp(self):
            data = '\x80\x48\x00\x00\x00\x00' \
                   '\x80\x48\x00\x00\x00\x00' \
                   '\x88\xcc' \
                   '\x02\x11\x07' + "deadbeefcafecafe" \
                   '\x04\x05\x07' + "0008" \
                   '\x06\x02\x00\x3c' \
                   '\x00\x00'
            ethlldp = ethernet.Ethernet(data)
            if (data != ethlldp.pack()):
                raise dpkt.PackError

    unittest.main()
