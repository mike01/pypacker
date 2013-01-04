"""PFlog dumps have a special link-layer, which is parsed by this class."""

import struct
import dpkt

class Pflog(dpkt.Packet):
    __hdr__ = (
        ('len', 'B', ''),
        ('addressFamily', 'B', ''),
        ('action', 'B', ''),
        ('reason', 'B', ''),
        ('interfaceName', '16s', ''),
        ('ruleSet', '16s', ''),
        ('ruleNr', 'L', ''),
        ('subRuleNr', 'L', ''),
        ('uid', 'L', ''),
        ('pid', 'l', ''),
        ('ruleuid', 'L', ''),
        ('rulepid', 'l', ''),
        ('direction', 'B', ''),
        ('padding', '3s', ''),
        )
