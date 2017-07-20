from struct import Struct

unpack_B = Struct(">B").unpack
pack_B = Struct(">B").pack
unpack_BB = Struct(">BB").unpack

unpack_H = Struct(">H").unpack
pack_H = Struct(">H").pack
unpack_H_le = Struct("<H").unpack
pack_H_le = Struct("<H").pack
unpack_HH = Struct(">HH").unpack
unpack_HHHH = Struct(">HHHH").unpack

unpack_I = Struct(">I").unpack
pack_I = Struct(">I").pack
unpack_I_le = Struct("<I").unpack
pack_I_le = Struct("<I").pack
unpack_I_n = Struct("=I").unpack
unpack_IIII = Struct(">IIII").unpack
unpack_IIII_le = Struct("<IIII").unpack

unpack_Q_le = Struct("<Q").unpack
unpack_Q = Struct(">Q").unpack
pack_Q = Struct(">Q").pack

pack_ipv4_header = Struct(">4s4sxBH").pack
pack_ipv6_header = Struct(">16s16sxBH").pack

pack_ipv4 = Struct("BBBB").pack
unpack_ipv4 = Struct("BBBB").unpack
pack_mac = Struct("BBBBBB").pack
unpack_mac = Struct("BBBBBB").unpack