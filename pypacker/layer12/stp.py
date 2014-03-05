"""Spanning Tree Protocol."""

from pypacker import pypacker


class STP(pypacker.Packet):
	__hdr__ = (
		("proto_id", "H", 0),
		("v", "B", 0),
		("type", "B", 0),
		("flags", "B", 0),
		("root_id", "8s", b""),
		("root_path", "I", 0),
		("bridge_id", "8s", b""),
		("port_id", "H", 0),
		("age", "H", 0),
		("max_age", "H", 0),
		("hello", "H", 0),
		("fd", "H", 0)
	)
