"""
This script aims to find bugs by parsing arbitrary packets.
Packets leading to errors will be dumped to file for later analyzis.
"""
import sys
import time
import getopt
import argparse

from pypacker.layer12 import ethernet
from pypacker import ppcap
from pypacker import psocket


def readndump_network(file_name="bugpackets.pcap", iface_name="lo"):
	print("will store bug-packets to: %s" % file_name)
	pcap_writer = ppcap.Writer(filename=file_name)
	psock = psocket.SocketHndl(iface_name=iface_name, timeout=999999)

	try:
		for bts in psock:
			pass_or_dump(bts)
	except KeyboardInterrupt:
		pass

	pcap_writer.close()
	psock.close()


def readndump_capfile(infile_name="bugpackets.pcap"):
	outfile_name = infile_name + "_buggyagain.pcap"
	print("will store bug-packets to: %s" % outfile_name)
	pcap_in = ppcap.Reader(filename=infile_name)

	pcap_out = ppcap.Writer(filename=outfile_name)

	for ts, bts in pcap_in:
		pass_or_dump(bts, pcap_out)

	pcap_in.close()
	pcap_out.close()


def pass_or_dump(bts, pcap_writer):
	try:
		eth = ethernet.Ethernet(bts)

		if bts != eth.bin():
			raise Exception("parsing was buggy: %r != %r" % (bts, eth.bin()))
		tmp = "%r" % eth
		#print(bts)
		#print("%r" % eth)
		#print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
		print(".", end="")
		print("%r" % eth.highest_layer.__class__.__name__, end="")

		sys.stdout.flush()

		for layer in eth:
			if layer.dissect_error:
				raise Exception("parsing was buggy: %r != %r" % (bts, eth.bin()))
	except Exception as ex:
		print("\nError while parsing: %r" % ex)
		pcap_writer.write(bts)


FILENAME_CAPTURE_BUGGY		= "bugpackets.pcap"


if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("--iface", default="eth0")
	parser.add_argument("--mode", default="sniff")  # mode = sniff or replay, replay needs --infile
	parser.add_argument("--infile", default=FILENAME_CAPTURE_BUGGY)
	args = parser.parse_args()

	if args.mode == "sniff":
		print("sniffing for packets")
		readndump_network(file_name=FILENAME_CAPTURE_BUGGY, iface_name=args.iface)
	elif args.mode == "replay":
		print("reading files from: %r" % args.infile)
		readndump_capfile(infile_name=args.infile)
	else:
		args.print_help()
