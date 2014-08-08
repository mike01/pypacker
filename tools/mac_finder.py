"""
Tool for find MAC->Object associations
"""
import datetime as datetime
import time
import sys
import cmd
import os
import re


from sqlalchemy import *
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relation, sessionmaker

from pypacker import psocket
from pypacker.layer12 import ieee80211, radiotap
from pypacker import utils

import logging
logger = logging.getLogger("pypacker")


#
# sanity checks
#
if len(sys.argv) < 2:
	print("pleace specify an interface as 1st parameter")
	sys.exit(1)

iface	= sys.argv[1]

utils.set_wlan_monmode(iface, monitor_active=True)
psock = psocket.SocketHndl(iface_name=iface, timeout=0.5)
channels = utils.get_available_wlan_channels(iface)

if len(channels) == 0:
# set default channels
	channels = [ch for ch in range(1, 12)]
print("got som' channels: %r" % str(channels))


Base = declarative_base()


#
# data schemes
#
class Station(Base):
	__tablename__ = 'station'

	id = Column(Integer, primary_key=True, unique=True)
	mac = Column(String(20), nullable=False)
	last_seen = Column(DateTime)
	location = Column(String(128))
	tag = Column(String(128))
	stype = Column(String(16))				# ap, client

	def __init__(self, mac=None, last_seen=None, tag=None, location=None, stype=None):
		self.mac = mac
		self.last_seen = last_seen
		self.tag = tag
		self.location = location
		self.stype = stype

	def __repr__(self):
		return "Station(%r, %r, %r, %r)" % (self.mac, self.tag, self.location, self.last_seen)

engine = create_engine('sqlite:///sqla.db')
engine.echo = False
Base.metadata.create_all(engine)


class SessionHandler(object):
	"""Handles more komplex DB operations."""
	def __init__(self, engine):
		Session = sessionmaker(bind=engine)
		self.session = Session()

	def store_clients(self, client_macs, tags, location):
		for client_mac in client_macs:
			for tag in tags:
				station = Station(mac=client_mac,
						last_seen=datetime.datetime.now(),
						location=location,
						tag=tag,
						stype="client")
				self.session.add(station)
		self.session.commit()

	def get_tags(self):
		"""Get unique tags."""
		return self.session.query(Station.tag).distinct()

	def get_locations(self):
		"""Get unique tags."""
		return self.session.query(Station.location).distinct()

	def get_macs(self):
		"""Get unique client macs."""
		logger.info("getting macs")
		return self.session.query(Station.mac).\
			filter(Station.stype == 'client').\
			distinct()

	def get_top_for_tag(self, tag, cnt):
		"""Get top cnt macs (amount_seen_with_tag, mac) for the given tag (desc)."""
		tags = self.session.\
			query(func.count(Station.mac).label("count"), Station.mac).\
			group_by(Station.mac, Station.tag).\
			filter(Station.tag == tag).\
			order_by(desc("count")).\
			limit(cnt)
		return tags

	def get_top_for_mac(self, mac, cnt=5):
		"""Get top cnt tag-infos (amount, tag) for the given mac (desc)."""
		tags = self.session.\
			query(func.count(Station.mac).label("count"), Station.tag).\
			group_by(Station.mac, Station.tag).\
			filter(Station.mac == mac).\
			order_by(desc("count")).\
			limit(cnt)
		return tags

	def delete_by_mac(self, mac):
		"""remove entries having a specific mac"""
		ex = self.session.\
			query(Station).\
			filter(Station.mac == mac).delete()

	def close(self):
		self.session.commit()
		self.session.flush()
		self.session.close()

hndl = SessionHandler(engine=engine)


HARVEST_MODE_AP			= 0	# harvest ap MACs
HARVEST_MODE_CLIENT		= 1	# harvest client MACs
HARVEST_MODE_CLIENT_LIST	= 2	# just show known clients in range and their info


def harvest(psock, mode, aps=None, known_clients=None, harvest_time_ch=5):
	"""
	harvest_time_ch -- time to harvest per channel in seconds
	return -- set(ap_mac | client_macs)
	"""
	found = set()

	for channel in channels:
		utils.switch_wlan_channel(psock.iface_name, channel)
		print("setting channel: %d" % channel)

		time_start = time.time()
		clients_seen = {}
		cnt = 0

		# TODO: to be tuned
		while (time.time() - time_start) < harvest_time_ch:
			try:
				try:
					raw_bytes = psock.recv()
				except:
					# assume timeout: switch channel
					break
				cnt += 1
				drvinfo = radiotap.Radiotap(raw_bytes)

				if cnt % 1000 == 0:
					print("packets/s: %d" % (cnt / (time.time() - time_start)) )

				if mode == HARVEST_MODE_AP:
					beacon = drvinfo[ieee80211.IEEE80211.Beacon]

					if beacon is None:
						continue
					if not beacon.bssid_s in found:
						logger.info("found AP: %18s %-40s %-10s" % (beacon.bssid_s,
							utils.get_vendor_for_mac(beacon.bssid_s[0:8]),
							beacon.params[0].data))
					found.add(beacon.bssid_s)
				elif mode == HARVEST_MODE_CLIENT:
					dataframe = drvinfo[ieee80211.IEEE80211.Dataframe]

					if dataframe is None:
						continue
					src = dataframe.src_s

					if src in aps:
						# not interested in aps
						continue
					if not src in found:
						logger.info("found new client: %s" % src)
						found.add(src)
				elif mode == HARVEST_MODE_CLIENT_LIST:
					try:
						src = drvinfo[ieee80211.IEEE80211]._body_handler.src_s

						if src in known_clients:
							# TODO: signal strength
							#print(src)
							found.add(src)
					except AttributeError as e:
						pass
						#print(e)
					except Exception as e:
						print(e)

					for k in found:
						#os.system("clear")
						print("%s -> (%r)" % (k, str(known_clients[k])))
				else:
					print("wrong harvest mode")
					return None

			except Exception as e:
				print(e)
	return found


def harvest_clients(psock, aps, tags, location, hndl):
	if len(tags) == 0 or location is None:
		print("No tags or locations???")
		return
	if len(aps) == 0:
		print(">>> no APs searched so far harvesting")
		aps.update( harvest(psock, mode=HARVEST_MODE_AP, harvest_time_ch=5) )

		print(">>> APs:")
		for ap in aps:
			print(ap)

	print(">>> harvesting clients, tags/location: %s/%s" % (str(tags), location))
	clients = harvest(psock, mode=HARVEST_MODE_CLIENT, aps=aps)

	hndl.store_clients(clients, tags, location)


def monitor_clients(psock, hndl, rounds=1):
	# mac -> [ top_tags ]
	client_infos = {}
	clients = hndl.get_macs()
	# load top client macs known so far
	for c in clients:
		print("client to follow: %s" % c.mac)
		client_infos[c.mac] = [t.tag for t in hndl.get_top_for_mac(c.mac)]

	for i in range(rounds):
		harvest(psock, mode=HARVEST_MODE_CLIENT_LIST, known_clients=client_infos)


class FinderShell(cmd.Cmd):
	intro = "Mac finder initiated"
	promt = ">"
	file = None
	aps = set()

	def do_searchap(self, arg):
		"""Update the current APs seen."""
		FinderShell.aps.clear()
		FinderShell.aps.update( harvest(psock, mode=HARVEST_MODE_AP, harvest_time_ch=2) )

	def do_aps(self, arg):
		"""Show all APs."""
		print("got %d aps: " % len(FinderShell.aps))
		for ap in FinderShell.aps:
			#print(ap)
			print("%17s %s" % (ap, utils.get_vendor_for_mac(ap[0:8])))

	def do_harvest(self, arg):
		"""Harvest clients giving tags and one location."""
		l = re.split("\s+", arg)
		harvest_clients(psock, FinderShell.aps, l[:-1], l[-1], hndl)

	def do_show(self, arg):
		"""Show tags ans locations."""
		tags = hndl.get_tags()

		print(">>> known tags:")
		for v in tags:
			print(v[0])

		locations = hndl.get_locations()
		print("\n>>> known locations:")
		for v in locations:
			print(v[0])

		#print(">>> client assumptions:")
		#clients = hndl.get_macs()
		## load top client macs known so far
		#for c in clients:
		#	print(c.mac)
		#	for t in hndl.get_top_for_mac(c.mac):
		#		print("\t%s (%d)" % (t.tag, t.count))

	def do_macfortag(self, arg):
		"""Get top macs for given tag."""
		try:
			maccnts = hndl.get_top_for_tag(arg, 5)

			print(">>> top macs for tag %s" % arg)

			for cnt, mac in maccnts:
				print("%s (%s)" % (mac, cnt))
		except Exception as e:
			print(e)

	def do_monitor(self, arg):
		"""Track currently seen clients."""
		l = re.split("\s+", arg)
		rounds = 1

		try:
			rounds = int(l[0])
		except:
			pass
		print(">>> looking for clients in %s rounds" % rounds)
		monitor_clients(psock, hndl, rounds)

try:
	FinderShell().cmdloop()
except:
	pass

psock.close()
hndl.close()
