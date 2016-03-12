"""
Tool to find MAC -> Object associations:
- Which MACs are associated to APs?
- Which person uses which MAC?
"""
import time
import sys
import cmd
import re
import socket
import logging
import struct
from multiprocessing import Process, Queue

from sqlalchemy import *
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relation, relationship, sessionmaker

from pypacker.layer12 import ieee80211, radiotap
from pypacker import psocket, utils, ppcap

Radiotap = radiotap.Radiotap

root_logger = logging.getLogger()
root_logger.handlers = []
logger = logging.getLogger("macfinder")
# logger.setLevel(logging.WARNING)
# logger.setLevel(logging.INFO)
logger.setLevel(logging.DEBUG)

# create formatter and add it to the handlers
formatter = logging.Formatter("%(message)s")
streamhandler = logging.StreamHandler()
streamhandler.setFormatter(formatter)
logger.addHandler(streamhandler)

unpack_B = struct.Struct(">B").unpack

def is_special_mac(mac_str):
	"""
	Check if this is a special MAC adress (not a client address). Every MAC not found
	in the official OUI database is assumed to be non-client.

	mac_str -- Uppercase mac string like "AA:BB:CC[:DD:EE:FF]", first 3 MAC-bytes are enough
	"""
	return len(utils.get_vendor_for_mac(mac_str[0:8])) == 0


#
# Database schemes
#
Base = declarative_base()


class AssociationTagStation(Base):
	__tablename__ = "association_tag_station"
	id = Column(Integer, primary_key=True)
	station_mac = Column(String(256), ForeignKey('station.mac'), primary_key=False)
	tag_name = Column(String(256), ForeignKey('tag.name'), primary_key=False)

	station = relationship("Station", back_populates="tags")
	tag = relationship("Tag", back_populates="stations")

	tagdate = Column(DateTime, default=func.now())

	def __init__(self, station, tag):
		self.station = station
		self.tag = tag


class Tag(Base):
	"""
	Represents a tag used to mark a client.
	"""
	__tablename__ = "tag"

	name = Column(String(256), primary_key=True, nullable=False)
	stations = relationship("AssociationTagStation", back_populates="tag")

	def __init__(self, name):
		self.name = name


class Station(Base):
	"""
	Represents an AP or client.
	"""
	__tablename__ = "station"

	mac = Column(String(17), primary_key=True, nullable=False)
	stype = Column(String(16), nullable=False)			# "ap", "client"
	description = Column(String(512), nullable=True)		# ap: essid
	tags = relationship("AssociationTagStation", back_populates="station")

	def __init__(self, mac, stype, description=None):
		self.mac = mac
		self.stype = stype
		self.description = description

	def __repr__(self):
		return "Station(%r, %r, %r)" % (self.mac, self.stype, self.description)


class DatabaseHandler(object):
	"""Handles more komplex DB operations."""
	def __init__(self, engine_db):
		Session = sessionmaker(bind=engine_db)
		self.session = Session()
		clients_from_db = self.get_client_macs()
		client_tags = {}

		for client_db in clients_from_db:
			# just load macs, tags are lazy loaded
			client_tags[client_db.mac] = None

		# mac -> None | [tag1, tag2, ...]
		# senables lazy loading of client tags
		self._client_tags = client_tags

	def store_aps(self, ap_macs_to_store):
		"""
		ap_macs_to_store -- set of MAC addresses. Must contain at minimum
			all APs currently in the database.
		"""
		#aps_from_db = set([ap[0] for ap in self.get_aps()])
		#logger.debug("APs in database: %d" % len(aps_from_db))
		#aps_to_store = ap_macs_to_store - aps_from_db
		logger.info("merging %d APs" % len(ap_macs_to_store))

		for ap_mac_to_store in ap_macs_to_store:
			# TODO: add ESSID
			station = Station(ap_mac_to_store, "ap")
			self.session.merge(station)
		self.session.commit()
		self.session.flush()

	def get_aps(self):
		return self.session.query(
			Station.mac).\
			filter(Station.stype == "ap").\
			distinct()

	def store_clients(self, client_macs, tagnames):
		"""
		client_macs -- [MAC1, MAC2, ...]
		tagnames -- [tagname1, tagname2, ...]
		"""
		client_mac_objs = []

		logger.info("merging %d clients" % len(client_macs))

		# TODO: store clients also locally

		for client_mac in client_macs:
			station = Station(client_mac, "client")
			self.session.merge(station)
			client_mac_objs.append(station)

		tag_objs = []

		logger.info("merging %d tags" % len(tagnames))

		for tagname in tagnames:
			tag_obj = Tag(tagname)
			self.session.merge(tag_obj)
			tag_objs.append(tag_obj)

		self.session.commit()

		logger.debug("saving %d mac<->tag associations" % (len(client_mac_objs) * len(tag_objs)))

		for client_mac_obj in client_mac_objs:
			for tag_obj in tag_objs:
				assoc = AssociationTagStation(client_mac_obj, tag_obj)
				self.session.merge(assoc)

		self.session.commit()
		self.session.flush()

	def get_client_macs(self):
		return self.session.query(
			Station.mac).\
			filter(Station.stype == "client").\
			distinct()

	def get_clients_amount(self):
		return len(self._client_tags)

	def get_client_tags(self, client_mac):
		"""
		raises -- KeyError if client mac is not found
		"""
		tags = self._client_tags[client_mac]

		# lazy load data
		if tags is None:
			#logger.debug("lazy loading tags")
			tags = self.get_top_for_mac(client_mac)
			self._client_tags[client_mac] = tags
		return tags

	def get_tags(self):
		"""Get unique tags."""
		return self.session.query(Tag.name).distinct()

	def get_top_for_mac(self, mac, cnt=5):
		"""Get top cnt tags for the given mac."""
		#logger.info("getting top %d for mac %s" % (cnt, mac))
		tags = self.session.\
			query(func.count(AssociationTagStation.station_mac).label("count"),
				AssociationTagStation.tag_name).\
			group_by(AssociationTagStation.station_mac, AssociationTagStation.tag_name).\
			filter(AssociationTagStation.station_mac == mac).\
			order_by(desc("count")).\
			limit(cnt)
		return [tag[1] for tag in tags]

	def delete_by_mac(self, mac):
		"""remove entries having a specific mac"""
		self.session.\
			query(Station).\
			filter(Station.mac == mac).delete()

	def close(self):
		self.session.commit()
		self.session.flush()
		self.session.close()


class Logic(object):
	def __init__(self, db_handler, packet_collector, channels):
		"""
		Workflow: harvest clients (save AP and client MACs -> monitor clients (use known AP and client MACs))
		"""
		# [mac1, mac2, ...]
		self._aps_known = set()
		self._db_handler = db_handler
		self._packet_collector = packet_collector
		self._channels = channels
		self._tags = set()
		self._ap_channels = set()

		self._initiage_aps_and_clients()

	aps = property(lambda self: self._aps_known)
	channels = property(lambda self: self._channels)
	tags = property(lambda self: self._tags)


	def clear_ap_channels(self):
		self._ap_channels.clear()

	def shutdown(self):
		"""
		Close database session, packet collector and collector processes
		"""
		self._db_handler.close()
		self._packet_collector.stop_collecting()

	def _initiage_aps_and_clients(self):
		aps = self._db_handler.get_aps()

		for ap in aps:
			self._aps_known.add(ap[0])

		tags = self._db_handler.get_tags()

		for tag in tags:
			if tag[0] is not None:
				self._tags.add(tag[0])

		clients_amount = self._db_handler.get_clients_amount()

		logger.debug("APS=%d, clients=%d, tags=%d" % (len(self._aps_known), clients_amount, len(self._tags)))

	def _harvest(self, strategy, harvest_time_per_channel_sec=10, channels_to_scan=None):
		"""
		Harvest information about entities in the network (eg APs or clients)
		using the callback represented by strategy.
		This iterates ALL available channels as we don't know
		where the entities operate at.

		strategy -- callback with signature "strategy(packet) [True|False|None]", returns True
			if channel-skip counter should be reset (remain on channel until next countdown exceeds)
		return -- set(ap_mac | client_macs)
		"""
		self._packet_collector.start_collecting()
		_channels_to_scan = self._channels if channels_to_scan is None else channels_to_scan
		logger.debug("scanning channels: %r" % _channels_to_scan)

		for channel in _channels_to_scan:
			utils.switch_wlan_channel(self._packet_collector.iface, channel)
			logger.info("! setting channel: %d" % channel)
			time_start = time.time()

			for bts in self._packet_collector:
				reset_channel_countdown = False

				try:
					ratiotap_pkt = Radiotap(bts)
					reset_channel_countdown = strategy(ratiotap_pkt, channel)
				except Exception as e:
					# something went wrong, parsing error?
					logger.exception(e)

				if reset_channel_countdown is True:
					time_start = time.time()
				elif time.time() - time_start > harvest_time_per_channel_sec:
					break

		self._packet_collector.stop_collecting()

	def harvest_clients(self, tags):
		# user provided tags: could be duplicated
		tags = set(tags)
		logger.info("harvesting clients, tags (unique)=%s" % str(tags))
		clients_found = set()
		# collect new APs dedicated (less than stored ones)
		aps_found_new = set()

		def strategy(radiotap_pkt, channel):
			try:
				# radiotap -> ieee -> [Beacon, data, ACK, ...]
				ieee80211_pkt = radiotap_pkt.body_handler
				#logger.debug("checking...")
				if ieee80211_pkt.subtype == 8 and ieee80211_pkt.type == 0:
					if ieee80211_pkt.body_handler.bssid_s not in self._aps_known:
						beacon = ieee80211_pkt.body_handler
						#logger.debug("skipping beacon")
						logger.info("found new AP: %18s %-40s %-10s" % (beacon.bssid_s,
							utils.get_vendor_for_mac(beacon.bssid_s[0:8]),
							beacon.params[0].data))
						aps_found_new.add(beacon.bssid_s)
						self._aps_known.add(beacon.bssid_s)
						self._ap_channels.add(channel)

						# remain on channel
						return True
					return False
			except Exception as ex:
				logger.warning("error while harvesting: %r" % ex)
				return False

			ieee_handler = ieee80211_pkt.body_handler
			client_macs = []

			# management
			if ieee80211_pkt.type == 0:
				# both src/dst could be client
				client_macs = [ieee_handler.src_s, ieee_handler.dst_s]
			# control
			elif ieee80211_pkt.type == 1:
				try:
					client_macs.append(ieee_handler.dst_s)
				except:
					# TODO: exceptions possible?
					pass
				try:
					client_macs.append(ieee_handler.src_s)
				except:
					# dst not always present
					pass
			# data
			elif ieee80211_pkt.type == 2:
				if ieee80211_pkt.from_ds == 1 and ieee80211_pkt.to_ds == 0:
					client_macs.append(ieee_handler.dst_s)
				elif ieee80211_pkt.to_ds == 1 and ieee80211_pkt.from_ds == 0:
					client_macs.append(ieee_handler.src_s)
			else:
				logger.warning("unknown ieee80211 type: %r (0/1/2 = mgmt/ctrl/data)" % ieee80211_pkt.type)
				return False

			found_client = False

			for addr in client_macs:
				# not an AP and not yet stored
				if addr not in self._aps_known and addr not in clients_found:
					if is_special_mac(addr):
						logger.debug("special MAC: %s" % addr)
						continue
					logger.info("found possible client: %s\t%s" %
						(addr, utils.get_vendor_for_mac(addr[0:8])))
					logger.debug("ieee type was: %d" % ieee80211_pkt.type)
					clients_found.add(addr)

					# remain on channel, we found something
					found_client = True
			return found_client

		self._harvest(strategy, harvest_time_per_channel_sec=5)
		#self._harvest(strategy, harvest_time_per_channel_sec=10)
		#self._harvest(strategy, harvest_time_per_channel_sec=1)
		# update current state without loading data from database
		for tag in tags:
			self._tags.add(tag)

		self._db_handler.store_clients([client for client in clients_found if client not in self._aps_known], tags)
		self._db_handler.store_aps(aps_found_new)

	def monitor_clients(self, only_active_channels=False):
		"""
		Shows present clients based on stored data
		"""
		logger.info("reloading AP/clients from database")
		self._initiage_aps_and_clients()
		# mac -> [ top_tags ]
		clients_identified = set()
		# store new MAC dedicated to improve performance later on when storing
		aps_new = set()

		client_count = self._db_handler.get_clients_amount()

		if client_count == 0:
			logger.warning("no clients tagged so far")
			return
		else:
			logger.info("amount of clients to search for: %d" % client_count)

		def strategy(radiotap_pkt, channel):
			try:
				ieee = radiotap_pkt.body_handler
				ieee_handler = ieee.body_handler

				if ieee.subtype == 8 and ieee.type == 0:
					# add APs if not seen so far
					mac_ap = ieee_handler.bssid_s

					if mac_ap not in self._aps_known:
						logger.debug("adding unknown AP: %s" % mac_ap)
						aps_new.add(mac_ap)
						self._aps_known.add(mac_ap)
					return False
			except Exception as ex:
				logger.debug(ex)
				return False

			addresses = []
			try:
				addresses.append(ieee_handler.src_s)
			except:
				pass
			try:
				addresses.append(ieee_handler.dst_s)
			except:
				pass
			#logger.debug("src=%s, dst=%s" % (addresses[0], addresses[1]))

			found_client = False

			try:
				for addr in addresses:
					# TODO: signal strength?
					#print("======>")
					if addr not in clients_identified \
						and addr not in self._aps_known\
						and not is_special_mac(addr):
						try:
							tags = "%r" % self._db_handler.get_client_tags(addr)
							logger.info("%s (%s) -> (%r), Sig: %d" %
								(addr,
								utils.get_vendor_for_mac(addr[0:8]),
								tags,
								unpack_B(radiotap_pkt.flags[3][1])[0]
								))
						except KeyError:
							pass

						clients_identified.add(addr)
						found_client = True
				#print("<======")
			except AttributeError as ex1:
				# no src_s present, ignore
				logger.exception(ex1)
				pass
			except Exception as ex2:
				logger.exception(ex2)

			return found_client

		channels = None

		if only_active_channels:
			channels = self._ap_channels

		self._harvest(strategy, harvest_time_per_channel_sec=5, channels_to_scan=channels)

		if len(clients_identified) != 0:
			pass
		else:
			logger.info("no clients found")

		self._db_handler.store_aps(aps_new)


class PacketCollector(object):
	def __init__(self, iface_name):
		self._iface_name = iface_name
		self._collect_process = None
		self._packet_queue = None
		self._socket = None
		self._collect_proc = None

	iface = property(lambda self: self._iface_name)

	def _collect_cycler(sockethndl, queue):
		recv_bts = sockethndl.recv
		put_bts = queue.put
		cnt = 0
		cnt_old = 0
		seconds_last = time.time()

		while True:
			try:
				bts = recv_bts()
			except socket.timeout:
				continue

			cnt += 1

			if cnt % 200 == 0:
				print(".", end="")
				sys.stdout.flush()

				seconds_new = time.time()

				if seconds_new - seconds_last > 5:
					logger.debug("%0.2f packets/s, size: %d" % (
						(cnt - cnt_old) / (seconds_new - seconds_last),
						queue.qsize()
					))
					cnt_old = cnt
					seconds_last = seconds_new
			put_bts(bts)

	def start_collecting(self, queue_size=100000, read_timeout_sec=1):
		if self._collect_proc is not None:
			logger.debug("collect process already started")
			return

		#self._packet_queue = SimpleQueue()
		self._packet_queue = Queue(maxsize=queue_size)
		self._sockethndl = psocket.SocketHndl(iface_name=self._iface_name,
			timeout=read_timeout_sec,
			buffersize_recv=2 ** 29)

		self._collect_proc = Process(target=PacketCollector._collect_cycler,
						args=(self._sockethndl, self._packet_queue))
		logger.debug("starting packet collector")
		self._collect_proc.start()

	def stop_collecting(self):
		if self._collect_proc is None:
			logger.debug("no collect process running for termination")
			return

		self._collect_proc.terminate()
		self._collect_proc = None
		self._sockethndl.close()
		self._sockethndl = None
		self._packet_queue = None

		# remove rest of the collected packets (no simpler procedure for this)
		#while not self._packet_queue.empty():
		#	self._packet_queue.get()
		logger.debug("stopped packet collector")

	def __iter__(self):
		while True:
			try:
				yield self._packet_queue.get(timeout=2)
			except:
				raise StopIteration

	def clear(self):
		logger.debug("starting to clear queue")

		try:
			while True:
				self._packet_queue.get(timeout=0.01)
		except:
			pass
		try:
			logger.debug("queue cleared, size: %d" % self._packet_queue.qsize())
		except:
			pass


class FinderShell(cmd.Cmd):
	"""
	Command line interface to control logic.
	"""
	intro = "Mac finder initiated"
	prompt = ">"
	file = None

	def __init__(self, logic, db_handler):
		self._logic = logic
		self._db_handler = db_handler
		cmd.Cmd.__init__(self)

	def do_channel(self, arg):
		try:
			channel = int(arg)
			logger.debug("setting channel to: %d" % channel)
			utils.switch_wlan_channel(self._logic._packet_collector.iface, channel)
		except Exception as ex:
			logger.warning("could not set channel: %r" % ex)
			logger.warning("available channels: %r" % self._logic.channels)

	def do_show_ap_channels(self, _):
		logger.info("%r" % self._logic._ap_channels)

	def do_clear_ap_channels(self, _):
		self._logic.clear_ap_channels()

	def do_colstart(self, _):
		utils.switch_wlan_channel(self._logic._packet_collector.iface, 1)
		self._logic._packet_collector.start_collecting()

	def do_colstop(self, _):
		self._logic._packet_collector.stop_collecting()

	def do_checkparsefail(self, _):
		pktwrite = ppcap.Writer(filename="parsefail.cap")
		cnt = 0

		for bts in self._logic._packet_collector:
			if cnt > 10000:
				break
			cnt += 1
			try:
				pkt = Radiotap(bts)
				pkt.dissect_full()

				for layer in pkt:
					if layer.dissect_error:
						logger.warning("error while parsing (in layer): %r" % ex)
						pktwrite.write(bts)
						break
			except Exception as ex:
				logger.warning("error while parsing: %r" % ex)
				pktwrite.write(bts)

		pktwrite.close()
		logger.warning("parsefail checking finished")

	def do_colclear(self, _):
		self._logic._packet_collector.clear()

	"""
	def do_harvestaps(self, _):
		self._logic.harvest_aps()
	"""

	def do_aps(self, _):
		"""Show all APs."""
		aps = self._logic.aps
		logger.info("got %d aps: " % len(aps))

		for ap in aps:
			logger.info("%17s %s" % (ap, utils.get_vendor_for_mac(ap[0:8])))

	def do_harvestclients(self, arg):
		"""Harvest clients giving tags Parameter: tag1...tagX"""
		tags = [tag for tag in re.split("\s*", arg) if len(tag) > 0]

		if len(tags) == 0:
			logger.warning("not tags defined!")
			return
		self._logic.harvest_clients(tags)

	def complete_harvestclients(self, text, line, begidx, endidx):
		#logger.debug("matching: %s" % text)
		#return ["xxxx", "yyyy"]
		return [tag for tag in self._logic.tags if tag.startswith(text)]

	def do_tags(self, _):
		"""Show all stored tags."""
		logger.info("got %d tags:" % len(self._logic.tags))

		for tag in self._logic.tags:
			logger.info(tag)

	def do_monitor(self, arg):
		"""Track currently seen clients."""
		args = re.split("\s+", arg)
		only_active = False

		if arg == "onlyactive":
			logger.debug("monitoring only active channel, %r" % arg)
			only_active = True

		self._logic.monitor_clients(only_active_channels=only_active)

	def complete_monitor(self, text, line, begidx, endidx):
		return ["onlyactive"]


def main(iface):
	"""initiate database"""
	logger.debug("initiating database")
	engine = create_engine('sqlite:///sqla.db')
	engine.echo = False
	Base.metadata.create_all(engine)
	db_handler = DatabaseHandler(engine)

	"""initiate interface"""
	initial_mode = utils.get_wlan_mode(iface)
	initial_state_up = utils.is_interface_up(iface)
	logger.debug("setting monitor mode on %s" % iface)
	utils.set_interface_mode(iface, monitor_active=True, state_active=True)

	channels = utils.get_available_wlan_channels(iface)

	if len(channels) == 0:
		# set default channels
		logger.debug("no channels found, defaulting to 1->12")
		channels = [ch for ch in range(1, 12)]

	logger.info("available channels: %r" % str(channels))

	"""initiate logic"""
	packetcollector = PacketCollector(iface)
	logic = Logic(db_handler, packetcollector, channels)
	findershell = FinderShell(logic, db_handler)

	try:
		findershell.cmdloop()
	except KeyboardInterrupt:
		# don't mind if user interrupted session
		pass

	"""shutdown everything"""
	logic.shutdown()

	# re-init interface with original configuration
	monitor_active = True if initial_mode == utils.MODE_MONITOR else False
	logger.debug("re-enabling initial interface mode on %s, monitor=%r, active=%r" %
				(iface, monitor_active, initial_state_up))
	utils.set_interface_mode(iface, monitor_active=monitor_active, state_active=initial_state_up)


if __name__ == "__main__":
	# sanity checks
	if len(sys.argv) < 2:
		logger.warning("pleace specify an interface as 1st parameter")
		sys.exit(1)

	main(sys.argv[1])
