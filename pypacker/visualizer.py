"""
Network traffic visualizer framework using Graph Tool and GTK+

Requirements:
	graph-tool (>=v2.2.31)
	gtk+ libraries (>=3.12.2)

Graph tool sources:
	http://graph-tool.skewed.de/download
	http://graph-tool.skewed.de/static/doc/quickstart.html

Installation Note:
	Compiling Graph tool needs a whole lot of memory (>4GiB). On a 32Bit system you
	are encouraged to use the newst gcc compiler in order to minimize memory
	usage (gcc v4.8.3 worked on graph-tool v2.2.31)
"""
import logging
import time
import random
import threading

logger = logging.getLogger("pypacker")

try:
	import graph_tool
	from graph_tool import Graph, Vertex, Edge, GraphView
	from graph_tool.draw import arf_layout, sfdp_layout, fruchterman_reingold_layout, radial_tree_layout, GraphWindow
	from gi.repository import Gtk, GObject
except Exception as e:
	logger.warning("Could not find graph-tool and/or Gtk+ libs which are needed for visualizer")
	logger.exception(e)

_key_listener = []


def key_press_event(self, widget, event):
	r"""Handle key press."""

	# print(event.keyval)
	if event.keyval == 114:
		self.fit_to_window()
		self.regenerate_surface(timeout=50)
		self.queue_draw()
	elif event.keyval == 115:
		self.reset_layout()
	elif event.keyval == 97:
		self.apply_transform()
	elif event.keyval == 112:
		if self.picked is False:
			self.init_picked()
		else:
			self.picked = False
			self.selected.fa = False
			self.vertex_matrix = None
			self.queue_draw()
	elif event.keyval == 0x7a:
		if isinstance(self.picked, PropertyMap):
			u = GraphView(self.g, vfilt=self.picked)
			self.fit_to_window(g=u)
			self.regenerate_surface(timeout=50)
			self.queue_draw()
	# key "t": call listener callbacks and update layout
	elif event.keyval == 116:
		# print("resetting positions")
		for l in _key_listener:
			l()
		self.apply_transform()
		self.reset_layout()
	return True

# add new listener: press "t" to reorder node effectively
graph_tool.draw.gtk_draw.GraphWidget.key_press_event = key_press_event


def config_cb_default(packet, vertex_src, vertex_dst, edge, vertexprop_dict, edgeprop_dict):
	"""
	Default configuration callback.
	"""
	vertexprop_dict["text"][vertex_src] = "N"

	if vertex_dst is not None:
		vertexprop_dict["text"][vertex_dst] = "N"
		edgeprop_dict["text"][edge] = "E"


def __getattr__autocreate(self, name):
	"""
	Set default values for unknown variables having names suffix like:
	_n = 0
	_s = ""
	_b = False
	_y = b""
	_l = []
	_d = {}
	_e = set()
	"""
	defaults = {"_n": 0, "_s": "", "_b": False, "_y": b"", "_l": [], "_d": {}, "_e": set()}

	try:
		value = defaults[name[-2:]]
		# logger.debug("suffix: %s" % value)
	except:
		raise AttributeError()

	object.__setattr__(self, name, value)
	return value

# Allow auto creation of variables for convenience.
# This comes in handy when implementing "config_cb"
Vertex.__getattr__ = __getattr__autocreate
Edge.__getattr__ = __getattr__autocreate


class Visualizer(object):
	"""
	Vizualizer using graph-tool to visualize nodes in a network.
	Note: xxx_cb is callback returning values stated in the desriptions.
	Livecycle: stopped - started (paused <-> running) - stopped (terminated)


	iterable -- an object which is iterable and returns packets, raises StopIteration on EOF
	src_dst_cb -- returns list like [source, destination] or [source, None] eg ["127.0.0.1", "127.0.0.2"].
		Destination can be set to None eg for broadcast-packets. If both are not None an edge will be
		added automatically. Source/destination must uniquely identify a node.
		Callback-structure: fct(packet)
	config_cb -- updates a dict representing the current node-config
		Callback-structure: fct(packet, vertex_src, vertex_dst, edge, vertex_props, edge_props).
		In order to store additional data (like number of total packets from this source) save
		them in the vertex-object itself like "vertex_src.my_data=123".
	additional_vertexprops -- additional vertex properties to be added via [name, format, defaultvalue]
		Property definitions: http://graph-tool.skewed.de/static/doc/draw.html
	additional_edgeprops -- additional properties to be added via [name, format, defaultvalue]
		Property definitions: http://graph-tool.skewed.de/static/doc/draw.html
	node_timeout -- timeout until node vanishes in seconds, default is 60
	#update_interval -- update interval for drawing in seconds, default is 1
	"""
	def __init__(self, iterable,
			src_dst_cb,
			config_cb=config_cb_default,
			node_timeout=10,
			update_interval=1,
			additional_vertexprops=[],
			additional_edgeprops=[]):
		# given params
		self._iterable = iterable
		self._src_dst_cb = src_dst_cb
		self._config_cb = config_cb
		self._node_timeout = node_timeout
		# self._update_interval = update_interval
		# additional fields
		self._graphics_start_thread = threading.Thread(target=self._start_graphics)
		self._packet_update_thread = threading.Thread(target=self._packet_read_loop)
		self._packet_update_sema = threading.Semaphore(value=0)
		# removing vertices/edges in parallel makes trouble, synchronize update and graphics thread
		self._cleanup_sema = threading.Semaphore(value=0)
		self._want_cleanup = False
		self._cleanup_vertices = []
		# temporarily paused
		self._is_paused = True
		self._is_stopped = True
		# is visualizer definitely terminated?
		self._is_terminated = False
		#
		self._last_cleanup = time.time()
		# self._last_graphic_update = self._last_cleanup

		# self._psocket = None

		# dict: unique name (src) -> vertex object
		self._vertices_dict = {}
		# dict: unique name (src_dst) -> edge object
		self._edges_dict = {}

		# name : object
		self._vertex_properties = {}
		# name : default value
		self._vertex_properties_defaultvalues = {}
		self._vertex_livetime = {}
		self._edge_properties = {}
		# name : default value
		self._edge_properties_defaultvalues = {}

		self._init_graphwindow(additional_vertexprops, additional_edgeprops)

		# add reset-callback listener called when pressing "t"
		# only 1 instance allowed, old one will be removed
		_key_listener.clear()
		_key_listener.append(self._reset_positions)

	# TODO: more default properties
	DEFAULT_PROPERTIES_VERTEX = [["text", "string", "NODE!!!"],
					["size", "int", 50],
					["shape", "string", "circle"],
					["color", "vector<float>", [0, 0, 0, 0.0]],
					["fill_color", "vector<float>", [1, 1, 1, 0.0]],
					["halo", "bool", False],
					["halo_color", "vector<float>", [1, 0, 0, 0.4]]
					]

	DEFAULT_PROPERTIES_EDGE = [["text", "string", "EDGE!!!"],
					["color", "vector<float>", [0, 0, 0, 1]],
					["dash_style", "vector<float>", []]
					]

	def _init_graphwindow(self, additional_vertexprops=[], additional_edgeprops=[]):
		self._graph = Graph(prune=True, directed=False)
		# load properties
		self._positions = self._graph.new_vertex_property("vector<float>")

		for prop in Visualizer.DEFAULT_PROPERTIES_VERTEX + additional_vertexprops:
			self._add_property(True, prop)
		for prop in Visualizer.DEFAULT_PROPERTIES_EDGE + additional_edgeprops:
			self._add_property(False, prop)

		# pos = fruchterman_reingold_layout(self._graph, pos=self._positions)
		pos_layout = sfdp_layout(self._graph, K=10, verbose=True, pos=self._positions)
		# pos_layout = sfdp_layout(self._graph)
		# pos = radial_tree_layout(self._graph, 0)
		# pos_layout = self._positions
		self._graphwindow = GraphWindow(
			self._graph,
			# update_layout=True,
			# pos=self._positions,
			pos=pos_layout,
			# TODO: make this dynamic
			geometry=(400, 300),
			vertex_font_size=10,
			vertex_pen_width=1,
			# vertex_text_offset=[0,0],
			vprops=self._vertex_properties,
			edge_font_size=10,
			edge_pen_width=1,
			# edge_marker_size=12,
			# markers added allthough undirected???
			# edge_start_marker="arrow",
			# edge_end_marker="arrow",
			# edge_text_distance=2,
			eprops=self._edge_properties)

		# set optimal distance in order to make auto-layout working
		# self._graphwindow.graph.layout_K = 40
		# minimum 1 vertex on graph (avoid bug in graph-tool which leads to division by zero)
		# TODO: remove
		logger.debug("adding initial vertices")
		self._update_vertices("A", "B")
		self._update_vertices("B", "A")
		"""
		self._update_vertices("A", "C")
		self._update_vertices("A", "D")
		self._update_vertices("D", None)
		self._update_vertices("E", None)
		self._update_vertices("F", None)
		self._update_vertices("G", None)
		self._update_vertices("H", None)
		self._update_vertices("I", None)
		self._update_vertices("J", None)
		self._update_vertices("K", None)
		self._update_vertices("L", None)
		self._update_vertices("M", None)
		self._update_vertices("M", "L")
		self._update_vertices("M", "F")
		self._update_vertices("A", "F")
		self._update_vertices("F", "F")
		self._update_vertices("K", "L")
		self._update_vertices("A", "L")
		"""

	def _add_property(self, for_vertex, property_config):
		"""
		Add a new property to be modified.

		for_vertex -- add vertex property if True, else add an edge property
		property_config -- property description like as list: ["name", "type_description", default_value]
		"""
		logger.debug("adding property (%s): %r" % ("vertex" if for_vertex else "edge", property_config))

		if for_vertex:
			property = self._graph.new_vertex_property(property_config[1])
			self._vertex_properties[property_config[0]] = property
			self._vertex_properties_defaultvalues[property_config[0]] = property_config[2]
		else:
			property = self._graph.new_edge_property(property_config[1])
			self._edge_properties[property_config[0]] = property
			self._edge_properties_defaultvalues[property_config[0]] = property_config[2]

	def _cleanup_graph(self, current_time):
		"""
		Remove vertices (+ attached edges) which are too old.
		"""
		logger.debug("cleaning up graph")
		vertex_remove_local = []

		for name, last_update in self._vertex_livetime.items():
			if current_time - last_update > self._node_timeout:
				vertex_remove_local.append(name)
				vertex = self._vertices_dict[name]
				logger.debug("vertex to remove: %r" % vertex)
				# edges in graph should be removed automatically
				self._cleanup_vertices.append(vertex)

		self._want_cleanup = True
		# wait until graphics thread has removed vertices
		logger.debug("waiting until vertices are removed")
		self._cleanup_sema.acquire()

		for name in vertex_remove_local:
			del self._vertex_livetime[name]
			del self._vertices_dict[name]
			# vertex can be placed as _edges_dict[name][...] or _edges_dict[...][name]
			try:
				del self._edges_dict[name]
			except KeyError:
				# name not present
				pass

			for vertex_a in self._edges_dict:
				try:
					del self._edges_dict[vertex_a][name]
				except KeyError:
					# name not present
					pass
		logger.debug("finished removing local vertices")

	def _add_vertex(self):
		"""
		Place a new vertex at a random position.

		return -- the newly added vertex
		"""
		# random position in start
		# TODO: width/height
		random.seed(time.time())
		x = random.randint(10, 100)
		random.seed(time.time() + 1)
		y = random.randint(10, 100)
		vertex = self._graph.add_vertex()
		self._positions[vertex] = (x, y)
		# self._positions[vertex] = (50.0, 50.0)
		# TODO: find better place for this
		# self._reset_positions()
		return vertex

	def _reset_positions(self):
		"""
		Put all vertices in a close distance in order to reorder them fast afterwards.
		"""
		# logger.debug("resetting")
		cnt = 1

		for name, vertex in self._vertices_dict.items():
			random.seed(cnt + time.time())
			x = random.randint(1, 10)
			random.seed(cnt + time.time() + 1)
			y = random.randint(1, 10)
			self._positions[vertex] = (x, y)
			cnt += 1

	def _update_vertices(self, src, dst=None):
		"""
		Add new vertex identified by src (and dst + edge between them) if not allready present.

		src -- unique source string
		dst -- unique destination string or None
		return -- vertex_source, vertex_dest, edge where vertex_dest and edge can be None
		"""
		vertex_to_update = []

		# create new vertex
		try:
			vertex_src = self._vertices_dict[src]
		except KeyError:
			vertex_src = self._add_vertex()
			self._vertices_dict[src] = vertex_src
			vertex_to_update.append(vertex_src)

		vertex_dst = None
		edge_src_dst = None

		if dst is not None:
			# initiate dst and add edge between src<->dst
			try:
				vertex_dst = self._vertices_dict[dst]
			except KeyError:
				vertex_dst = self._add_vertex()
				self._vertices_dict[dst] = vertex_dst
				vertex_to_update.append(vertex_dst)

			edge = sorted([src, dst])
			add_edge = False

			try:
				edge_src_dst = self._edges_dict[edge[0]][edge[1]]
			except KeyError:
				if not edge[0] in self._edges_dict:
					self._edges_dict[edge[0]] = {}
				add_edge = True

			if add_edge:
				# TODO: don't add second edge but update arrows (both directions)
				edge_src_dst = self._graph.add_edge(vertex_src, vertex_dst)
				self._edges_dict[edge[0]][edge[1]] = edge_src_dst
				# logger.debug("!!!!! adding edge")
				# set default property values for edge
				for k, v in self._edge_properties_defaultvalues.items():
					# logger.debug("edge default val: %r: %s=%s" % (self._edge_properties[k], k, v))
					self._edge_properties[k][edge_src_dst] = v

		for vertex in vertex_to_update:
			# set default property values for vertices
			for k, v in self._vertex_properties_defaultvalues.items():
				# logger.debug("vertex default val: %r: %s=%s" % (self._vertex_properties[k], k, v))
				self._vertex_properties[k][vertex] = v

		return vertex_src, vertex_dst, edge_src_dst

	def _packet_read_loop(self):
		"""
		Read packets from _iterable and update graph data until StopIteration
		is thrown by it or Visualizer is stopped.
		Take packets (pkt) instead of eg raw bytes for _src_dst_cb and _config_cb:
		avoid unneeded reparsing.
		"""
		for pkt in self._iterable:
			# time.sleep(1)
			if self._is_paused:
				self._packet_update_sema.acquire()
			if self._is_stopped:
				break
			# analyze packet and update graph
			src, dst = self._src_dst_cb(pkt)

			if src is None:
				continue

			vertex_src, vertex_dst, edge = self._update_vertices(src, dst)

			self._config_cb(pkt,
					vertex_src,
					vertex_dst,
					edge,
					self._vertex_properties,
					self._edge_properties)
			# cleanup logic
			current_time = time.time()

			if dst is not None:
				self._vertex_livetime[dst] = current_time

			self._vertex_livetime[src] = current_time

			if current_time - self._last_cleanup > self._node_timeout:
				# TODO: temporarily disabled
				# self._cleanup_graph(current_time)
				self._last_cleanup = current_time

		logger.debug("finished iterating packets")

	def _update_graphics(self):
		if self._want_cleanup:
			for vertex in self._cleanup_vertices:
				logger.debug("removing vertex: %r" % vertex)
				# remove in/out-edges
				self._graph.clear_vertex(vertex)
				# nomen est omen
				self._graph.remove_vertex(vertex)
			self._cleanup_vertices.clear()
			self._want_cleanup = False
			self._cleanup_sema.release()

		# self._graphwindow.graph.regenerate_surface(lazy=True)
		self._graphwindow.graph.regenerate_surface(lazy=False)
		self._graphwindow.graph.queue_draw()
		return True

	def _start_graphics(self):
		logger.debug("initiating graphics")

		# cid = GObject.idle_add(self._update_graphics)
		cid = GObject.timeout_add(150, self._update_graphics)
		self._graphwindow.connect("delete_event", Gtk.main_quit)
		self._graphwindow.show_all()
		Gtk.main()
		logger.debug("window was closed...stopping")
		# no graphics = window was closed = nothing to be done anymore
		self.stop()

	def start(self):
		if self._is_terminated:
			return
		logger.debug("starting visualizer")

		self._is_stopped = False
		self._is_paused = False

		self._graphics_start_thread.start()
		self._packet_update_thread.start()

	def pause(self):
		if self._is_stopped:
			return
		logger.debug("pausing visualizer")
		self._is_paused = True

	def resume(self):
		if self._is_stopped:
			return
		logger.debug("resuming visualizer")

		self._is_paused = False
		# TODO: check locking mechanisms
		self._packet_update_sema.release()

	def stop(self):
		if self._is_terminated:
			return
		logger.debug("stopping visualizer")

		self._is_terminated = True
		# unlock locked packet-reader
		self.resume()
		self._is_stopped = True
