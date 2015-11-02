"""
Network traffic visualizer.

Requirements:
	graphviz
	pygraphviz
"""
import logging
import time
import random
import threading

logger = logging.getLogger("pypacker")

try:
	import pygraphviz as pgv
except Exception as e:
	logger.warning("Unable to load pygraphviz")
	logger.exception(e)


GETATTR_DEFAULTS = {
	"_n": lambda: 0, "_s": lambda: "", "_b": lambda: bool(False),
	"_y": lambda: b"", "_l": lambda: list(), "_d": lambda: dict(),
	"_e": lambda: set()
}


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

	try:
		value = GETATTR_DEFAULTS[name[-2:]]()
		#print("setting initial value: %r, char for type: %r " % (value, name[-2:]))
		# logger.debug("suffix: %s" % value)
	except:
		raise AttributeError()

	object.__setattr__(self, name, value)
	return value

# Monkey patching:
# Allow auto creation of variables for convenience.
# This comes in handy when implementing "config_cb"
pgv.agraph.Edge.__getattr__ = __getattr__autocreate
pgv.agraph.Node.__getattr__ = __getattr__autocreate


class Visualizer(object):
	"""
	Vizualizer using graphviz to visualize nodes in a network.
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
	node_timeout -- timeout until node vanishes in seconds, default is 60
	#update_interval -- update interval for drawing in seconds, default is 1
	"""
	def __init__(self,
			iterable,
			src_dst_cb,
			config_cb,
			cleanup_interval=10,
			output_update_interval=5,
			filename_image="graph.png"):
		# given params
		self._iterable = iterable
		self._src_dst_cb = src_dst_cb
		self._config_cb = config_cb
		self._cleanup_interval = cleanup_interval
		self._output_update_interval = output_update_interval
		self._filename_image = filename_image

		self._packet_update_thread = threading.Thread(target=self._packet_read_cycler)
		self._graphics_update_thread = threading.Thread(target=self._graphics_cycler)

		self._is_stopped = True
		self._is_terminated = False

		self._last_cleanup = time.time()

		graph = pgv.AGraph(ranksep="2", directed=True)
		#graph.graph_attr["label"] = "Graphname"
		# TODO: iterate through all possibilities until we found one
		#graph.graph_attr["layout"] = "neato"
		graph.graph_attr["scale"] = "1.5"
		graph.graph_attr["defaultdist"] = "100"
		graph.graph_attr["mindist"] = "5"
		#graph.graph_attr["sep"] = "10"
		graph.graph_attr["splines"] = "true"
		#graph.graph_attr["mode"] = "KK"
		graph.graph_attr["overlap"] = "false"
		#graph.graph_attr["overlap"] = "ipsep"

		graph.node_attr["shape"] = "box"
		graph.node_attr["height"] = 0.1
		graph.node_attr["fontcolor"] = "#000000"
		#graph.node_attr["style"] = "filled"
		graph.node_attr["fontsize"] = "8"
		#graph.node_attr["labelfontsize"] = "10"
		graph.node_attr["fontname"] = "Helvetica"
		graph.node_attr["imagescale"] = "true"
		#graph.node_attr["fixedsize"] = "true"
		graph.node_attr["group"] = "true"

		graph.edge_attr["color"] = "#000000"
		graph.edge_attr["fontsize"] = "8"
		#graph.node_attr["labelfontsize"] = "10"
		graph.edge_attr["fontname"] = "Helvetica"
		graph.edge_attr["arrowhead"] = "open"
		graph.edge_attr["arrowtail"] = "open"
		graph.edge_attr["arrowsize"] = "0.4"
		#graph.edge_attr["dir"] = "both"

		graph.layout()
		self._graph = graph

	def _cleanup_graph(self):
		"""
		Remove vertices (+ attached edges) which are too old.
		"""
		pass

	def _packet_read_cycler(self):
		"""
		Read packets from _iterable and update graph data until StopIteration
		is thrown by it or Visualizer is stopped.
		Take packets (pkt) instead of eg raw bytes for _src_dst_cb and _config_cb:
		avoid unneeded reparsing.
		"""
		cnt = 0

		for pkt in self._iterable:
			cnt += 1
			#if cnt > 4:
			#	logger.debug("pausing...")
			#	time.sleep(999)
			if self._is_stopped:
				break
			# analyze packet and update graph
			src, dst = self._src_dst_cb(pkt)

			if src is None:
				continue

			graph = self._graph
			edge = None

			# check if already present, reuse existent
			try:
				edge = graph.get_edge(dst, src)
				edge.attr["dir"] = "both"
				# logger.debug("reused edge!")
			except KeyError:
				graph.add_edge(src, dst)
				edge = graph.get_edge(src, dst)
			current_time = time.time()

			node_src = graph.get_node(src)
			node_src._time = current_time
			node_dst = graph.get_node(dst)
			node_dst._time = current_time

			self._config_cb(pkt,
					node_src,
					node_dst,
					edge
			)

		logger.debug("finished iterating packets")

	def _graphics_cycler(self):
		while not self._is_terminated:
			time.sleep(self._output_update_interval)
			current_time = time.time()

			if current_time - self._last_cleanup > self._output_update_interval:
				self._cleanup_graph()
				self._last_cleanup = current_time

			# logger.debug("drawing to: %s" % self._filename_image)
			self._graph.layout("neato")
			self._graph.draw(self._filename_image)

	def start(self):
		if self._is_terminated:
			return
		logger.debug("starting visualizer")

		self._is_stopped = False

		self._graphics_update_thread.start()
		self._packet_update_thread.start()

	def stop(self):
		if self._is_terminated:
			return
		logger.debug("stopping visualizer")

		self._is_terminated = True
		self._is_stopped = True

"""
Node/Edge attributes:
http://www.graphviz.org/doc/info/attrs.html

Some examples:
	color		"#000000"
	label		"label"
	height		"100"
	width		"100"
	shape		"circle"
	fixedsize	"true"
	fontsize
	stely		filled
	outputorder
	ratio		"1.0"
	style		"setlinewidth(2)"
"""
