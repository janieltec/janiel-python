import logging
import json
import re

from webob import Response

from ryu.app import con_switch_key as cs_key 
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.base import app_manager
from ryu.controller import conf_switch
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.exception import OFPUnknownVersion
from ryu.lib import dpid as dpid_lib
from ryu.lib import mac 
from ryu.lib import ofctl_v1_0
from ryu.lib import ofctl_v1_2
from ryu.lib import ofctl_v1_3
from ryu.lib.ovs import bridge
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from ryu.ofproto import ether
from ryu.ofproto import inet

SWITCHID_PATTERN = dpid_lib.DPID_PATTERN + r '|all'
VLANID_PATTERN = r '[0-9]{1,4}|all'
QOS_TABLE_ID = 0

REST_ALL = 'all'
REST_SWITCHID = 'switch_id'
REST_COMMAND_RESULT ='command_result'
REST_PRIORITY = 'priority'
REST_VLANID = 'vlan_id'
REST_DL_VLAN = 'dl_vlan'
REST_PORT_NAME = 'port_name'
REST_QUEUE_TYPE = 'type'
REST_QUEUE_MAX_RATE = 'max_rate'
REST_QUEUE_MIN_RATE = 'min_rate'
REST_QUEUES = 'queues'
REST_QOS = 'qos'
REST_QOS_ID = 'qos_id'
REST_COOKIE = 'cookie'

REST_MACTH = 'match'
REST_IN_PORT = 'in_port'
REST_SRC_MAC = 'dl_src'
REST_DST_MAC = 'dl_dst'
REST_DL_TYPE  = 'dl_type'
REST_DL_TYPE_ARP = 'ARP'
REST_DL_TYPE_IPV4 = 'IPv4'
REST_DL_TYPE_IVP6 = 'IPv6'
REST_DL_VLAN = 'dl_vlan'
REST_SRC_IP = 'nw_src'
REST_DST_IP = 'nw_dst'
REST_SRC_IPV6 = 'ipv6_src'
REST_DST_IPV6 = 'ipv6_dst'
REST_NW_PROTO = 'nw_proto'
REST_NW_PROTO_TCP = 'TCP'
REST_NW_PROTO_UDP = 'UDP'
REST_NW_PROTO_ICMP = 'ICMP'
REST_NW_PROTO_ICMPv6 = 'ICMPv6'
REST_TP_SRC = 'tp_src'
REST_TP_DST = 'tp_dst'
REST_DSCP = 'ip_dscp'

REST_ACTION = 'actions'
REST_ACTION_QUEUE = 'queue'
REST_ACTION_MARK = 'mark'
REST_ACTION_METER = 'meter'

REST_METER_ID = 'meter_id'
REST_METER_BURST_SIZE = 'burst_size'
REST_METER_RATE = 'rate'
REST_METER_PREC_LEVEL_ = 'prec_level'
REST_METER_BANDS = 'bands'
REST_METER_ACTION_DROP = 'drop'
REST_METER_ACTION_REMARK = 'remark'

DEFAULT_FLOW_PRIORITY = 0
QOS_PRIORITY_MAX = ofproto_v1_3_parser.UINT16_MAX -1
QOS_PRIORITY_MIN = 1

VLANID_NONE =0
VLANID_MIN = 2
VLANID_MAX = 4094
COOKIE_SHIFT_VLANID = 32

BASE_URL = '/qos'
REQUIREMENTS = {'switchid': SWITCHID_PATTERN,
				 'vlanid': VLANID_PATTERN}

LOG = loggin.getLogger(__name__)

class RestQoSAPI(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION,
					ofproto_v1_2.OFP_VERSION,
					ofproto_v1_3.OFP_VERSION]

	_CONTEXTS = {
		'dpset': dpset.DPSet,
		'conf_switch': conf_switch.ConfSwitchSet,
		'wsgi':WSGIApplication }

	def __init__(self, *args, **kwargs):
		super(RestQoSAPI, self).__init__(*args, **kwargs)

		#logger configure
		QoSController.set_logger(self.logger)
		self.cs = kwargs['conf_switch']
		self.dpset = kwargs['dpset']
		wsgi = kwargs['wsgi']
		self.waiters = {}
		self.data = {}
		self.data['dpset'] = self.dpset
		self.data['waiters'] = self.waiters	
		wsgi.registory['QoSController'] = self.data
		wsgi.register(QosController, self.data)

	def stats_reply_handler(self,ev):
		msg = ev.msg
		dp = msg.datapath
		if dp.id not in self.waiters:
			return
		if msg.xid not in self.waiters[dp.id]:
			return

		lock, msgs  = self.waiters[dp.id][msg.xid]
		msgs.append(msg)

		flags = 0
		if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION or \
				dp.ofproto.OFP_VERSION == ofproto_v1_2.OFP_VERSION:
			flags  = dp.ofproto.OFPSF_REPLY_MORE
		elif dp.ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
			flags = dp.ofproto.OFPMPF_REPLY_MORE

		if msg.flags & flags:
			return
		del self.waiters[dp.id][msg.xid]
		lock.set()

	@set_ev_cls(conf_switch.EventConfSwitchSet)
	def conf_switch_set_handler(self, ev):
		if ev.key == cs_key.OVSDB_ADDR:
			QoSController.set_ovsdb_addr(ev.dpid, ev.value)
		else:
			QoSController._LOGGER.debug("unknown event: %s", ev)

	@set_ev_cls(conf_switch.EventConfigSwitchDel)
	def conf_switch_del_handler(self, dev):
		if ev.key == cs_key.OVSDB_ADDR:
			QoSController.delete_ovsdb_addr(dv.dpid)
		else:
			QoSController._LOGGER.debug("unknown event: %s", ev)

	#for OpenFlow version1.0
	@set_ev_cls(ofp_event.EventDP, dpset.DPSET_EV_DISPATCHER)
	def handler_datapath(self, ev):
		if ev.enter:
			QoSController.regist_ofs(ev.dp, self.CONF)
		else:
			QoSController.unregist_ofs(ev.dp)

	#for OpenFlow version1.2 or latter
	@set_ev_cls(ofp_event.EventOFPStatsReply, MAIN_DISPATCHER)
	def stats_reply_handler_v1_2(self, ev):
		self.stats_reply_handler(ev)

	#for OpenFow version1.2 or later
	@set_ev_cls(ofp_event.EventOFPQueueStatsReply, MAIN_DISPATCHER)
	def queue_stats_reply_handler_v1_2(self, ev):
		self.stats_reply_handler(ev)

	#for OpenFlow version1.2 or later
	@set_ev_cls(ofp_event.EventOFPMeterStatsReply, MAIN_DISPATCHER)
	def meter_stats_reply_handler_v1_2(self, ev):
		self.stats_reply_handler(ev)

class QoSOfsList(dict):
	def __init__(self):
		super(QoSOfsList, self).__init__()

	def get_ofs(self, dp_id):
		

