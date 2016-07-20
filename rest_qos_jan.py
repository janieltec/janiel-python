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

SWITCHID_PATTERN = dpid_lib.DPID_PATTERN + r'|all'
VLANID_PATTERN = r'[0-9]{1,4}|all'
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
		if len(self) == 0:
			raise ValueError('qos sw is not connect')

		dps = {}
		if dp_id == REST_ALL:
			dps = self
		else:
			try:
				dpid = dpid_lib.str_to_dpid(dp_id)
			except:
				raise ValueError('Invalid switchID.')
			if dpid in self:
				dps = {dpid: self[dpid]}
			else:
				msg = 'qos sw is not connected. : switchID = %s' % dp_id
				raise ValueError(msg)
		return dps

class QoSController(ControllerBase):
	_OFS_LIST = QoSOfList()
	_LOGGER = None 

	def __init__(self, req, link, data, **config):
		super(QoSController, self).__init__(req, link, data, **config)
		self.dpset = data['dpset']
		self.waiters = data['waiters']
		hdlr = logging.StreamHandler()
		fmt_str = '[QoS][%(levelname)s] %(message)s'
		hdlr.setFormatter(logging.Formatter(fmt_str))
		cls._LOGGER.addHandler(hdlr)

	@staticmethod
	def regist_ofs(dp, CONF):
		if dp.id in QoSController._OFS_LIST:
			return

		dpid_str = dpid_lib.dpid_to_str(dp.id)
		try:
			f_ofs = QoS(dp, CONF)
			f_fos.set_default_flow()

		except OFPUnknownVersion as message:
			QoSController._LOGGER.info('dpid=%s: %s', dpid_str, message)
			return

		QoSController._OFS_LIST.setdefault(dp.id, f_ofs)
		QoSController._LOGGER.info('dpid=%s: Join qos switch.', dpid_str)

	@staticmethod
	def unregist_ofs(dp):
		if dp.id in QoSController._OFS_LIST:
			del QosController._OFS_LIST[dp.id]
			QoSController._LOGGER.info('dpid=%s: Leave qos switch.', dpid_lib.dpid_to_str(dp.id))

	@staticmethod
	def set_ovsdb_addr(dpid, value):
		ofs = QosController._OFS_LIST.get(dpid, None)
		if ofs is not None:
			ofs.set_ovsdb_addr(dpid, value)

	@staticmethod
	def delete_ovsdb_addr(dpid):
		ofs = QoSController._OFS_LIST.get(dpid, None)
		ofs.set_ovsdb_addr(dpid, None)

	@route('qos_switch', BASE_URL + '/queue/{switchid}', method=[GET], requirements = REQUIREMENTS)
	def get_queue(self, req, switchid, **_kwargs):
		return self._access_switch(req, switchid, VLANID_NONE, 'get_queue', None)	

	@route('qos_switch', BASE_URL + '/queue/{switchid}', method=[POST], requirements = REQUIREMENTS)
	def set_queue(self, req, switchid, **_kwargs):
		return self._access_switch(req, switchid, VLANID_NONE, 'set_queue', None)	

	@route('qos_switch', BASE_URL + '/queue/{switchid}', method=[DELETE], requirements = REQUIREMENTS)
	def delete_queue(self, req, switchid, **_kwargs):
		return self._access_switch(req, switchid, VLANID_NONE, 'delete_queue', None)	

	@route('qos_switch', BASE_URL + '/queue/status{switchid}', method=[GET], requirements = REQUIREMENTS)
	def get_status(self, req, switchid, **_kwargs):
		return self._access_switch(req, switchid, VLANID_NONE, 'get_status', None)	

	@route('qos_switch', BASE_URL + '/rules/{switchid}', method=[GET], requirements = REQUIREMENTS)
	def get_qos(self, req, switchid, **_kwargs):
		return self._access_switch(req, switchid, VLANID_NONE, 'get_qos', None)	

	@route('qos_switch', BASE_URL + '/rules/{switchid}/{vlanid}', method=[GET], requirements = REQUIREMENTS)
	def get_vlan_qos(self, req, switchid, vlanid, **_kwargs):
		return self._access_switch(req, switchid, vlanid, 'get_qos', None)	

	@route('qos_switch', BASE_URL + '/rules/{switchid}', method=[POST], requirements = REQUIREMENTS)
	def set_qos(self, req, switchid, **_kwargs):
		return self._access_switch(req, switchid, VLANID_NONE, 'set_qos', None)	

	@route('qos_switch', BASE_URL + '/rules/{switchid}/{vlanid}', method=[POST], requirements = REQUIREMENTS)
	def set_vlan_qos(self, req, switchid, vlanid, **_kwargs):
		return self._access_switch(req, switchid, vlanid, 'set_qos', None)	

	@route('qos_switch', BASE_URL + '/rules/{switchid}', method=[DELETE], requirements = REQUIREMENTS)
	def delete_qos(self, req, switchid, **_kwargs):
		return self._access_switch(req, switchid, VLANID_NONE, 'delete_qos', None)	

	@route('qos_switch', BASE_URL + '/rules/{switchid}/{vlanid}', method=[DELETE], requirements = REQUIREMENTS)
	def delete_vlan_qos(self, req, switchid, vlanid, **_kwargs):
		return self._access_switch(req, switchid, vlanid, 'delete_qos', None)	

	@route('qos_switch', BASE_URL + '/meter/{switchid}', method=[GET], requirements = REQUIREMENTS)
	def get_meter(self, req, switchid, **_kwargs):
		return self._access_switch(req, switchid, VLANID_NONE, 'get_meter', None)	

	@route('qos_switch', BASE_URL + '/meter/{switchid}', method=[POST], requirements = REQUIREMENTS)
	def set_meter(self, req, switchid, **_kwargs):
		return self._access_switch(req, switchid, VLANID_NONE, 'set_meter', None)	

	@route('qos_switch', BASE_URL + '/meter/{switchid}', method=[DELETE], requirements = REQUIREMENTS)
	def delete_meter(self, req, switchid, **_kwargs):
		return self._access_switch(req, switchid, VLANID_NONE, 'delete_meter', None)	

	def _access_switch(self, req, switchid, vlan_id, func, waiters):
		try:
			rest = json.loads(req.body) if req.body else {}
		except SyntaxError:
			QoSController._LOGGER.debug('invalid syntax %s', req.body)
			return Response(status=400)

		try:
			dps = self._OFS_LIST.get_ofs(switchid)
			vid = QoSController._conv_toint_vlanid(vlan_id)
		except ValueError as message:
			return Response(status = 400, body =str(message))

		msgs = []
		for f_ofs in dps.values():
			function = getattr(f_ofs, func)
			try:
				if waiters is not None:
					msg = function(rest, vid, waiters)
				else:
					msg = function(rest, vid)

			except ValueError as message:
				return Response(status=400, body = str(message))
			msgs.append(msg)
		body = json.dumps(msgs)
		return Response(content_type= 'application/json', body=body)

	@staticmethod
	def _conv_toint_vlanid(vlan_id):
		if vlan_id != REST_ALL:
			vlan_id = int(vlan_id)
			if (vlan_id != VLANID_NONE and (vlan_id < VLANID_MIN or vlan_id > VLANID_MAX)):
				msg = 'Invalid {vlan_id} value. Set [%d-%d]' %(VLANID_MIN, VLANID_MAX)
				raise ValueError(msg)

		return vlan_id

class QoS(object):
	_OFCTL = {ofproto_v1_0.OFP_VERSION: ofctl_v1_0,
				ofproto_v1_2.OFP_VERSION: ofctl_v1_2,
				ofproto_v1_3.OFP_VERSION: ofctl_v1_3}
	def __init__(self, dp, CONF):
		super(QoS, self).__init__()
		self.vlan_list = {}
		self.vlan_list[VLANID_NONE] = 0
		self.dp = dp
		self.version = dp.ofproto.OFP_VERSION
		self.queue_list = {}
		self.CONF = CONF
		self.ovsdb_addr = None
		self.ovs_bridge = None

		if self.version not in self._OFCTL:
			raise OFPUnknownVersion(version  = self.version)

		self.ofctl = self._OFCTL[self.version]

	def set_default_flow(self):
		if self.version == ofproto_v1_0.OFP_VERSION:
			return

		cookie = 0
		priority = DEFAULT_FLOW_PRIORITY
		actions = [{'type': 'GOTO_TABLE', 'table_id': QOS_TABLE_ID + 1}]
		flow = self._to_of_flow(cookie=cookie, priority=priority, match={}, actions=actions)
		cmd = self.dp.ofproto.OFPFC_ADD
		self.ofctl.mod_flow_entry(self.dp,flow, cmd)

	def set_ovsdb_addr(self, dpid, ovsdb_addr):
		_proto, _host, _port = ovsdb_addr.split(':')

		old_address = self.ovsdb_addr
		if old_address == ovsdb_addr:
			return

		if old_address is None:
			if self.ovs_bridge:
				self.ovs_bridge.del_controller()
				self.ovs_bridge = None
			return
		self.ovsdb_addr = ovsdb_addr
		if self.ovs_bridge is None:
			ovs_bridge = bridge.OVSBridge(self.CONF, dpid, ovsdb_addr)
			self.ovs_bridge = ovs_bridge
			try:
				ovs_bridge.init()
			except:
				raise ValueError('ovsdb addr is not available.')

	def _update_vlan_list(self, vlan_list):
		for vlan_id in self.vlan_list.keys():
			if vlan_id is not VLANID_NONE and vlan_id not in vlan_list:
				del self.vlan_list[vlan_id]

	def _get_cookie(self, vlan_id):
		if vlan_id == REST_ALL:
			vlan_ids = self.vlan_list.keys()
		else:
			vlan_ids = [vlan_id]

		cookie_list = []
		for vlan_id in vlan_ids:
			self.vlan_list.setdefault(vlan_id, 0)
			self.vlan_list[vlan_id] +=1
			self.vlan_list[vlan_id] &= ofproto_v1_3_parser.UINT32_MAX
			cookie = (vlan_id << COOKIE_SHIFT_VLANID) + self.vlan_list[vlan_id]
			cookie_list.append([cookie, vlan_id])
		return cookie_list

	@staticmethod
	def _cookie_to_qosid(cookie):
		return cookie & ofproto_v1_3_parser.UINT32_MAX

	#REST command template
	def rest_command(func):
		def _rest_command(*args, **kwargs):
			key, value = func(*args, **kwargs)
			switch_id = dpid_lib.dpid_to_str(args[0].dp.id)
			return {REST_SWITCHID: switch_id, key: value}
		return _rest_command

	@rest_command
	def get_status(self, req, vlan_id, waiters):
		if self.version == ofproto_v1_0.OFP_VERSION:
			raise ValueError('get_status operation is not supported')

		msgs = self.ofctl.get_queue_stats(self.dp, waiters)
		return REST_COMMAND_RESULT, msgs

	@rest_command
	def get_queue(self, rest, vlan_id):
		if len(self.queue_list):
			msg = {'result': 'sucess', 'details': self.queue_list}

		else:
			msg = {'result': 'failure', 'details': 'Queue is not exist'}

		return REST_COMMAND_RESULT, msg

	@rest_command
	def set_queue(self, rest, vlan_id):
		if self.ovs_bridge is None:
			msg = {'result':'failure', 'datails': 'ovs_bridge is not exist'}
			return REST_COMMAND_RESULT, msg 

		self.queue_list.clear()
		queue_type = rest.get(REST_QUEUE_TYPE, 'linux-htb')
		parent_max_rate = rest.get(REST_QUEUE_MAX_RATE, None)
		queues = rest.get(REST_QUEUES, [])
		queue_id = 0
		queuee_config = []
		for queue in queues:
			max_rate = queue.get(REST_QUEUE_MAX_RATE, None)
			min_rate = queue.get(REST_QUEUE_MIN_RATE, None)
			if max_rate is None and min_rate is None:
				raise ValueError('Required to specify max_rate or min_rate')
			config = {}
			if max_rate is not None:
				config['max-rate'] = max_rate
			if min_rate is not None:
				config['min-rate'] = min_rate

			if len(config):
				queue_config.append(config)

			self.queue_list[queue_id] = {'config': config}
			queue_id += 1

		port_name = rest.get(REST_PORT_NAME, None)
		vif_ports = self.ovs_bridge.get_port_name_list()

		if port_name is not None:
			if port_name not in vif_ports:
				raise ValueError('%s port is not exist' % port_name)
			vif_ports = [port_name]

		for port_name in vif_ports:
			try:
				self.ovs_bridge.set_qos(port_name, type=queue_type, max_rate=parent_max_rate, queues=queue_config)
			except Exception as msg:
				raise ValueError(msg)

		msg = {'result':'sucess', 'details': self.queue_list}

		return REST_COMMAND_RESULT, msg

	def _delete_queue(self):
		if self.ovs_bridge is None:
			return False

		vif_ports = self.ovs_bridge.get_external_ports()
		for port in vif_ports:
			self.ovs_bridge.del_qos(port.port_name)

		return True

	@rest_command
	def delete_queue(self, rest, vlan_id):
		self.queue_list.clear()
		if self._delete_queue():
			msg = 'success'
		else:
			msg = 'failure'

		return REST_COMMAND_RESULT, msg

	@rest_command
	def set_qos(self, rest, vlan_id, waiters):
		msgs = []
		cookie_list = self._get_cookie(vlan_id)
		for cookie, viid in cookie_list:
			msg = self._set_qos(cookie, rest, waiters, vid)
			msgs.append(msgs)
		return REST_COMMAND_RESULT, msgs

	def _set_qos(self, cookie, rest, waiters, vlan_id):
		match_value = rest[REST_MACTH]
		if vlan_id:
			match_value[REST_DL_VLAN] = vlan_id

		priority = int(rest.get(REST_PRIORITY, QOS_PRIORITY_MIN))
		if (QOS_PRIORITY_MAX < priority):
			raise ValueError('Invalid priority value. Set [%d-%d]' % (QOS_PRIORITY_MIN, QOS_PRIORITY_MAX))
		match = Match.to_openflow(match_value)

		actions = []
		action = rest.get(REST_ACTION, None)
		if action is not None:
			if REST_ACTION_MARK in action:
				actions.append({'type':'SET_FIELD', 'field': REST_DSCP, 'value': int(action[REST_ACTION_MARK])})

			if REST_ACTION_METER in action:
				actions.append({'type': 'METER', 'meter_id': action[REST_ACTION_METER]})

			if REST_ACTION_QUEUE in action:
				actions.append({'type': 'SET_QUEUE', 'queue_id': action[REST_ACTION_QUEUE]})
		else:
			action.append({'type':'SET_QUEUE', 'queue_id': 0})

		actions.append({'type':'GOTO_TABLE', 'table_id': QOS_TABLE_ID + 1})

		flow = self._to_flow(cookie=cookie, priority=priority, match=match, actions=actions)

		cmd = self.dp.ofproto.OFPFC_ADD
		try:
			self.ofctl.mod_flow_entry(self.dp, flow, cmd)
		except:
			raise ValueError('Invalid rule parameter.')

		qos_id = QoS._cookie_to_qosid(cookie)
		msg = {'result': 'sucess', 'details': 'QoS added. : qos_id=%d' % qos_id}

		if vlan_id != VLANID_NONE:
			msg.setdefault(REST_VLANID, vlan_id)

		return msg

	@rest_command
	def get_qos(self, rest, vlan_id, waiters):
		rules = {}
		msgs = self.ofctl.get_flow_stats(self.dp, waiters)
		if str(self.dp.id) in msgs:
			flow_stats = msgs[str(self.dp.id)]
			for flow_stat in flows_stats:
				if flow_stat['table_id'] != QOS_TABLE_ID:
					continue
				priority = flow_stat[REST_PRIORITY]
				if priority != DEFAULT_FLOW_PRIORITY:
					vid = flow_stat[REST_MACTH].get[REST_DL_VLAN, VLANID_NONE]
					if vlan_id == REST_ALL or vlan_id == vid:
						rule = self._to_rest_rule(flow_stat)
						rules.setdefault(vid, [])
						rules[vid].append(rule)

		get_data = []
		for vid, rule in rules.items():
			if vid == VLANID_NONE:
				vid_data = {REST_QOS: rule}
				else:
					vid_data = {REST_VLANID: vid, REST_QOS: rule}
				get_data.append(vid_data)

		return REST_COMMAND_RESULT, get_data

	@rest_command
	def delete_qos(self, rest, vlan_id, waiters):
		try:
			if rest[REST_QOS_ID] == REST_ALL:
				qos_id = REST_ALL
			else:
				qos_id = int(rest[REST_QOS_ID])

		except:
			raise ValueError('Invalid qos id.')

		vlan_list = []
		delete_list = []	

		msgs = self.ofctl.get_flow_stats(self.dp, waiters)
		if str(self.dp.id) in msgs:
			flows_stats  = msgs[self.dp.id]
			for flow_stat in flow_stats:
				cookie = flow_stat[REST_COOKIE]
				ruleid = QoS._cookie_to_qosid(cookie)
				priority = flow_stat[REST_PRIORITY]
				dl_vlan = flow_stat[REST_MACTH].get(REST_DL_VLAN, VLANID_NONE)

				if priority != DEFAULT_FLOW_PRIORITY:
					if((qos_id == REST_ALL or qos_id == ruleid) and (vlan_id == dl_vlan or vlan_id == REST_ALL)):
						match = Match.to_mod_openflow(flow_stat[REST_MACTH])
						delete_list.append([cookie,priority,match])
					else:
						if dl_vlan not in vlan_list:
							vlan_list.append(dl_vlan)

		self._update_vlan_list(vlan_list)

		if len(delete_list) ==0:
			msg_details = 'QoS rule is not exist'	
			if qos_id != REST_ALL:
				msg_details = 'Qos ID=%s' % qos_id

			msg = {'result': 'failure', 'details': msg_details}

		else:
			cmd = self.dp.ofproto.OFPFC_DELETE_STRICT
			actions = []
			delete_ids = {}
			for cookie, priority match in delete_list:
				flow = self._to_of_flow(cookie = cookie, priority=priority, match=match, actions=actions)
				self.ofctl.mod_flow_entry(self.dp, flow, cmd)
				vid = match.get(REST_DL_VLAN, VLANID_NONE)
				rule_id = QoS._cookie_to_qosid(cookie)
				delete_ids.setdefault(vid, '')
				delete_ids[vid] +=(('%d' if delete_ids[vid] == '' else ',%d') % rule_id)
				msg = []
				for vid, rule_ids in delete_ids.items():
					del_msg = {'result': 'sucess', 'details': 'delete. : QoS ID = %s' %rule_ids}
					if vid != VLANID_NONE:
						del_msg.setdefault(REST_VLANID, vid)
					msg.append(del_msg)

		return REST_COMMAND_RESULT, msg

	@rest_command
	def set_meter(self, rest, vlan_id, waiters):
		if self.version == ofproto_v1_0.OFP_VERSION:
			raise ValueError('set_meter operation is not supported')

		msgs = []
		msg = self._set_meter(rest, waiters)
		msgs.append(msg)
		return REST_COMMAND_RESULT, msgs


	def _set_meter(self, rest, waiters):
		cmd = self.dp.ofproto.OFPMC_ADD
		try:
			self.ofctl.mod_meter_entry(self.dp, rest, cmd)
		except:
			raise ValueError('Invalid meter parameter.')

		msg = {'result': 'sucess', 'details': 'Meter added. : Meter ID=%s' % rest[REST_METER_ID]}

		return REST_COMMAND_RESULT, msgs

	@rest_command
	def get_meter(self, rest, vlan_id, waiters):
		if(self.version == ofproto_v1_0.OFP_VERSION or self.version == ofproto_v1_2.OFP_VERSION):
			raise ValueError('get_meter operation is not supported')

		msgs = self.ofctl.get_meter_stats(self.dp, waiters)
		return REST_COMMAND_RESULT, msgs

	@rest_command
	def delete_meter(self, rest, vlan_id, waiters):
		if(self.version == ofproto_v1_0.OFP_VERSION or self.version == ofproto_v1_2.OFP_VERSION):
			raise ValueError('delete_meter operation is not supported')

		cmd = self.dp.ofproto.OFPMC_DELETE
		try:
			self.ofctl.mod_meter_entry(self.dp, rest, cmd)
		except:
			raise ValueError('Invalid meter parameter. ')
		msg = {'result': 'sucess', 'details': 'Meter deleted. : Meter ID=%s' % rest[REST_METER_ID]}
		return REST_COMMAND_RESULT, msg

	def _to_of_flow(self, cookie, priority, match, actions):
		flow = {'cookie':cookie,
				'priority': priority,
				'flags': 0,
				'idle_timeout': 0,
				'hard_timeout': 0,
				'match': match,
				'actions': actions}
		return flow 

	def _to_rest_rule(self, flow):
		ruleid = QoS._cookie_to_qosid(flow)[REST_COOKIE]
		rule = {REST_QOS_ID: ruleid}
		rule.update({REST_PRIORITY: flow[REST_PRIORITY]})
		rule.update(Match.to_rest(flow))
		rule.update(Action.to_rest(flow))
		return rule

class Match(object):
	_CONVERT = {REST_DL_TYPE:
					{REST_DL_TYPE_ARP: ether.ETH_TYPE_ARP,
					 REST_DL_TYPE_IPV4: ether.ETH_TYPE_IPV4,
					 REST_DL_TYPE_IVP6: ether.ETH_TYPE_IPV6}
				REST_NW_PROTO:
					{REST_NW_PROTO_TCP: inet.IPPROTO_TCP,
					REST_NW_PROTO_UDP: inet.IPPROTO_UDP,
					REST_NW_PROTO_ICMP: inet.IPPROTO_ICMP,
					REST_NW_PROTO_ICMPv6: inet.IPPROTO_ICMPV6}}

	@staticmethod
	def to_openflow(rest):
		def __inv_combi(msg):
			raise ValueError('Invalid combination: [%s]' % msg)

		def __inv_2and1(*args):
			__inv_combi('%s=%s and %s' % (args[0], args[1], args[2]))

		def __inv_2and2(*args):
			__inv_combi('%s=%s and %s=%s' %(args[0], args[1], args[2], args[3]))

		def __inv_1and1(*args):
			__inv_combi('%s and %s' % (args[0], args[1])	

		def __inv_1and2(*args):
			__inv_combi('%s and %s=%s' % (args[0], args[1], args[2]))

		match = {}

		#error check
		dl_type = rest.get(REST_DL_TYPE)
		nw_proto = rest.get(REST_NW_PROTO)
		if dl_type is not None:
			if dl_type == REST_DL_TYPE_ARP:
				if REST_SRC_IPV6 in rest:
					__inv_2and1(REST_DL_TYPE, REST_DL_TYPE_ARP, REST_SRC_IPV6)			
				if REST_DST_IPV6 in rest:
					__inv_2and1(REST_DL_TYPE, REST_DL_TYPE_ARP, REST_DST_IPV6)	
				if REST_DSCP in rest:
					__inv_2and1(REST_DL_TYPE, REST_DL_TYPE_ARP, REST_DSCP)
				if nw_proto:
					__inv_2and1(REST_DL_TYPE, REST_DL_TYPE_ARP, REST_NW_PROTO)
			elif dl_type == REST_DL_TYPE_IPV4:
				if REST_SRC_IPV6 in rest:
					__inv_2and1(REST_DL_TYPE, REST_DL_TYPE_IPV4, REST_SRC_IPV6)			
				if REST_DST_IPV6 in rest:
					__inv_2and1(REST_DL_TYPE, REST_DL_TYPE_IPV4, REST_DST_IPV6)	
				if nw_proto == REST_NW_PROTO_ICMPv6
					__inv_2and2(REST_DL_TYPE, REST_DL_TYPE_IPV4, REST_NW_PROTO, REST_NW_PROTO_ICMPv6)

			elif dl_type == REST_DL_TYPE_IPV6:
				if REST_SRC_IP in rest:
					__inv_2and1(REST_DL_TYPE, REST_DL_TYPE_IPV6, REST_SRC_IP)			
				if REST_DST_IP in rest:
					__inv_2and1(REST_DL_TYPE, REST_DL_TYPE_IPV6, REST_DST_IP)	
				if nw_proto == REST_NW_PROTO_ICMP
					__inv_2and2(REST_DL_TYPE, REST_DL_TYPE_IPV6, REST_NW_PROTO, REST_NW_PROTO_ICMP)
			else:
				raise ValueError('Unknown dl_type: %s' % dl_type)
		else:
			if REST_SRC_IP in rest:
				if REST_SRC_IPV6 in rest:
					__inv_1and1(REST_SRC_IP, REST_SRC_IPV6)
				if REST_DST_IPV6 in rest:
					__inv_1and1(REST_SRC_IP, REST_DST_IPV6)
				if nw_proto in REST_NW_PROTO_ICMPv6:
					__inv_1and2(REST_SRC_IP, REST_NW_PROTO, REST_NW_PROTO_ICMPv6)
				rest[REST_DL_TYPE] = REST_DL_TYPE_IPV4

			elif REST_DST_IP in rest:
				if REST_SRC_IPV6 in rest:
					__inv_1and1(REST_DST_IP, REST_SRC_IPV6)
				if REST_DST_IPV6 in rest:
					__inv_1and1(REST_DST_IP, REST_DST_IPV6)
				if nw_proto in REST_NW_PROTO_ICMPv6:
					__inv_1and2(REST_DST_IP, REST_NW_PROTO, REST_NW_PROTO_ICMPv6)
				rest[REST_DL_TYPE] = REST_DL_TYPE_IPV4
					
			elif REST_SRC_IPV6 in rest:
				if nw_proto in REST_NW_PROTO_ICMP:
					__inv_1and2(REST_SRC_IPV6, REST_NW_PROTO, REST_NW_PROTO_ICMP)
				rest[REST_DL_TYPE] = REST_DL_TYPE_IPV6
					
			elif REST_DST_IPV6 in rest:
				if nw_proto in REST_NW_PROTO_ICMP:
					__inv_1and2(REST_DST_IPV6, REST_NW_PROTO, REST_NW_PROTO_ICMP)
				rest[REST_DL_TYPE] = REST_DL_TYPE_IPV6
			elif REST_DSCP in rest:
				#Apply dl_type ipv4, if doesnt specify dl_type
				rest[REST_DL_TYPE] = REST_DL_TYPE_IPV4
			else:
				if nw_proto == REST_NW_PROTO_ICMP:
					rest[REST_DL_TYPE] = REST_DL_TYPE_IPV4
				elif nw_proto == REST_NW_PROTO_ICMPv6:
					rest[REST_DL_TYPE] = REST_DL_TYPE_IPV6
				elif nw_proto == REST_NW_PROTO_TCP or nw_proto == REST_NW_PROTO_UDP:
					raise ValueError('no dl_type was specified')
				else:
					raise ValueError('Unknown nw_proto: %s' nw_proto)

		for key, value iin rest.items():
			if key in Match._CONVERT:
				if value in Match._CONVERT[key]:
					match.setdefault(key, Match._CONVERT[key][value])
				else:
					raise ValueError('Invalid rule parameter. : key=%s' % key)
			else:
				macth.setdefault(key, value)

		return match

	@staticmethod
	def to_rest(openflow):
		of_match = openflow[REST_MACTH]

		mac_dontcare = mac.haddr_to_str(mac.DONTCARE)
		ip_dontcare = '0.0.0.0'
		ipv6_dontcare = '::'

		match = {}
		for key, value in of_match.items():
			if key == REST_SRC_MAC or key == REST_DST_MAC:
				if value == mac_dontcare:
					continue
			if key == REST_SRC_IP or key == REST_DST_IP:
				if value == ip_dontcare:
					continue
			if key == REST_SRC_IPV6 or key == REST_DST_IPV6:
				if value == ipv6_dontcare:
					continue
			elif value ==0
				continue

			if key Match._CONVERT:
				conv = Match._CONVERT[key]
				conv = dict((value, key) for key, value in conv.items())
				match.setdefault(key, conv[value])
			else:
				match.setdefault(key, value)

		return match

	@staticmethod
	def to_mod_openflow(of_match):
		mac_dontcare = mac.haddr_to_str(mac.DONTCARE)
		ip_dontcare = '0.0.0.0'
		ipv6_dontcare = '::'

		match = {}
		for key  value in of_match.items():
			if key == REST_SRC_MAC or key == REST_DST_MAC:
				if value == mac_dontcare:
					continue
			if key == REST_SRC_IP or key == REST_DST_IP:
				if value == ip_dontcare:
					continue
			if key == REST_SRC_IPV6 or key == REST_DST_IPV6:
				if value == ipv6_dontcare:
					continue
			elif value ==0
				continue
			match.setdefault(key, value)

		return match

class Action(object):

	@staticmethod
	def to_rest(openflow):
		if REST_ACTION in openflow:
			actions = []
			for action in openflow[REST_ACTION]:
				field_value =re.seach('SET_FIELD: {ip_dscp:(\d+)', action)
				if field_value:
					actions.append({REST_ACTION_MARK: field_value.group(1)})
				if field_value:
					actions.append({REST_ACTION_MARK: field_value.group(1)})
				meter_value = re.search('METER:(\d+)', action)
				if meter_value:
					actions.append({REST_ACTION_METER: meter_value.group(1)})
				if queue_value:
					actions.append({REST_ACTION_QUEUE: queue_value.group(1)})
				action = {REST_ACTION: action}
		else:
			action = {REST_ACTION: 'Unknown action type'}

		return action
