from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import dpid as dpid_lib
from ryu.lib import stplib
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

class SimpleSwitch13(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
	_CONTEXTS = {'stplib': stplib.Stp}

	def __init__(self, *args, **kwargs):
		super(SimpleSwitch13, self).__init__(*args, **kwargs)
		self.mac_to_port = {}
		self.stp = kwargs['stplib']

		config = {dpid_lib.str_to_dpid('0000000000000001'): {'bridge': {'priority':0x8000}},
				  dpid_lib.str_to_dpid('0000000000000002'): {'bridge': {'priority':0x9000}},
				  dpid_lib.str_to_dpid('0000000000000003'): {'bridge': {'priority':0xa000}}}

		self.stp.set_config(config)

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
										   ofproto.OFPCML_NO_BUFFER)]

		self.add_flow(datapath, 0, match, actions)

	def add_flow(self, datapath, priority, match, actions):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

		mod = parser.OFPFlowMod(datapath = datapath, priority= priority, match = match, instructions = inst)
		datapath.send_msg(mod)

	def delete_flow(self, datapath):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		for dst in self.mac_to_port[datapath.id].keys():
			match = parser.OFPMatch(eth_dst=dst)
			mod = parser.OFPFlowMod(
					datapath, 
					command=ofproto.OFPFC_DELETE,
					out_port=ofproto.OFPP_ANY,
					out_group=ofproto.OFPG_ANY,
					priority=1,
					match=match )
			datapath.send_msg(mod)
	@set_ev_cls(stplib.EventPacketIn, MAIN_DISPATCHER)		
	def _packet_in_handler(self, ev):
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		in_port = msg.match['in_port']

		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocols(ethernet.ethernet)[0]

		dst = eth.dst
		src = eth.src

		dpid = datapath.id
		self.mac_to_port.setdefault(dpid, {})

		self.logger.info("PACOTE ENTRANTE:  %s %s %s %s", dpid, src, dst, in_port)

		self.mac_to_port[dpid][src] = in_port

		if dst in self.mac_to_port[dpid]:
			out_port = self.mac_to_port[dpid][dst]

		else:
			out_port = ofproto.OFPP_FLOOD

		actions = [parser.OFPActionOutput(out_port)]

		if out_port != ofproto.OFPP_FLOOD:
			match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
			self.add_flow(datapath, 1, match, actions)

		data = None
		if msg.buffer_id == ofproto.OFP_NO_BUFFER:
			data = msg.data

		out = parser.OFPPacketOut(datapath=datapath,
								  buffer_id = msg.buffer_id,
								  in_port = in_port,
								  actions = actions,
								  data = data)
		datapath.send_msg(out)

	@set_ev_cls(stplib.EventTopologyChange, MAIN_DISPATCHER)
	def _topology_change_handler(self, ev):
		dp = ev.dp
		dpid_str = dpid_lib.dpid_to_str(dp.id)
		msg = 'Receive topology change event. Flush MAC table.'
		self.logger.debug("[SWITCH - dpid=%s] %s", dpid_str, msg)

		if dp.id in self.mac_to_port:
			self.delete_flow(dp)
			del self.mac_to_port[dp.id]

	@set_ev_cls(stplib.EventPortStateChange, MAIN_DISPATCHER)
	def _port_state_change_handler(self, ev):
		dpid_str = dpid_lib.dpid_to_str(ev.dp.id)
		of_state = {stplib.PORT_STATE_DISABLE: 'DISABLE',
					stplib.PORT_STATE_BLOCK: 'BLOCK',
					stplib.PORT_STATE_LISTEN: 'LISTEN',
					stplib.PORT_STATE_LEARN: 'LEARN',
					stplib.PORT_STATE_FORWARD: 'FORWARD'}
		self.logger.debug("MUDANCA NAS PORTAS: [dpid=%s] [port=%d] state=%s",
							dpid_str, ev.port_no, of_state[ev.port_state])

