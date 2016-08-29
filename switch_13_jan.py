# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import igmp
from ryu.ofproto import inet
#from ryu.lib import igmplib
import igmplib_jan
from ryu.lib.dpid import str_to_dpid



class Switch_13_jan(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'igmplib_jan': igmplib_jan.IgmpLib}

    def __init__(self, *args, **kwargs):
        super(Switch_13_jan, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.fonte_multicast = {}
        self.prefix_multicast  = range(224,240)
        self.mcast_to_port = {}
        self.report_mcast = {}
        self.src_multicast = {}
        self.membro_grupo = dict()

        #inicializando a funcao igmp
        self._snoop = kwargs['igmplib_jan']
        self._snoop.set_querier_mode(dpid=str_to_dpid('0000000000000001'),server_port=1)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    #def query_gerada_router(self, ev):


    #@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    @set_ev_cls(igmplib_jan.EventPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        #-----
        tp = eth.ethertype
        proto = {'0x800':'IPV4', '0x806':'ARP','0x8100':'VLAN','0x86dd':'IPV6'}


        dpid = datapath.id
       



        self.report_mcast.setdefault(dpid, {})
        self.src_multicast.setdefault(dpid, {})

        req_ip = pkt.get_protocol(ipv4.ipv4)
        req_igmp = pkt.get_protocol(igmp.igmp)

        if req_ip:
            if int(req_ip.dst.split('.')[0]) in range(224,240) and req_ip.dst not in self.fonte_multicast:
                self.fonte_multicast[req_ip.dst] = req_ip.src
                self.logger.info("Pacote de dentro IP %s", self.fonte_multicast)
      #          if self.fonte_multicast[req_ip.dst] == "0.0.0.0":
      #              out_port = ofproto.OFPP_NORMAL
      #              actions = [parser.OFPActionOutput(out_port)]
      #              match = parser.OFPMatch(in_port=in_port, eth_type=2048, ipv4_dst=req_ip.dst)
      #              self.add_flow(datapath, 1, match, actions, msg.buffer_id)
      #              return

      #     if req_igmp:
      #          self.logger.info("Pacote IGMP %s", req_igmp)
      #          if req_igmp.msgtype == igmp.IGMP_TYPE_REPORT_V2 or req_igmp.msgtype == igmp.IGMP_TYPE_REPORT_V3:
      #              self.membro_grupo[req_ip.dst].append()
      #              self.report_mcast[dpid][req_ip.dst] = in_port
      #              if req.ip.dst in self.src_multicast[dpid]
      #                  match = parser.OFPMatch(in_port= elf.src_multicast[dpid][req_ip.dst], eth_type=0x800, ipv4_dst=req_ip.dst)
      #                  actions = [ofproto.OFPActionOutput(in_port)]
      #                  self.add_flow(datapath,1, match, actions)
      #              else:
      #                  self.logger.info("Pacote destinado ao Querier")
      #
      #           else:
      #              self.src_multicast[dpid][req_ip.dst] = in_port
      #              match = parser.OFPMatch(in_port=in_port, eth_type=0x800,ipv4_dst=req_ip.dst)
      #              actions = [ofproto.OFPActionOutput(ALL)]
      #              self.logger.info("Paconte IP")
      #              self.add_flow(datapath,1, match, actions)

        self.mac_to_port.setdefault(dpid, {})

        self.logger.info('Packet [%s] in [%s] %s %s %s ', proto[hex(tp)],dpid, src, dst, in_port )
        
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(igmplib_jan.EventMulticastGroupStateChanged, MAIN_DISPATCHER)
    def _status_changed(self, ev):
        msg = {
            igmplib_jan.MG_GROUP_ADDED: 'GRUPO Multicast Adicionado',
            igmplib_jan.MG_MEMBER_CHANGED: 'GRUPO Multicast Alterado',
            igmplib_jan.MG_GROUP_REMOVED: 'GRUPO Multicast Removido'
        }
        self.logger.info("%s: [%s] querier: [%s] host: %s ", msg.get(ev.reason), ev.address, ev.src, ev.dsts)
