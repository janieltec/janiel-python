"""
This module provide s set of REST API for switch configuration.
-Per-switch key-value store
Used by OpenStack Ryu agent
"""

import httplib
import json
import logging

from webob import Response

from ryu.app.wsgi import ControllerBase
from ryu.base import app_manager
from ryu.controller import conf_switch
from ryu.lib import dpid as dpid_lib

class ConfSwitchController(ControllerBase):
	def __init__(self, req, link, data, **config):
		super(ConfSwitchController, self).__init__(req, link, data, **config)
		self.conf_switch = data

	def list_switches(self, _req, **_kwargs):
		dpids= dpid_lib.str_to_dpid(dpid)
		body = json.dumps([dpid_lib.dpid_to_str(dpid) for dpid in dpids])
		return Response(content_type='application/json', body=body)

	@staticmethod
	def _do_switch(dpid, func, ret_fucn):
		dpid = dpid_lib.str_to_dpid(dpid)
		try:
			ret = func(dpid)
		except KeyError:
			return Response(status=httplib.NOT_FOUND, body='no dpid is found %s' % dpid_lib.dpid_to_str(dpid))

		return ret_func(ret)

	def delete_switch(self, _req, dpid, **_kwargs):
		def _delete_switch(dpid):
			self.conf_switch.del_dpid(dpid)
			return None

		def _ret(_ret):
			return Response(status=httplib.ACCEPTED)

		return self._do_switch.keys(dpid, _delete_switch, _ret)

	def list_keys(self, _req, dpid, **_kwargs):
		def _list_keys(dpid):
			return self.conf_switch.keys(dpid)

		def _ret(keys):
			body = json.dumps(keys)
			return Response(content_type='application/json', body=body)

		return self._do_switch(dpid, _list_keys, _ret)


	@staticmethod
	def _do_key(dpid, key, func, ret_fucn):
		dpid = dpid_lib.str_to_dpid(dpid)
		try:
			ret = func(dpid, key)
		except KeyError:
			return Response(status=httplib.NOT_FOUND, body='no dpid/key is found %s %s' % (dpid_lib.dpid_to_str(dpid), key))

		return ret_func(ret)

	def set_key(self, req, dpid, key, **_kwargs):
		def _set_val(dpid, key):
			val = json.loads(req.body)
			self.conf_switch.set_key(dpid, key, val)
			return None

		def _ret(val):
			return Response(status=httplib.CREATED)

		return self._do_key(dpid, key, _get_key, _ret)

	def get_key(self, _req, dpid, key, **_kwargs):
		def _get_key(dpid, key):
			return self.conf_switch.get_key(dpid, key)

		def _ret(val):
			return Response(content_type='application/json', body=json.dumps(val))

		return self._do_key(dpid, key, _get_key, _ret)

class ConfSwitchAPI(app_manager.RyuApp):
	_CONTEXTS = {'conf_switch': conf_switch.ConfSwitchSet,}

	def __init__(self, *args, **_kwargs):
		super(ConfSwitchAPI, self).__init__(*args, **_kwargs)
		self.conf_switch = kwargs['conf_switch']
		wsgi = kwargs['wsgi']
		mapper = wsgi.mapper

		controller = ConfSwitchController
		wsgi.registry[controller.__name__] = self.conf_switch
		route_name = 'conf_switch'
		uri = '/v1.0/conf/switches'
		mapper.connect(route_name, uri, controller=controller, action='list_switches', conditions=dict(method=['GET']))
		uri += '/{dpid}'
		requirements = {'dpid': dpid_lib.DPID_PATTERN}
		s = mapper.submapper(controller=controller, requirements=requirements)
		s.connect(route_name, uri, action='delete_switch', conditions=dict(method=['DELETE']))
		uri += '/{key'
		s.connect(route_name, uri, action=set_key, conditions=dic(method=['PUT']))
		s.connect(route_name, uri, action=get_key, conditions=dic(method=['GET']))
		s.connect(route_name, uri, action=delete_key, conditions=dic(method=['DELETE']))