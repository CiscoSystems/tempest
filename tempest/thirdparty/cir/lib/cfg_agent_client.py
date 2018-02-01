import json
from oslo_log import log as logging
from tempest import config
#from tempest.services.network.json import base
from tempest.lib.services.network import base 
from networking_cisco._i18n import _

from neutronclient.common import extension
from neutronclient.neutron import v2_0 as neutronV20


HOSTING_DEVICE = 'hosting_device'

CONF = config.CONF
LOG = logging.getLogger(__name__)

# API calls taken from python-neutronclient and wedged into a tempest client

AGENT = 'agent'
HOSTING_DEVICE_CFG_AGENTS = '/hosting-device-cfg-agents'


class ConfigAgentHandlingHostingDevice(extension.NeutronClientExtension):
    resource = AGENT
    resource_plural = '/v2.0/%ss' % resource
    object_path = '/%s' % resource_plural
    resource_path = '/%s/%%s' % resource_plural
    versions = ['2.0']
    allow_names = True


class CfgAgentClient(base.BaseNetworkClient):

    routers_path = "/routers"
    router_path = "/routers/%s"
    agents_path = "/agents"
    agent_path = "/agents/%s"
    L3_ROUTER_DEVICES = '/l3-router-hosting-devices'
    DEVICE_L3_ROUTERS = '/hosting-device-l3-routers'
    HOSTING_DEVICE_CFG_AGENTS = '/hosting-device-cfg-agents'
    CFG_AGENT_HOSTING_DEVICES = '/cfg-agent-hosting-devices'
    hosting_devices_path = "/dev_mgr/hosting_devices"
    hosting_device_path = "/dev_mgr/hosting_devices/%s"
    hosting_device_templates_path = "/dev_mgr/hosting_device_templates"
    hosting_device_template_path = "/dev_mgr/hosting_device_templates/%s"
    routertypes_path = "/routertypes"
    routertype_path = "/routertypes/%s"

    def config_agent_associate_hosting_device(self,
                                              config_agent_id,
                                              hosting_device_id):
        hdi_dict = {'hosting_device_id': hosting_device_id}
        #return self.post((ConfigAgentHandlingHostingDevice.resource_path +
        #                  self.CFG_AGENT_HOSTING_DEVICES) % config_agent_id,
        #                 body=body)
        return self.post((ConfigAgentHandlingHostingDevice.resource_path +
                          self.CFG_AGENT_HOSTING_DEVICES) % config_agent_id,
                         body=json.dumps(hdi_dict))


    def config_agent_disassociate_hosting_device(self,
                                                 config_agent_id,
                                                 hosting_device_id):
        return self.delete((ConfigAgentHandlingHostingDevice.resource_path +
                            self.CFG_AGENT_HOSTING_DEVICES + "/%s") %
                           (config_agent_id, hosting_device_id))

    def list_hosting_devices(self, **filters):
        return self.list_resources(self.hosting_devices_path, **filters)

    def update_hosting_device(self, hosting_device_id, body=None):
        return self.put(self.hosting_device_path % hosting_device_id,
                        body=body)

    def show_hosting_device(self, hosting_device_id, **_params):
        return self.show_resource(self.hosting_device_path % hosting_device_id)

    def list_hosting_devices_hosting_routers(self, router_id, **filters):
        return self.list_resources((self.router_path + self.L3_ROUTER_DEVICES)
                                   % router_id, **filters)

    def list_routers_on_hosting_device(self, hosting_device_id, **filters):
        return self.list_resources((self.hosting_device_path +
                                    self.DEVICE_L3_ROUTERS) %
                                   hosting_device_id, **filters)

    def list_config_agents_handling_hosting_device(self, hosting_device_id,
                                                   **filters):
        return self.list_resources((self.hosting_device_path +
                                    self.HOSTING_DEVICE_CFG_AGENTS) %
                                   hosting_device_id,
                                   **filters)

    def list_hosting_device_handled_by_config_agent(self, cfg_agent_id,
                                                    **filters):
        return self.list_resources((self.agent_path +
                                    self.CFG_AGENT_HOSTING_DEVICES) %
                                   cfg_agent_id, **filters)
