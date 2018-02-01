# Copyright 2015 Cisco Systems
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import re
import time
import tempest.thirdparty.cir.lib.asr_exceptions as asr_exceptions
import tempest.thirdparty.cir.lib.asr as asr
import testtools

from tempest.thirdparty.cir.lib.device.LogInspector import LogInspector
from tempest.thirdparty.cir.lib.director_client import DirectorClient
from oslo_log import log as logging
from tempest.lib import decorators
from tempest.lib import exceptions
from tempest import config as tempest_conf
from tempest.scenario import test_network_multi_node
from tempest import test as test
from tempest.thirdparty.cir.lib.cfg_agent_client import CfgAgentClient

CONF = tempest_conf.CONF

LOG = logging.getLogger(__name__)
LOG.debug("TestASRStandBy")


class TestASRCfgAgentHA(test_network_multi_node.TestNetworkMultiNode):

    # For setting up cfg agent client
    default_params = {
        'disable_ssl_certificate_validation':
            CONF.identity.disable_ssl_certificate_validation,
        'ca_certs': CONF.identity.ca_certificates_file,
        'trace_requests': CONF.debug.trace_requests
    }

    def setUp(self):

        # Make sure there are at least 2 cfg-agents
        l3_agents = self.network_client.list_agents()['agents']
        agent_topics = [cfg_agent['topic'] for cfg_agent in l3_agents]
        msg = "No Cisco-cfg-agents found on this stack"
        self.assertIn('cisco_cfg_agent', agent_topics, msg)
        topics_count = {i: agent_topics.count(i) for i in agent_topics}
        msg = "Not enough Cisco-cfg-agents running on this stack"
        self.assertGreater(topics_count['cisco_cfg_agent'], 1, msg)
        self.cisco_cfg_agents = [cfg_agent for cfg_agent in l3_agents
                                 if cfg_agent['topic'] == 'cisco_cfg_agent']

        self.addCleanup(self.setup_cfg_agent_ha)
        self.addCleanup(self.close_logs)

        self.cfg_agent_host_names = [host_name['host'] for host_name in
                                     self.cisco_cfg_agents]

        self.director_log = open('/tmp/director_console.log', 'w')

        self.director_client = DirectorClient('rh-director',
                                              logfile=self.director_log)

        self.controller_dns = {}
        for host_name in self.cfg_agent_host_names:
            self.controller_dns[host_name] = \
                {'ip': self.director_client.get_ip(host_name), }
            # Delay for bug
            time.sleep(5)

        for cfg_agent_controller in self.controller_dns:
            ip = self.controller_dns[cfg_agent_controller]['ip']
            cmd = 'systemctl status neutron-cisco-cfg-agent.service | cat'
            status = self.director_client.run_cmd_on(ip, cmd)
            msg = "Cisco cfg agent is not running on {0}".format(ip)
            self.assertRegexpMatches(status,
                                     '.+Active: .*active .running.+',
                                     msg)

        self.cfg_agent_client = CfgAgentClient(
            self.manager.auth_provider,
            CONF.network.catalog_type,
            CONF.network.region or CONF.identity.region,
            endpoint_type=CONF.network.endpoint_type,
            build_interval=CONF.network.build_interval,
            build_timeout=CONF.network.build_timeout,
            **self.default_params)

        self.asr1 = asr.ASR(name=CONF.cisco.asr1,
                            ip=CONF.cisco.asr1_ip,
                            user=CONF.cisco.user_name,
                            pw=CONF.cisco.user_pw,
                            external_intf=CONF.cisco.asr1_external_intf,
                            internal_intf=CONF.cisco.asr1_internal_intf)

        self.asr2 = asr.ASR(name=CONF.cisco.asr2,
                            ip=CONF.cisco.asr2_ip,
                            user=CONF.cisco.user_name,
                            pw=CONF.cisco.user_pw,
                            external_intf=CONF.cisco.asr2_external_intf,
                            internal_intf=CONF.cisco.asr2_internal_intf)

        self.asr1.clear_netconf_counters()
        self.asr2.clear_netconf_counters()
        self.verify_asrs = asr.VerifyASRStandby(active=self.asr1,
                                                standby=self.asr2)

        super(test_network_multi_node.TestNetworkMultiNode, self).setUp()

    def setup_multinode_network(self):
        self.keypair = self.create_keypair()
        self.floating_ip_tuples = []
        self.linux_client = None
        self.private_key = None
        self.servers = {}
        self.srv_kwargs = {'key_name': self.keypair['name']}
        self.tenant_id = self.manager.identity_client.tenant_id
        self.total_expected_pkts = 0
        self.total_expected_bytes = 0
        self.segmentation_ids = []
        self.number_instances_per_compute = 1
        self.number_routers_per_tenant = 1
        self.network_vms = {}
        self.routers = []

        # Classes that inherit this class can redefine packet size/count
        # based on their own needs or accept the default in the CONF
        if not hasattr(self, 'test_packet_sizes'):
            self.test_packet_sizes = map(int, CONF.scenario.test_packet_sizes)

        if not hasattr(self, 'test_packet_count'):
            self.test_packet_count = CONF.scenario.test_packet_count

        if not hasattr(self, 'max_instances_per_tenant'):
            self.max_instances_per_tenant = (
                CONF.scenario.max_instances_per_tenant)

        # Allows the ability to place VMs on specific compute nodes
        self.setup_aggregates()

        self.num_networks = int(self.max_instances_per_tenant /
                                len(self.hypervisors))

        # If user specified max_instances_per_tenant less than
        # number of hypervisors availabe then result is zero
        # give at least one.
        if self.num_networks == 0:
            self.num_networks = 1

        LOG.debug("Max instances per tenant = {0}".
                  format(self.max_instances_per_tenant))
        LOG.debug("Number of instances per Network/compute = {0}".
                  format(self.number_instances_per_compute))
        LOG.debug("Number of Networks = {0}".format(self.num_networks))

        self.security_group = self._create_security_group(
            tenant_id=self.tenant_id)
        my_security_groups = [{'name': self.security_group['name']}]
        self.srv_kwargs['security_groups'] = my_security_groups
        try:
            self._create_loginable_secgroup_rule(secgroup=self.security_group)
        except Exception as e:
            LOG.debug("Login sec group already exists: {0}".format(e))

        self.setup_networks()
        self.setup_vms()

    def delete_multinode_network(self):
        if len(self.floating_ip_tuples) > 0:
            self.delete_floating_ips()
        self.delete_vms()
        for aggregate in self.aggregates:
            aggregate_info = \
                self.aggregates_client.show_aggregate(
                    aggregate['id'])['aggregate']
            self._remove_host(aggregate['id'],
                              aggregate_info['hosts'][0])
            self.aggregates_client.delete_aggregate(aggregate['id'])

        for router in self.routers:
            router.unset_gateway()

        for network in self.networks:
            dhcp_agents = \
                self.network_client.list_dhcp_agent_hosting_network(
                    network_id=network['id'])['agents']
            for agent in dhcp_agents:
                self.network_client.remove_network_from_dhcp_agent(
                    agent_id=agent['id'], network_id=network['id'])

            subnets = \
                self.network_client.list_subnets(
                    network_id=network['id'])['subnets']
            for subnet in subnets:
                for router in self.routers:
                    self.network_client.remove_router_interface_with_subnet_id(
                        router_id=router['id'], subnet_id=subnet['id'])
            network.delete()

        for router in self.routers:
            router.delete()

    def verify_asrs_insync(self):
        self.verify_asrs.check_active_asr(self.segmentation_ids[0])
        self.verify_asrs.netconf_counters()
        self.verify_asrs.vrfs(self.network_client.list_routers()['routers'],
                              self.tenant_id,
                              region_id=CONF.network.region1_id)

        self.verify_asrs.nat_pool(self.network_client,
                                  self.tenant_id,
                                  region_id=CONF.network.region1_id)
        self.verify_asrs.nat_translations(self.floating_ip_tuples)
        self.verify_asrs.acls(self.network_client,
                              self.networks_client,
                              self.tenant_id,
                              self.segmentation_ids,
                              region_id=CONF.network.region1_id)
        self.verify_asrs.ext_subintf(self.network_client,
                                     self.networks_client,
                                     self.routers,
                                     self.tenant_id,
                                     region_id=CONF.network.region1_id)
        self.verify_asrs.standby_state(self.segmentation_ids)

    def close_logs(self):
        if self.director_log:
            self.director_log.close()

    def setup_cfg_agent_ha(self, ha_type='MULTI_HA'):
        active_re = re.compile(r'.*Active.*active.*running.*')
        if ha_type == 'MULTI_HA':
            # Turn on all config agents
            for cfg_agent_controller in self.controller_dns:
                ip = self.controller_dns[cfg_agent_controller]['ip']
                cmd = 'systemctl status neutron-cisco-cfg-agent.service | cat'
                status = self.director_client.run_cmd_on(ip, cmd)
                active_match = active_re.search(status)
                if not active_match:
                    cmd = 'sudo systemctl start ' \
                          'neutron-cisco-cfg-agent.service | cat'
                    self.director_client.run_cmd_on(ip, cmd)

        elif ha_type == 'SINGLE_HA':
            single_cfg_agent = None
            for cfg_agent_controller in self.controller_dns:
                ip = self.controller_dns[cfg_agent_controller]['ip']
                cmd = 'systemctl status neutron-cisco-cfg-agent.service | cat'
                status = self.director_client.run_cmd_on(ip, cmd)
                active_match = active_re.search(status)
                if single_cfg_agent is None and active_match:
                    single_cfg_agent = cfg_agent_controller
                else:
                    cmd = 'sudo systemctl stop ' \
                          'neutron-cisco-cfg-agent.service | cat'
                    self.director_client.run_cmd_on(ip, cmd)

        else:
            msg = "Invalid ha_type {0} specified".format(ha_type)
            raise asr_exceptions.ASRTestException(msg)

    def get_ha_router(self, router, ha_state='ACTIVE'):
        if router['cisco_ha:details']['state'] == ha_state:
            return router
        else:
            redundancy_routers = \
                router['cisco_ha:details']['redundancy_routers']
            for redundant_router in redundancy_routers:
                if redundant_router['state'] == ha_state:
                    return redundant_router

        msg = "Could not find HA Router in state {0} for router {1}".format(
            ha_state, router['id'])
        raise asr_exceptions.NoASRHaRouterFound(msg)

    def get_cfg_agent(self, router):
        hosting_device_id = None
        hosting_devices_resp = self.cfg_agent_client.list_hosting_devices()
        hosting_devices = hosting_devices_resp['hosting_devices']
        for hosting_device in hosting_devices:
            routers_on_hd = \
                self.cfg_agent_client.list_routers_on_hosting_device(
                    hosting_device_id=hosting_device['id'])['routers']
            for hd_router in routers_on_hd:
                if router['id'] == hd_router['id']:
                    hosting_device_id = hosting_device['id']
                    break

        if hosting_device_id is None:
            msg = "Could not find hosting device for router {0}".format(
                router['id'])
            raise asr_exceptions.ASRTestException(msg)
        cfg_agents = \
            self.cfg_agent_client.list_config_agents_handling_hosting_device(
                hosting_device_id=hosting_device_id)['agents']
        return cfg_agents

    def failover_cfg_agent(self, cfg_agent, timeout=60):
        original_hosting_devices = \
            self.cfg_agent_client.list_hosting_device_handled_by_config_agent(
                cfg_agent_id=cfg_agent['id'])

        cfg_agent_ip = self.controller_dns[cfg_agent['host']]['ip']
        cmd = 'systemctl status neutron-cisco-cfg-agent.service'
        status = self.director_client.run_cmd_on(cfg_agent_ip, cmd)
        msg = "Cisco cfg agent is not running on {0}".format(cfg_agent_ip)
        self.assertRegexpMatches(status,
                                 '.+Active: .*active .running.+',
                                 msg)
        cmd = 'sudo systemctl stop neutron-cisco-cfg-agent.service | cat'
        self.director_client.run_cmd_on(cfg_agent_ip, cmd)
        time.sleep(90)

        cmd = 'systemctl status neutron-cisco-cfg-agent.service | cat'
        status = self.director_client.run_cmd_on(cfg_agent_ip, cmd)
        msg = "Cisco cfg agent is running on {0}".format(cfg_agent_ip)
        self.assertRegexpMatches(status,
                                 '.+Active: .*inactive .dead.+',
                                 msg)

        cmd = 'sudo systemctl start neutron-cisco-cfg-agent.service | cat'
        self.director_client.run_cmd_on(cfg_agent_ip, cmd)
        status = self.director_client.run_cmd_on(cfg_agent_ip, cmd)

        time.sleep(30)
        cmd = 'systemctl status neutron-cisco-cfg-agent.service '
        status = self.director_client.run_cmd_on(cfg_agent_ip, cmd)
        msg = "Cisco cfg agent is not running on {0}".format(cfg_agent_ip)
        self.assertRegexpMatches(status,
                                 '.+Active: .*active .running.+',
                                 msg)

        time.sleep(90)
        # Finally check the original cfg_agent isn't managing the original
        # hosting device(s)
        current_hosting_devices = \
            self.cfg_agent_client.list_hosting_device_handled_by_config_agent(
                cfg_agent_id=cfg_agent['id'])
        self.assertNotEqual(original_hosting_devices, current_hosting_devices)

    @testtools.skipUnless(CONF.cisco.asr1,
                          'ASR1 switch not specified in tempest.conf')
    @testtools.skipUnless(CONF.cisco.asr2,
                          'ASR2 switch not specified in tempest.conf')
    @test.attr(type='tc878')
    @test.attr(type='asr-cfg-agent-ha-functional')
    def test_active_device_cfg_agent_failover(self):
        """
        With one cfg-agent per hosting device, perform a failover of the
        cfg-agent managing the active hosting-device.  No new router update
        during the failover.
        """
        self.setup_cfg_agent_ha()
        self.setup_multinode_network()
        self.create_floating_ips()
        self.verify_asrs_insync()
        self.verify_vm_connectivity()
        self.verify_vm_to_vm_connectivity()
        active_asr = self.verify_asrs.active
        active_ha_router = self.get_ha_router(self.routers[0])
        active_cfg_agents = self.get_cfg_agent(active_ha_router)
        nc_counters_pre_failover = active_asr.get_netconf_counters()
        self.failover_cfg_agent(active_cfg_agents[0])
        nc_counters_post_failover = active_asr.get_netconf_counters()
        msg = "Netconf transaction errors reported pre-failover on " \
              "ASR {0}".format(active_asr.name)
        self.assertIs(0,
                      int(nc_counters_pre_failover['netconf-counters.transaction-errors']),
                      msg)
        msg = "Netconf transaction errors reported post-failover on " \
              "ASR {0}".format(active_asr.name)
        self.assertIs(0,
                      int(nc_counters_post_failover['netconf-counters.transaction-errors']),
                      msg)
        msg = "Netconf transactions seen during failover on " \
              "ASR {0}".format(active_asr.name)
        self.assertEqual(nc_counters_pre_failover['netconf-counters.transactions-total'],
                         nc_counters_post_failover['netconf-counters.transactions-total'],
                         msg)
        self.verify_asrs_insync()
        self.verify_vm_to_vm_connectivity()

    @testtools.skipUnless(CONF.cisco.asr1,
                          'ASR1 switch not specified in tempest.conf')
    @testtools.skipUnless(CONF.cisco.asr2,
                          'ASR2 switch not specified in tempest.conf')
    @test.attr(type='tc879')
    @test.attr(type='asr-cfg-agent-ha-regress')
    @test.attr(type='asr-cfg-agent-ha-functional')
    def test_standby_device_cfg_agent_failover(self):
        """
        With one cfg-agent per hosting device, perform a failover of the
        cfg-agent managing the standby hosting-device.  No new router update
        during the failover.
        """
        self.setup_cfg_agent_ha()
        self.setup_multinode_network()
        self.create_floating_ips()
        self.verify_asrs_insync()
        self.verify_vm_connectivity()
        self.verify_vm_to_vm_connectivity()
        standby_asr = self.verify_asrs.standby
        standby_ha_router = self.get_ha_router(self.routers[0],
                                               ha_state='STANDBY')
        standby_cfg_agent = self.get_cfg_agent(standby_ha_router)
        nc_counters_pre_failover = standby_asr.get_netconf_counters()
        self.failover_cfg_agent(standby_cfg_agent)
        nc_counters_post_failover = standby_asr.get_netconf_counters()
        msg = "Netconf transaction errors reported pre-failover on " \
              "ASR {0}".format(standby_asr.name)
        self.assertIs(0,
                      int(nc_counters_pre_failover['netconf-counters.transaction-errors']),
                      msg)
        msg = "Netconf transaction errors reported post-failover on " \
              "ASR {0}".format(standby_asr.name)
        self.assertIs(0,
                      int(nc_counters_post_failover['netconf-counters.transaction-errors']),
                      msg)
        msg = "Netconf transactions seen during failover on " \
              "ASR {0}".format(standby_asr.name)
        self.assertEqual(nc_counters_pre_failover['netconf-counters.transactions-total'],
                         nc_counters_post_failover['netconf-counters.transactions-total'],
                         msg)
        self.verify_asrs_insync()
        self.verify_vm_to_vm_connectivity()

    @testtools.skipUnless(CONF.cisco.asr1,
                          'ASR1 switch not specified in tempest.conf')
    @testtools.skipUnless(CONF.cisco.asr2,
                          'ASR2 switch not specified in tempest.conf')
    @test.attr(type='tc880')
    @test.attr(type='asr-cfg-agent-ha-regress')
    def test_all_device_cfg_agent_failover(self):
        """
        With the same cfg-agent managing both hosting devices, perform a
        failover.  No new router update during the failover.
        """
        self.setup_cfg_agent_ha('SINGLE_HA')
        self.setup_single_cfg_agent()
        self.setup_multinode_network()
        self.create_floating_ips()
        self.verify_asrs_insync()
        self.verify_vm_connectivity()
        self.verify_vm_to_vm_connectivity()
        active_asr = self.verify_asrs.active
        nc_counters_pre_failover = active_asr.get_netconf_counters()
        self.setup_cfg_agent_ha(ha_type='MULTI_HA')
        active_ha_router = self.get_ha_router(self.routers[0])
        active_cfg_agents = self.get_cfg_agent(active_ha_router)
        self.failover_cfg_agent(active_cfg_agents[0])
        nc_counters_post_failover = active_asr.get_netconf_counters()
        msg = "Netconf transaction errors reported pre-failover on " \
              "ASR {0}".format(active_asr.name)
        self.assertIs(0,
                      int(nc_counters_pre_failover['netconf-counters.transaction-errors']),
                      msg)
        msg = "Netconf transaction errors reported post-failover on " \
              "ASR {0}".format(active_asr.name)
        self.assertIs(0,
                      int(nc_counters_post_failover['netconf-counters.transaction-errors']),
                      msg)
        msg = "Netconf transactions seen during failover on " \
              "ASR {0}".format(active_asr.name)
        self.assertEqual(nc_counters_pre_failover['netconf-counters.transactions-total'],
                         nc_counters_post_failover['netconf-counters.transactions-total'],
                         msg)
        self.verify_asrs_insync()
        self.verify_vm_to_vm_connectivity()

    @testtools.skipUnless(CONF.cisco.asr1,
                          'ASR1 switch not specified in tempest.conf')
    @testtools.skipUnless(CONF.cisco.asr2,
                          'ASR2 switch not specified in tempest.conf')
    @test.attr(type='tc881')
    @test.attr(type='asr-cfg-agent-ha-regress')
    def test_net_create_during_active_failover(self):
        """
        During active hosting-device cfg-agent failover, create
        router/gateway/interface/floating IP.
        """
        self.setup_cfg_agent_ha()
        active_asr = self.verify_asrs.active
        active_ha_router = self.get_ha_router(self.routers[0])
        active_cfg_agent = self.get_cfg_agent(active_ha_router)
        self.failover_cfg_agent(active_cfg_agent)
        self.setup_multinode_network()
        self.create_floating_ips()
        self.verify_asrs_insync()
        self.verify_vm_connectivity()
        self.verify_vm_to_vm_connectivity()

    @testtools.skipUnless(CONF.cisco.asr1,
                          'ASR1 switch not specified in tempest.conf')
    @testtools.skipUnless(CONF.cisco.asr2,
                          'ASR2 switch not specified in tempest.conf')
    @test.attr(type='tc882')
    @test.attr(type='asr-cfg-agent-ha-regress')
    def test_net_delete_during_active_failover(self):
        """
        During active hosting-device cfg-agent failover, delete
        router/gateway/interface/floating IP.
        """
        self.setup_cfg_agent_ha()
        self.setup_multinode_network()
        self.create_floating_ips()
        self.verify_asrs_insync()
        self.verify_vm_connectivity()
        self.verify_vm_to_vm_connectivity()
        active_asr = self.verify_asrs.active
        active_ha_router = self.get_ha_router(self.routers[0])
        active_cfg_agent = self.get_cfg_agent(active_ha_router)
        self.failover_cfg_agent(active_cfg_agent)
        self.delete_multinode_network()
        self.setup_multinode_network()
        self.create_floating_ips()
        self.verify_asrs_insync()
        self.verify_vm_connectivity()
        self.verify_vm_to_vm_connectivity()

    @testtools.skipUnless(CONF.cisco.asr1,
                          'ASR1 switch not specified in tempest.conf')
    @testtools.skipUnless(CONF.cisco.asr2,
                          'ASR2 switch not specified in tempest.conf')
    @test.attr(type='tc883')
    @test.attr(type='asr-cfg-agent-ha-regress')
    def test_net_create_during_standby_failure(self):
        """
        During standby hosting-device cfg-agent failover,
        create router/gateway/interface/floating IP.
        """
        self.setup_cfg_agent_ha()
        standby_ha_router = self.get_ha_router(self.routers[0],
                                               ha_state='STANDBY')
        standby_cfg_agent = self.get_cfg_agent(standby_ha_router)
        self.failover_cfg_agent(standby_cfg_agent)
        self.setup_multinode_network()
        self.create_floating_ips()
        self.verify_asrs_insync()
        self.verify_vm_connectivity()
        self.verify_vm_to_vm_connectivity()

    @testtools.skipUnless(CONF.cisco.asr1,
                          'ASR1 switch not specified in tempest.conf')
    @testtools.skipUnless(CONF.cisco.asr2,
                          'ASR2 switch not specified in tempest.conf')
    @test.attr(type='tc884')
    @test.attr(type='asr-cfg-agent-ha-regress')
    def test_net_delete_during_standby_failure(self):
        """
        During standby hosting-device cfg-agent failover,
        delete router/gateway/interface/floating IP.
        """
        self.setup_cfg_agent_ha()
        self.setup_multinode_network()
        self.create_floating_ips()
        self.verify_asrs_insync()
        self.verify_vm_connectivity()
        self.verify_vm_to_vm_connectivity()
        standby_ha_router = self.get_ha_router(self.routers[0],
                                               ha_state='STANDBY')
        standby_cfg_agent = self.get_cfg_agent(standby_ha_router)
        self.failover_cfg_agent(standby_cfg_agent)
        self.delete_multinode_network()
        time.sleep(30)
        self.setup_multinode_network()
        self.create_floating_ips()
        time.sleep(60)
        self.verify_asrs_insync()
        self.verify_vm_connectivity()
        self.verify_vm_to_vm_connectivity()

    @testtools.skipUnless(CONF.cisco.asr1,
                          'ASR1 switch not specified in tempest.conf')
    @testtools.skipUnless(CONF.cisco.asr2,
                          'ASR2 switch not specified in tempest.conf')
    @test.attr(type='tc885')
    @test.attr(type='asr-cfg-agent-ha-regress')
    def test_net_create_single_agent_failover(self):
        """
        During single cfg-agent for both hosting-devices failover,
        create router/gateway/interface/floating IP.
        """
        self.setup_cfg_agent_ha('SINGLE_HA')
        standby_asr = self.verify_asrs.standby
        standby_ha_router = self.get_ha_router(self.routers[0],
                                               ha_state='STANDBY')
        standby_cfg_agent = self.get_cfg_agent(standby_ha_router)
        self.setup_cfg_agent_ha(ha_type='MULTI_HA')
        active_ha_router = self.get_ha_router(self.routers[0])
        active_cfg_agent = self.get_cfg_agent(active_ha_router)
        self.failover_cfg_agent(active_cfg_agent)
        self.setup_multinode_network()
        self.create_floating_ips()
        self.verify_asrs_insync()
        self.verify_vm_connectivity()
        self.verify_vm_to_vm_connectivity()

    @testtools.skipUnless(CONF.cisco.asr1,
                          'ASR1 switch not specified in tempest.conf')
    @testtools.skipUnless(CONF.cisco.asr2,
                          'ASR2 switch not specified in tempest.conf')
    @test.attr(type='tc886')
    @test.attr(type='asr-cfg-agent-ha-regress')
    def test_net_delete_single_agent_failover(self):
        """
        During single cfg-agent for both hosting-devices failover,
        delete router/gateway/interface/floating IP.
        """
        self.setup_cfg_agent_ha('SINGLE_HA')
        self.setup_multinode_network()
        self.create_floating_ips()
        self.verify_asrs_insync()
        self.verify_vm_connectivity()
        self.verify_vm_to_vm_connectivity()
        self.setup_cfg_agent_ha(ha_type='MULTI_HA')
        active_ha_router = self.get_ha_router(self.routers[0])
        active_cfg_agent = self.get_cfg_agent(active_ha_router)
        self.failover_cfg_agent(active_cfg_agent)
        self.delete_multinode_network()
        time.sleep(30)
        self.setup_multinode_network()
        self.create_floating_ips()
        time.sleep(60)
        self.verify_asrs_insync()
        self.verify_vm_connectivity()
        self.verify_vm_to_vm_connectivity()

