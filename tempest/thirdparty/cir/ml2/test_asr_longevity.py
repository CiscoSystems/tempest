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

import datetime
import os
import time
import subprocess
import signal
import tempest.thirdparty.cir.lib.asr_exceptions as asr_exceptions
import tempest.thirdparty.cir.lib.neutron_client as nc
import tempest.thirdparty.cir.lib.asr as asr
import testtools

from tempest.thirdparty.cir.lib.device.LogInspector import LogInspector
from oslo_log import log as logging
from tempest.lib import decorators
from tempest import config as tempest_conf
from tempest.scenario import test_network_multi_node
from tempest import test as test

CONF = tempest_conf.CONF

LOG = logging.getLogger(__name__)
LOG.debug("TestASRLongevity")


class TestASRLongevity(test_network_multi_node.TestNetworkMultiNode):

    def setUp(self):
        self.start_time = datetime.datetime.now()
        #super(TestASRLongevity, self).setUp()
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
        for router in self.routers:
            router.unset_gateway()

        for network in self.networks:
            dhcp_agents = \
                self.network_client.list_dhcp_agent_hosting_network(
                    network_id=network['id'])['agents']
            for agent in dhcp_agents:
                self.network_client.remove_network_from_dhcp_agent(
                    agent_id=agent['id'], network_id=network['id'])

            subnets = self.network_client.list_subnets(network_id=network['id'])['subnets']
            for subnet in subnets:
                for router in self.routers:
                    self.network_client.remove_router_interface_with_subnet_id(
                        router_id=router['id'], subnet_id=subnet['id'])
            network.delete()

        for router in self.routers:
            router.delete()

    def test_asr_longevity_datapath(self):
        current_time = time.time()
        self.setup_multinode_network()
        self.create_floating_ips()

        timeout = current_time + CONF.scenario.test_duration
        while current_time < timeout:
            self.verify_vm_connectivity()
            self.verify_vm_to_vm_connectivity()
            current_time = time.time()

        self.delete_vms()

    def test_asr_longevity_control_plane(self):
        self.setup_multinode_network()
        self.create_floating_ips()
        self.delete_vms()

    def test_asr_longevity_control_plane_churn(self):
        current_time = time.time()
        timeout = current_time + CONF.scenario.test_duration
        while current_time < timeout:
            self.setup_multinode_network()
            self.create_floating_ips()
            self.delete_multinode_network()
            current_time = time.time()
