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
import parsergen as pg
import tempest.thirdparty.cir.lib.pg.brctl as brctl

from oslo_log import log as logging
from tempest import config
from tempest.scenario import test_network_multi_node

CONF = config.CONF

LOG = logging.getLogger(__name__)


class TestVxlanLinuxBridge(test_network_multi_node.TestNetworkMultiNode):
    """
    This script verifies the basic functionality of
    VXLAN overlay with Linux bridge
    """
    @classmethod
    def skip_checks(cls):
        super(TestVxlanLinuxBridge, cls).skip_checks()

        if not (CONF.network.bridge_type):
            msg = 'Bridge type must be identified in tempest.conf'
            raise cls.skipException(msg)

        bridge_type = CONF.network.bridge_type
        if bridge_type != 'linux':
            msg = 'Bridge type is not Linux'
            raise cls.skipException(msg)

    def setUp(self):
        super(TestVxlanLinuxBridge, self).setUp()

        self.network_ids = []
        self.bridges = []

        # Establish ssh connections to the controller and computer nodes
        routers = []
        for router_name in routers:
            LOG.debug("router_name is: {0}".format(router_name))
            router = routers[router_name]
            # Login to the  node
            cmd = "ssh -p {0} {1}@{2}".format(router.config['ssh_port'],
                                              router.config['login'],
                                              router.config['console'])
            router.spawn_connection(False, cmd=cmd)
            router._login()
            router.send_command('')

        self.controller = routers[CONF.network.controller]
        self.compute1 = routers[CONF.network.compute1]
        self.compute2 = routers[CONF.network.compute2]

        self.stack_nodes = [self.controller,
                            self.compute1,
                            self.compute2]

        self.compute_nodes = [self.compute1, self.compute2]

    def verify_network_create_events(self):
        """
        For each tenant network created and used by a tenant VM,
        a corresponding Linux bridge is created with an interface
        named "vxlan-<network_segmentation_id>"
        """
        for network in self.networks:
            network_id = network['id']
            segmentation_id = network['provider:segmentation_id']

            # The bridge name has the prefix "brq"
            # plus the first 11 characters of the network id.
            # E.g. if network id = 3441d2d3-7c26-4c0e-8607-db95d77e2dc9
            # The bridge name will be "brq3441d2d3-7c"
            bridge_name = 'brq' + network_id[0:11]
            self.bridges.append(bridge_name)

            # For each bridge, there should be an interface named
            # "vxlan-<segmentation_id> attached
            interface_name = "vxlan-" + str(segmentation_id)

            for node in self.stack_nodes:
                node.send_command('')
                pg.ext_dictio = {}
                pg.oper_fill(node,
                             ["SHOW_BRIDGE"],
                             ['bridge.name',
                             'bridge.stp',
                             'bridge.tap',
                             'bridge.interface'],
                             [bridge_name, None, None, None],
                             refresh_cache=True)
                bridge_values = pg.ext_dictio

                # Verify the vxlan interface is present at the bridge
                self.assertEqual(interface_name, bridge_values['bridge.interface'])


    def get_interface_mtu(self, node, interface_list):
        """
        Return the MTU of the bridge interface passed in
        """
        self.intf_mtu = {}

        for intf in interface_list:
            cmd = "ip link show {0}".format(intf)
            node.send_command('')
            ip_link_output = node.send_command(cmd + '\n')
            ip_link_data = ip_link_output.splitlines()

            # Output data example:
            # 1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT
            ip_link_re = re.compile(r'''
                                    ^\d+:\s+               # match the numbering entry, 1:
                                    [-A-Za-z0-9\\._/]+:\s+ # match the device name, lo:
                                    \D[-A-Za-z0-9,_]+\D\s+ # match misc enclosed in <>, <LOOPBACK,UP,LOWER_UP>
                                    mtu\s+                 # match the word mtu, mtu
                                    (\d+)\s+               # match the mtu value, 65536
                                    [A-Za-z0-9\s]+         # match the rest, qdisc noqueue state UNKNOWN mode DEFAULT
                                    ''', re.VERBOSE)

            for line in ip_link_data:
                match = ip_link_re.match(line)
                if match is not None:
                    mtu = match.group(1)
                    self.intf_mtu[intf] = mtu
                    break
        return self.intf_mtu

    def check_bridge_interface_mtu(self):
        """
        VXLAN overhead is 50 bytes.
        For the vxlan interface attached to the Linux bridge,
        MTU should be 50 less.
        """
        if not (CONF.network.network_interface_mtu):
            target_mtu = 1500
        else:
            target_mtu = CONF.network.network_interface_mtu

        for bridge_name in self.bridges:
            for node in self.compute_nodes:
                bridge_interfaces = []
                bridge_interfaces_mtu = {}
                node.send_command('')
                pg.ext_dictio = {}
                pg.oper_fill(node,
                             ["SHOW_BRIDGE"],
                             ['bridge.name',
                             'bridge.stp',
                             'bridge.tap',
                             'bridge.interface'],
                             [bridge_name, None, None, None],
                             refresh_cache=True)
                bridge_values = pg.ext_dictio

                # Get the bridge vxlan interface(s)
                vxlan_intf = bridge_values['bridge.interface']
                bridge_interfaces.append(vxlan_intf)

                # Get the bridge tap interface(s)
                tap_intf = bridge_values['bridge.tap']
                bridge_interfaces.append(tap_intf)

                # Retrieve the bridge interface MTU
                # and compare to the expected value
                bridge_interfaces_mtu = self.get_interface_mtu(node, bridge_interfaces)

                pattern = re.compile(r'(vxlan-)+\d+')
                for key in bridge_interfaces_mtu:
                    match = pattern.match(key)
                    if match:
                        expected_mtu = target_mtu - 50
                    else:
                        expected_mtu = target_mtu

                    self.assertEqual(str(expected_mtu), bridge_interfaces_mtu[key])

    def verify_network_delete_events(self):
        """
        Verify tenant network bridges are deleted
        """
        for bridge_name in self.bridges:
            for node in self.compute_nodes:
                node.send_command('')
                pg.ext_dictio = {}
                pg.oper_fill(node,
                             ["SHOW_BRIDGE"],
                             ['bridge.name',
                             'bridge.stp',
                             'bridge.tap',
                             'bridge.interface'],
                             [bridge_name, None, None, None],
                             refresh_cache=True)
                bridge_values = pg.ext_dictio

                self.assertEqual(0, len(bridge_values.keys()),
                                 "Bridge %s is not deleted" % bridge_name)

    def test_vxlan_linux_bridge(self):
        self.verify_network_create_events()
        self.create_floating_ips()
        self.check_bridge_interface_mtu()
        self.verify_vm_connectivity()
        self.verify_network_element_ready()
        self.verify_vm_to_vm_connectivity()
        self.verify_network_element_traffic_flows()
        self.delete_vms()
        self.verify_network_delete_events()