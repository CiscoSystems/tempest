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

import sys
import os
import re

if None:

    from tempest import config
    from tempest import exceptions
    from tempest.openstack.common import log as logging
    from tempest.scenario import test_network_multi_node

    import parsergen as pg
    import tempest.thirdparty.cir.lib.pg.vlan as vlan
    import tempest.thirdparty.cir.lib.pg.vlan_counters as vlan_counters
    import tempest.thirdparty.cir.lib.pg.interface_counters as interface_counters


CONF = config.CONF
LOG = logging.getLogger(__name__)

SSH_PORT = 22


class VlanCountersBasicTest(test_network_multi_node.TestNetworkMultiNode):

    @classmethod
    def check_preconditions(cls):
        if not (CONF.network.tenant_networks_reachable
                or CONF.network.public_network_id):
            msg = ('Either tenant_networks_reachable must be "true", or '
                   'public_network_id must be defined.')
            cls.enabled = False
            raise cls.skipException(msg)

        # Variables used to determine if Cisco gear is defined
        # in the tempest.conf file
        cls.setup_has_leaf_sw = False

        if CONF.cisco.leaf_sws:
            cls.leaf_sws = CONF.cisco.leaf_sws

            if cls.leaf_sws is not None:
                cls.setup_has_leaf_sw = True
                if not CONF.cisco.leaf_sw_connections:
                    msg = "leaf_sw_connections must be defined when " \
                          "leaf_sws is specified"
                    cls.enabled = False
                    raise cls.skipException(msg)

        super(VlanCountersBasicTest, cls).check_preconditions()

    def setUp(self):
        super(VlanCountersBasicTest, self).setUp()
        self.expected_mtu = 1400

        #########################################
        from cli import opt
        opt.use_ssh = True

        self.leaf1 = routers['leaf1']
        self.leaf1.original_router = self.leaf1
        self.leaf1.is_real_device = True
        self.leaf1.is_ng_node = True
        self.leaf1.portvector['DYNPORTssh'] = SSH_PORT
        self.leaf1.portvector['PortConsole'] = SSH_PORT
        self.leaf1.portvector['PortAux'] = SSH_PORT
        self.leaf1.portvector['SimulationHost'] = '172.22.191.67'
        self.leaf1.spawn_connection(False, cmd='ssh admin@172.22.191.67')
        self.leaf1._login()
        self.leaf1.send_command('')
        self.leaf1.send_command('')
        ##########################################

    def verify_network_create_events(self):
        """
        This method is called after all the VMs are placed on networks
        which should created the VLANs on the switch.  Verify VLANs
        show in the switch configuration.
        """
        for vlan_id in self.segmentation_ids:
            # Create predicate to test status of vlan
            pred = pg.oper_check(self.leaf1,
                                 ["SHOW_VLAN"],
                                 ['vlan.id',
                                  'vlan.status'],
                                 [vlan_id, 'active'], True)

            pred.assert_test_case()

            # Manually test status and record values
            pg.ext_dictio = {}
            pg.oper_fill(self.leaf1,
                         ["SHOW_VLAN"],
                         ['vlan.id',
                          'vlan.name',
                          'vlan.status',
                          'vlan.ports'],
                         [vlan_id, None, None, None], True)

            vlan_values = pg.ext_dictio
            LOG.info("VLAN Values {0}".format(vlan_values))

            ## Verify the VLAN is active
            self.assertEqual('active', vlan_values['vlan.status'])

    def verify_network_delete_events(self):
        """
        This method is called after the VMs are deleted, any previously
        created VLANs should be deleted by the ML2 driver.  Verify
        none of the VLANs are still configured on the switch.
        """
        for vlan_id in self.segmentation_ids:
            pg.ext_dictio = {}
            pg.oper_fill(self.leaf1,
                         ["SHOW_VLAN"],
                         ['vlan.id',
                          'vlan.name',
                          'vlan.status',
                          'vlan.ports'],
                         [vlan_id, None, None, None], True)

            vlan_values = pg.ext_dictio
            if 'vlan.id' in vlan_values:
                self.assertNotEqual(vlan_id, vlan_values['vlan.id'])

            LOG.info("VLAN Values {0}".format(vlan_values))

    def verify_network_element_ready(self):

        ## First check that the MTU is as expected on the remote host
        if self.linux_client is None:
            self.setup_linux_client()

        ip_a_output = None
        for cmd in ['/sbin/ip a', '/bin/ip a']:
            ip_a_output = None
            try:
                ip_a_output = self.linux_client.exec_command(cmd).splitlines()
                break
            except exceptions.SSHExecCommandFailed:
                pass

        self.assertIsNotNone(ip_a_output)

        intf_re = re.compile(r"""
                               ^(\d+)[:]\s
                               eth(\d+)[:]\s
                               <.+>\s
                               mtu\s
                               (\d+)\s
                               .*""", re.VERBOSE | re.IGNORECASE)
        LOG.debug("Linux client output: {0}".format(ip_a_output))
        self.actual_mtu = None
        for line in ip_a_output:
            m = intf_re.match(line.strip())
            if m is not None:
                self.actual_mtu = int(m.group(3))
                break

        self.assertEqual(self.expected_mtu, self.actual_mtu)

        LOG.debug("MTU Found on VM is {0}".format(self.actual_mtu))

        for vlan_id in self.segmentation_ids:
            self.leaf1.send_command("clear vlan id {0} counters".format(vlan_id))

            pred = pg.oper_check(self.leaf1,
                                 ["SHOW_VLAN_COUNTERS"],
                                 ['vlan-counters.vlan-id',
                                  'vlan-counters.total-pkts-in',
                                  'vlan-counters.total-pkts-out'],
                                 [vlan_id, "0", "0"], True)

            pred.assert_test_case()

            pg.oper_fill(self.leaf1,
                         ["SHOW_VLAN_COUNTERS"],
                         ['vlan-counters.vlan-id',
                          'vlan-counters.total-pkts-in',
                          'vlan-counters.total-pkts-out'],
                         [vlan_id, None, None], True)

            vlan_counter_values = pg.ext_dictio
            LOG.debug("VLAN {0} Input pkts {1}, Output pkts {2}"
                      .format(vlan_counter_values['vlan-counters.vlan-id'],
                              vlan_counter_values['vlan-counters.total-pkts-in'],
                              vlan_counter_values['vlan-counters.total-pkts-out']))

    def verify_network_element_traffic_flows(self):

        for vlan_id in self.segmentation_ids:
            pg.oper_fill(self.leaf1,
                         ["SHOW_VLAN_COUNTERS"],
                         ['vlan-counters.vlan-id',
                          'vlan-counters.total-pkts-in',
                          'vlan-counters.total-pkts-out'],
                         [vlan_id, None, None], True)

            vlan_counter_values = pg.ext_dictio
            LOG.debug("VLAN {0} Input pkts {1}, Output pkts {2}"
                      .format(vlan_counter_values['vlan-counters.vlan-id'],
                              vlan_counter_values['vlan-counters.total-pkts-in'],
                              vlan_counter_values['vlan-counters.total-pkts-out']))

