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
import datetime
import time
import testtools
import parsergen as pg
import tempest.thirdparty.cir.lib.asr_exceptions as asr_exceptions
import tempest.thirdparty.cir.lib.neutron_client as nc
import tempest.thirdparty.cir.lib.asr as asr

from tempest.thirdparty.cir.lib.device.LogInspector import LogInspector
from tempest.thirdparty.cir.lib.cfg_agent_client import CfgAgentClient
from oslo_log import log as logging
from tempest.lib import decorators
from tempest import config as tempest_conf
from tempest.scenario import test_network_multi_node
from tempest import test as test

CONF = tempest_conf.CONF

LOG = logging.getLogger(__name__)
LOG.debug("TestASRHeartbeat")


class TestASRHeartbeat(test_network_multi_node.TestNetworkMultiNode):
    """
    @REQUIREMENT: testbed has at least one neutron router created and
    its gateway set to the external/public network.
    @Terminal Server for the ASRs should have the following configured:
    aaa new-model
    aaa authentication login default enable
    """

    # For setting up cfg agent client
    default_params = {
        'disable_ssl_certificate_validation':
            CONF.identity.disable_ssl_certificate_validation,
        'ca_certs': CONF.identity.ca_certificates_file,
        'trace_requests': CONF.debug.trace_requests
    }

    def setUp(self):
        self.asr_go_offline = False
        self.switch_hsrp_priority = False
        self.reboot_asr = False
        self.switch_asr = False
        self.ping_fip_only = False
        self.addCleanup(self.check_log_errors)
        self.addCleanup(self.close_console)
        self.addCleanup(self.verify_asr_online)
        self.log_inspector = LogInspector()
        self.neutron_client = nc.NeutronClient('NeutronClient',
                                               ip=CONF.network.controller_ip,
                                               user=CONF.network.controller_user,
                                               pw=CONF.network.controller_pw,
                                               resource_file=CONF.network.controller_rc_file)

        self.cfg_agent_client = CfgAgentClient(self.manager.auth_provider,
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
                            internal_intf=CONF.cisco.asr1_internal_intf,
                            ts_ip=CONF.cisco.asr1_ts_ip,
                            ts_port=CONF.cisco.asr1_ts_port,
                            ts_pw=CONF.cisco.asr1_ts_pw)

        self.asr2 = asr.ASR(name=CONF.cisco.asr2,
                            ip=CONF.cisco.asr2_ip,
                            user=CONF.cisco.user_name,
                            pw=CONF.cisco.user_pw,
                            external_intf=CONF.cisco.asr2_external_intf,
                            internal_intf=CONF.cisco.asr2_internal_intf,
                            ts_ip=CONF.cisco.asr2_ts_ip,
                            ts_port=CONF.cisco.asr2_ts_port,
                            ts_pw=CONF.cisco.asr2_ts_pw)

        self.asr_pair = [self.asr1, self.asr2]

        self.asr1.clear_netconf_counters()
        self.asr2.clear_netconf_counters()

        self.verify_asrs = asr.VerifyASRStandby(active=self.asr1, standby=self.asr2)

        self.public_vlan_id = self.get_network_segmentation_id(self.neutron_client,
                                                               CONF.network.public_network_id)

        self.hosting_device_id_list = self.get_hosting_device_id_list(self.neutron_client)

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
        #for aggregate in self.aggregates:
        #    aggregate_info = \
        #        self.aggregates_client.show_aggregate(
        #            aggregate['id'])['aggregate']
        #    self._remove_host(aggregate['id'],
        #                     aggregate_info['hosts'][0])
        #    self.aggregates_client.delete_aggregate(aggregate['id'])

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

    def verify_asrs_insync(self, rebooted_asr=None, offline_asr=None):
        self.verify_asrs.check_active_asr(self.segmentation_ids[0])
        self.verify_asrs.netconf_counters()
        rtrs_under_test = self.get_rtrs_under_test(self.network_client.list_routers()['routers'],
                                                        self.tenant_id,
                                                        region_id=CONF.network.region1_id)
        self.verify_rtr_vrfs(rtrs_under_test, region_id=CONF.network.region1_id)
        self.verify_rtr_nat_pool(rtrs_under_test, region_id=CONF.network.region1_id)
        self.verify_asrs.nat_translations(self.floating_ip_tuples)
        self.verify_asrs.acls(self.network_client,
                              self.networks_client,
                              self.tenant_id,
                              self.segmentation_ids,
                              region_id=CONF.network.region1_id)
        if self.reboot_asr is True:
            self.switch_asr = self.verify_rebooted_asr(rtrs_under_test, rebooted_asr)
        elif self.asr_go_offline is True:
            # For each neutron router created, the associated active router
            # and HA backup router are hosted at the two ASRs respectively.
            # E.g. active router hosted at ASR1 and the backup router at ASR2.
            # For each tenant network interface attached to the router, an
            # internal sub-interface is created at each ASR.
            # The HSRP HA state for this sub-interface may be different from
            # from the router.  E.g. ASR1 hosts the active router but the
            # internal sub-interface HSRP HA state is in 'standby'.
            # This is to double check and reset the active and standby ASR
            # settings before checking the router specific external sub-interface
            # configurations since previously we used the internal sub-interface
            # (from the tenant network) to determine the settings.
            for rtr in rtrs_under_test:
                if rtr['hsrp_ha'] == 'active':
                    active_asr = rtr['asr_host']
                elif rtr['hsrp_ha'] == 'standby':
                    standby_asr = rtr['asr_host']
            self.verify_asrs = asr.VerifyASRStandby(active=active_asr, standby=standby_asr)

            self.switch_hsrp_priority = self.verify_offline_asr(rtrs_under_test, offline_asr)

        self.verify_asrs.ext_subintf(self.network_client,
                                     self.networks_client,
                                     self.routers,
                                     self.tenant_id,
                                     region_id=CONF.network.region1_id,
                                     switch_asr=self.switch_asr)

        #self.verify_asrs.standby_state(self.segmentation_ids,
        #                               switch_asr=self.switch_asr,
        #                               switch_hsrp_priority=self.switch_hsrp_priority)

    def close_console(self):
        self.asr1.console = None
        self.asr2.console = None

    def check_log_errors(self):
        self.log_inspector.record_errors('test-end')
        self.log_inspector.compare_logs('baseline', 'test-end')

    def check_cfg_size(self):
        max_time = 120
        sleep_for = 10
        start_time = time.time()
        current_time = time.time()
        timeout = current_time + max_time
        previous_id = "post-test-{0}".format(current_time)
        while current_time < timeout:
            id = "post-test-{0}".format(current_time)
            current_asr1_cfg_size = int(self.asr1.record_cfg_size(id))
            current_asr2_cfg_size = int(self.asr2.record_cfg_size(id))

            previous_asr1_cfg_size = int(self.asr1.get_cfg_size(previous_id))
            previous_asr2_cfg_size = int(self.asr2.get_cfg_size(id))
            previous_id= id

            if (current_asr1_cfg_size == previous_asr1_cfg_size) and \
                    (current_asr2_cfg_size == previous_asr2_cfg_size):
                break

            time.sleep(sleep_for)
            current_time = time.time()

        self.asr1.record_cfg_size('test-end')
        self.asr2.record_cfg_size('test-end')
        self.verify_asrs.eot_cfg_sizes()

    # Disable/enable the ASR management interface.
    def bounce_mgmt_link(self, asr, state):
        LOG.info("Set ASR {0} management interface to {1}".format(asr.name,
                                                                  state.upper()))
        asr.mgmt_intf_state(state=state)

    # Find the hosing device IDs for the ASRs.
    def get_hosting_device_id_list(self, neutron_client):
        the_nc = neutron_client
        hosting_devices = the_nc.cisco_hosting_device_list()
        hd_id_list = []
        for key in hosting_devices.keys():
            hd_id_list.append(key)

        return hd_id_list

    # Given the hosing device ID, find its IP.
    def get_hosting_device_ip(self, neutron_client, id):
        the_nc = neutron_client
        hd_info = the_nc.cisco_hosting_device_show(id)
        hd_ip = hd_info['management_ip_address']

        return hd_ip

    # Given the IP, find its hosting device ID.
    def get_hosting_device_id(self, neutron_client, id_list, ip):
        the_nc = neutron_client
        for id in id_list:
            hd_info = the_nc.cisco_hosting_device_show(id)
            if hd_info['management_ip_address'] == ip:
                hd_id = hd_info['id']

        return hd_id

    # Given the network name, find its segmentation ID.
    def get_network_segmentation_id(self, neutron_client, net):
        the_nc = neutron_client
        net_info = the_nc.net_show(net)
        net_segment_id = net_info['provider:segmentation_id']

        return net_segment_id

    # Get the hosting device state (ACTIVE/NON-RESPONDING/DEAD)
    # from the cfg-agent log.
    def get_hosting_device_state(self, log_inspector, start_time, id, sleep_for=60):
        hd_state = None
        log_inspector = log_inspector
        time.sleep(sleep_for)
        status_report = log_inspector.get_state_reports(start_time)

        for key in status_report.keys():
            if "configurations" in status_report[key]:
                if status_report[key]['configurations']['monitored_hosting_devices'][0]['host id'] == id:
                    hd_state = status_report[key]['configurations']['monitored_hosting_devices'][0]['hd_state']
                elif status_report[key]['configurations']['monitored_hosting_devices'][1]['host id'] == id:
                    hd_state = status_report[key]['configurations']['monitored_hosting_devices'][1]['hd_state']

        return hd_state

    # Verify the hosting device state from the cfg-agent log.
    def verify_hosting_device_state(self, log_inspector, id, state, max_time=300, sleep_for=60):
        log_inspector = log_inspector
        hd_id = id
        hd_state = state.upper()
        max_time = max_time
        sleep_for = sleep_for
        start_time = time.time()
        current_time = start_time
        timeout = current_time + max_time
        current_datetime = datetime.datetime.now()

        while current_time < timeout:
            current_state = self.get_hosting_device_state(log_inspector, current_datetime, hd_id, sleep_for)

            if current_state != hd_state:
                LOG.info("Waiting for hosting device {0} to reach {1} state".format(
                         hd_id, hd_state))
                current_time = time.time()

            else:
                LOG.info("Hosting device {0} reaches {1} state".format(hd_id, hd_state))
                return True

        if current_time >= timeout:
            msg = "Hosting-device {0} Fail to reach the expected state {1}".format(hd_id, hd_state)
            self.assertEqual(hd_state, current_state, msg)

    # Get the running-config size via the console connection.
    def console_get_cfg_size(self, asr, id):
        show_output = asr.console_send_command('show run | inc Current configuration')
        show_output_items = show_output.splitlines()

        cfg_size_re = re.compile(r'Current configuration\s+:\s+(\d+)')

        for item in show_output_items:
            cfg_size_match = cfg_size_re.match(item)
            if cfg_size_match:
                return cfg_size_match.group(1)

        return 0

    # Get the netconf counters via the console connection.
    def console_get_netconf_counters(self, asr):
        counters = {}
        show_output = asr.console_send_command('show netconf counters | section total')
        show_output_items = show_output.splitlines()
        counters_string = show_output_items[1].split()

        total_cntr_re = re.compile(r'total:(\d+)')
        success_cntr_re = re.compile(r'success:(\d+)')
        errors_cntr_re = re.compile(r'errors:(\d+)')

        for cntr_string in counters_string:
            total_cntr_match = total_cntr_re.match(cntr_string)
            if total_cntr_match:
                counters['transactions-total'] = int(total_cntr_match.group(1))

            success_cntr_match = success_cntr_re.match(cntr_string)
            if success_cntr_match:
                counters['transactions-success'] = int(success_cntr_match.group(1))

            errors_cntr_match = errors_cntr_re.match(cntr_string)
            if errors_cntr_match:
                counters['transactions-errors'] = int(errors_cntr_match.group(1))

        return counters

    # Get the neutron routers created by tempest during test
    # and determine the ASR that hosts the router.
    def get_rtrs_under_test(self, routers, tenant_id, region_id=None):
        num_routers = 0
        primary_rtr = {}
        rtrs_under_test = []
        for rtr in routers:
            if rtr['tenant_id'] == tenant_id:
                num_routers += 1
                rtr['asr_host'] = self.find_asr_host(rtr)
                rtr['hsrp_ha'] = 'active'
                rtrs_under_test.append(rtr)
                primary_rtr = rtr
                break

        primary_rtr_name = str(primary_rtr['name'])
        backup_rtr_name = primary_rtr_name + "_HA_backup_1"
        # Now look for the backup router
        for rtr in routers:
            if rtr['name'] == backup_rtr_name:
                num_routers += 1
                rtr['asr_host'] = self.find_asr_host(rtr)
                rtr['hsrp_ha'] = 'standby'
                rtrs_under_test.append(rtr)
                break

        if num_routers != 2:
            msg = "Not enough routers found for tenant-id " \
                  "{0}".format(tenant_id)
            raise asr_exceptions.NoRedundantASRException(msg)

        return rtrs_under_test

    # Find the ASR that hosts the Neutron router.
    def find_asr_host(self, router):
        asr_not_found = False
        hosting_device_id = None
        hosting_devices_resp = self.cfg_agent_client.list_hosting_devices()
        hosting_devices = hosting_devices_resp['hosting_devices']
        for hosting_device in hosting_devices:
            routers_on_hd = \
                self.cfg_agent_client.list_routers_on_hosting_device(
                    hosting_device_id=hosting_device['id'])['routers']
            for hd_router in routers_on_hd:
                if hd_router['id'] == router['id']:
                    hosting_device_id = hosting_device['id']
                    hosting_device_ip = hosting_device['management_ip_address']
                    break

        if hosting_device_id is None:
            msg = "Could not find hosting device for router {0}".format(
                router['id'])
            raise asr_exceptions.ASRTestException(msg)

        for asr_rtr in self.asr_pair:
            if asr_rtr.ip == hosting_device_ip:
                return asr_rtr
            else:
                asr_not_found = True

        if asr_not_found is True:
            msg = "Could not find the ASR for hosting device {0}".format(
                    hosting_device_id)
            raise asr_exceptions.ASRTestException(msg)

    def verify_rtr_vrfs(self, routers, region_id=None):
        for rtr in routers:
            rtr['asr_host'].verify_vrf(rtr, region_id=region_id)

    def verify_rtr_nat_pool(self, routers, region_id=None):
        for rtr in routers:
            asr_rtr = rtr['asr_host']
            vrf_name = self.verify_asrs.get_vrf_name(rtr, region_id=region_id)
            pool_name = vrf_name + "_nat_pool"
            attr_values = [('nat-pool.pool-name', pool_name), ]
            pg_sb = pg.oper_fill(asr_rtr,
                                 "show ip nat pool name {0}".format(pool_name),
                                 attr_values,
                                 refresh_cache=True,
                                 regex_tag_fill_pattern='^nat-pool\..*')
            nat_pool_data = {}
            if pg_sb.parse():
                result = pg.ext_dictio
                if asr_rtr.name in result:
                    nat_pool_data = result[asr_rtr.name]
                else:
                    msg = "{0} Failed to parse ip nat pool " \
                          "name output".format(asr_rtr.name)
                    raise asr_exceptions.ShowOutputParserException(msg)

            if 'nat-pool.pool-name' not in nat_pool_data or \
                            nat_pool_data['nat-pool.pool-name'] != pool_name:
                msg = "NAT Pool {0} is not configured " \
                      "on ASR {1}".format(pool_name, asr_rtr.name)
                raise asr_exceptions.NATPoolNotConfiguredException(msg)

            LOG.info("NAT Pool data = {0}".format(nat_pool_data))

    # If the ASR hosting the neutron active router is rebooted,
    # in terms of HSRP HA, the active router  will fail over to
    # the other ASR.  So switch the active/standby ASR to
    # account for it.
    def verify_rebooted_asr(self, routers, asr_rtr):
        previous_active_asr = asr_rtr
        swap_asr = False
        for rtr in routers:
            asr_host = rtr['asr_host']
            if rtr['hsrp_ha'] == 'active' and asr_host.ip == previous_active_asr.ip:
                swap_asr = True
        return swap_asr

    # If the neutron active router is scheduled on the ASR that goes
    # offline, the corresponding internal sub-interfaces for the tenant
    # networks will be hosted at the other ASR and in HSRP HA active
    # state, but with the lower HSRP prioity.
    # As such, need to swap the HSRP priority so that there will be no
    # failure when checking the HA state and priority for these internal
    # sub-interfaces.
    def verify_offline_asr(self, routers, asr_rtr):
        offline_asr = asr_rtr
        swap_hsrp_priority = False
        for rtr in routers:
            asr_host = rtr['asr_host']
            if rtr['hsrp_ha'] == 'active' and asr_host.ip == offline_asr.ip:
                swap_hsrp_priority = True
        return swap_hsrp_priority

    def poll_cfg_size(self, asr_rtr, id, cfg_size, max_time=300, sleep_for=60):
        expected_cfg_size = cfg_size
        current_time = time.time()
        timeout = current_time + max_time
        rtr_cfg_size = 0

        while current_time < timeout:
            asr_rtr.record_cfg_size(id)
            rtr_cfg_size = int(asr_rtr.get_cfg_size(id))

            # Sometimes the rtr_cfg_size and the expected_cfg_size
            # is not exactly the same but differs by up to 6 bytes
            # because a different IP address is assigned to the
            # external sub-interface, 15.0.0.0/24
            diff = abs(rtr_cfg_size - expected_cfg_size)
            if diff > 6:
                LOG.info("Polling ASR {0} running-config size".format(asr_rtr.name))
                asr_rtr.delete_cfg_size_record(id)
                time.sleep(sleep_for)
                current_time = time.time()
            else:
                return

        msg = "Config size is not as expected post test at " \
              "ASR {0}".format(asr_rtr.name)
        self.assertIs(expected_cfg_size, rtr_cfg_size, msg)


    def poll_ping(self, asr_rtr, ping_success=True, max_time=300, sleep_for=10):
        expected_result = ping_success
        current_time = time.time()
        timeout = current_time + max_time
        ping_result = False

        while current_time < timeout:
            try:
                ping_result = asr_rtr.ping_ip_address(asr_rtr.ip,
                                                      should_succeed=expected_result,
                                                      ping_timeout=10)
            except Exception:
                LOG.error("Unable to ping ASR {0} management interface {1}"
                          .format(asr_rtr.name, asr_rtr.ip))
                pass

            if ping_result is False:
                LOG.info("Pinging ASR {0} management interface".format(asr_rtr.name))
                time.sleep(sleep_for)
                current_time = time.time()
            else:
                if expected_result is True:
                    word = ''
                else:
                    word = 'not '
                LOG.info("ASR {0} management interface is {1}reachable"
                         .format(asr_rtr.name, word))
                return True

        if expected_result is True:
            word = 'not'
        else:
            word = 'still'
        msg = "ASR {0} management interface is {1} reachable"\
            .format(asr_rtr.name, word)
        self.assertIs(expected_result, ping_result, msg)

    def poll_netconf_ctr(self, asr_rtr, counter, max_time=300, sleep_for=10):
        current_time = time.time()
        timeout = current_time + max_time
        success_counter = -1
        netconf_counters = 0
        while current_time < timeout:
            try:
                netconf_counters = asr_rtr.get_netconf_counters()
                success_counter = int(netconf_counters[
                                          'netconf-counters.transaction-success'])
            except Exception:
                LOG.error("Unable to retrieve ASR {0} netconf counters".
                          format(asr_rtr.name))
                pass

            if success_counter < counter:
                LOG.info("Polling ASR {0} netconf counters".format(asr_rtr.name))
                time.sleep(sleep_for)
                current_time = time.time()
            else:
                return netconf_counters

        msg = "ASR {0} netconf successful transaction counter is not " \
              "as expected".format(asr_rtr.name)
        self.assertIs(counter, success_counter, msg)

    def verify_asr_online(self):
        for router in self.asr_pair:
            ping_result = router.ping_ip_address(router.ip,
                                                 should_succeed=True,
                                                 ping_timeout=10)
            if ping_result is False:
                self.bounce_mgmt_link(router, 'up')

    # Dummy test to avoid the test failure
    def test_network_multi_node(self):
        pass


    @testtools.skipUnless(CONF.cisco.asr1,
                          'ASR1 switch not specified in tempest.conf')
    @testtools.skipUnless(CONF.cisco.asr2,
                          'ASR2 switch not specified in tempest.conf')
    @test.attr(type='tc887')
    @test.attr(type='asr-heartbeat-regress')
    def test_net_create_active_not_responding(self):
        """
        While active hosting-device in 'NOT RESPONDING' state,
        - create router/gateway/tenant networks and attach to router;
        - launch VMs and associate floating IPs.
        """
        self.verify_asrs.check_active_asr(self.public_vlan_id)
        active_asr = self.verify_asrs.active
        active_asr_ip = self.verify_asrs.active.ip
        active_asr_hd_id = self.get_hosting_device_id(self.neutron_client,
                                                      self.hosting_device_id_list,
                                                      active_asr_ip)
        self.bounce_mgmt_link(active_asr, 'down')
        self.verify_hosting_device_state(self.log_inspector, active_asr_hd_id,
                                         'NOT RESPONDING', sleep_for=10)
        self.asr_go_offline = True
        pre_update_netconf_counters = self.console_get_netconf_counters(active_asr)
        self.setup_multinode_network()
        self.create_floating_ips()
        post_update_netconf_counters = self.console_get_netconf_counters(active_asr)
        msg = "Pre-update netconf transaction errors reported at " \
              "active ASR {0}".format(active_asr.name)
        self.assertIs(0, pre_update_netconf_counters['transactions-errors'], msg)

        msg = "Post-update netconf transaction errors reported at " \
              "active ASR {0}".format(active_asr.name)
        self.assertIs(0, post_update_netconf_counters['transactions-errors'], msg)

        msg = "Netconf transactions seen during config update at " \
              "active ASR {0}".format(active_asr.name)
        self.assertEqual(pre_update_netconf_counters['transactions-total'],
                         post_update_netconf_counters['transactions-total'],
                         msg)
        self.bounce_mgmt_link(active_asr, 'up')
        # Wait for the ASR to become reachable
        self.poll_ping(active_asr, ping_success=True)
        self.verify_hosting_device_state(self.log_inspector, active_asr_hd_id, 'ACTIVE',
                                         max_time=600, sleep_for=10)
        self.verify_asrs_insync(offline_asr=active_asr)
        self.verify_vm_connectivity()
        self.verify_vm_to_vm_connectivity()



    @testtools.skipUnless(CONF.cisco.asr1,
                          'ASR1 switch not specified in tempest.conf')
    @testtools.skipUnless(CONF.cisco.asr2,
                          'ASR2 switch not specified in tempest.conf')
    @test.attr(type='tc888')
    @test.attr(type='asr-heartbeat-regress')
    def test_net_delete_active_not_responding(self):
        """
        While active hosting-device in 'NOT RESPONDING' state,
        - disassociate floating IPs and delete VMs;
        - delete router interfaces/tenant networks;
        - unset gateway and delete router.
        """
        self.verify_asrs.check_active_asr(self.public_vlan_id)
        active_asr = self.verify_asrs.active
        active_asr_ip = self.verify_asrs.active.ip
        active_asr_hd_id = self.get_hosting_device_id(self.neutron_client,
                                                      self.hosting_device_id_list,
                                                      active_asr_ip)
        active_asr.record_cfg_size('tc888-test-start')
        test_start_cfg_size = int(active_asr.get_cfg_size('tc888-test-start'))
        self.setup_multinode_network()
        self.create_floating_ips()
        self.verify_asrs_insync()
        self.verify_vm_connectivity()
        self.verify_vm_to_vm_connectivity()
        self.bounce_mgmt_link(active_asr, 'down')
        self.verify_hosting_device_state(self.log_inspector, active_asr_hd_id,
                                         'NOT RESPONDING', sleep_for=10)
        pre_delete_netconf_counters = self.console_get_netconf_counters(active_asr)
        msg = "Pre-delete netconf transaction errors reported at " \
              "active ASR {0}".format(active_asr.name)
        self.assertIs(0, pre_delete_netconf_counters['transactions-errors'], msg)

        self.delete_multinode_network()

        post_delete_netconf_counters = self.console_get_netconf_counters(active_asr)
        msg = "Post-delete netconf transaction errors reported at " \
              "active ASR {0}".format(active_asr.name)
        self.assertIs(0, post_delete_netconf_counters['transactions-errors'], msg)

        msg = "Netconf transactions seen during config deletion at " \
              "active ASR {0}".format(active_asr.name)
        self.assertEqual(pre_delete_netconf_counters['transactions-total'],
                         post_delete_netconf_counters['transactions-total'],
                         msg)
        self.bounce_mgmt_link(active_asr, 'up')
        # Wait for the ASR to become reachable
        self.poll_ping(active_asr, ping_success=True)
        self.verify_hosting_device_state(self.log_inspector, active_asr_hd_id, 'ACTIVE',
                                         max_time=600, sleep_for=60)
        self.poll_cfg_size(active_asr, 'tc888-test-end', test_start_cfg_size, sleep_for=5)



    @testtools.skipUnless(CONF.cisco.asr1,
                          'ASR1 switch not specified in tempest.conf')
    @testtools.skipUnless(CONF.cisco.asr2,
                          'ASR2 switch not specified in tempest.conf')
    @test.attr(type='tc889')
    @test.attr(type='asr-heartbeat-regress')
    def test_net_create_standby_not_responding(self):
        """
        While standby hosting-device in 'NOT RESPONDING' state,
        - create router/gateway/tenant networks and attach to router;
        - launch VMs and associate floating IPs.
        """
        self.verify_asrs.check_active_asr(self.public_vlan_id)
        standby_asr = self.verify_asrs.standby
        standby_asr_ip = self.verify_asrs.standby.ip
        standby_asr_hd_id = self.get_hosting_device_id(self.neutron_client,
                                                       self.hosting_device_id_list,
                                                       standby_asr_ip)
        self.bounce_mgmt_link(standby_asr, 'down')
        self.verify_hosting_device_state(self.log_inspector, standby_asr_hd_id,
                                         'NOT RESPONDING', sleep_for=10)
        self.asr_go_offline = True
        pre_update_netconf_counters = self.console_get_netconf_counters(standby_asr)
        self.setup_multinode_network()
        self.create_floating_ips()
        post_update_netconf_counters = self.console_get_netconf_counters(standby_asr)
        msg = "Pre-update netconf transaction errors reported at " \
              "standby ASR {0}".format(standby_asr.name)
        self.assertIs(0, pre_update_netconf_counters['transactions-errors'], msg)

        msg = "Post-update netconf transaction errors reported at " \
              "standby ASR {0}".format(standby_asr.name)
        self.assertIs(0, post_update_netconf_counters['transactions-errors'], msg)

        msg = "Netconf transactions seen during config update at " \
              "standby ASR {0}".format(standby_asr.name)
        self.assertEqual(pre_update_netconf_counters['transactions-total'],
                         post_update_netconf_counters['transactions-total'],
                         msg)
        self.bounce_mgmt_link(standby_asr, 'up')
        # Wait for the ASR to become reachable
        self.poll_ping(standby_asr, ping_success=True)
        self.verify_hosting_device_state(self.log_inspector, standby_asr_hd_id, 'ACTIVE',
                                         max_time=600, sleep_for=10)
        self.verify_asrs_insync(offline_asr=standby_asr)
        self.verify_vm_connectivity()
        self.verify_vm_to_vm_connectivity()



    @testtools.skipUnless(CONF.cisco.asr1,
                          'ASR1 switch not specified in tempest.conf')
    @testtools.skipUnless(CONF.cisco.asr2,
                          'ASR2 switch not specified in tempest.conf')
    @test.attr(type='tc890')
    @test.attr(type='asr-heartbeat-regress')
    def test_net_delete_standby_not_responding(self):
        """
        While standby hosting-device in 'NOT RESPONDING' state,
        - disassociate floating IPs and delete VMs;
        - delete router interfaces/tenant networks;
        - unset gateway and delete router.
        """
        self.verify_asrs.check_active_asr(self.public_vlan_id)
        standby_asr = self.verify_asrs.standby
        standby_asr_ip = self.verify_asrs.standby.ip
        standby_asr_hd_id = self.get_hosting_device_id(self.neutron_client,
                                                       self.hosting_device_id_list,
                                                       standby_asr_ip)
        standby_asr.record_cfg_size('tc890-test-start')
        test_start_cfg_size = int(standby_asr.get_cfg_size('tc890-test-start'))
        self.setup_multinode_network()
        self.create_floating_ips()
        self.verify_asrs_insync()
        self.verify_vm_connectivity()
        self.verify_vm_to_vm_connectivity()
        self.bounce_mgmt_link(standby_asr, 'down')
        self.verify_hosting_device_state(self.log_inspector, standby_asr_hd_id,
                                         'NOT RESPONDING', sleep_for=10)
        pre_delete_netconf_counters = self.console_get_netconf_counters(standby_asr)
        msg = "Pre-delete netconf transaction errors reported at " \
              "standby ASR {0}".format(standby_asr.name)
        self.assertIs(0, pre_delete_netconf_counters['transactions-errors'], msg)

        self.delete_multinode_network()

        post_delete_netconf_counters = self.console_get_netconf_counters(standby_asr)
        msg = "Post-delete netconf transaction errors reported at " \
              "standby ASR {0}".format(standby_asr.name)
        self.assertIs(0, post_delete_netconf_counters['transactions-errors'], msg)

        msg = "Netconf transactions seen during config deletion at " \
              "standby ASR {0}".format(standby_asr.name)
        self.assertEqual(pre_delete_netconf_counters['transactions-total'],
                         post_delete_netconf_counters['transactions-total'],
                         msg)
        self.bounce_mgmt_link(standby_asr, 'up')
        # Wait for the ASR to become reachable
        self.poll_ping(standby_asr, ping_success=True)
        self.verify_hosting_device_state(self.log_inspector, standby_asr_hd_id, 'ACTIVE',
                                         max_time=600, sleep_for=10)

        self.poll_cfg_size(standby_asr, 'tc890-test-end', test_start_cfg_size, sleep_for=5)



    @testtools.skipUnless(CONF.cisco.asr1,
                          'ASR1 switch not specified in tempest.conf')
    @testtools.skipUnless(CONF.cisco.asr2,
                          'ASR2 switch not specified in tempest.conf')
    @test.attr(type='tc891')
    @test.attr(type='asr-heartbeat-regress')
    def test_net_create_active_dead(self):
        """
        While active hosting-device in 'DEAD' state,
        - create router/gateway/tenant networks and attach to router;
        - launch VMs and associate floating IPs.
        """
        self.verify_asrs.check_active_asr(self.public_vlan_id)
        active_asr = self.verify_asrs.active
        active_asr_ip = self.verify_asrs.active.ip
        active_asr_hd_id = self.get_hosting_device_id(self.neutron_client,
                                                      self.hosting_device_id_list,
                                                      active_asr_ip)
        self.bounce_mgmt_link(active_asr, 'down')
        self.verify_hosting_device_state(self.log_inspector, active_asr_hd_id, 'DEAD',
                                         max_time=600, sleep_for=10)
        self.asr_go_offline = True
        pre_update_netconf_counters = self.console_get_netconf_counters(active_asr)
        self.setup_multinode_network()
        self.create_floating_ips()
        post_update_netconf_counters = self.console_get_netconf_counters(active_asr)
        msg = "Pre-update netconf transaction errors reported at " \
              "active ASR {0}".format(active_asr.name)
        self.assertIs(0, pre_update_netconf_counters['transactions-errors'], msg)

        msg = "Post-update netconf transaction errors reported at " \
              "active ASR {0}".format(active_asr.name)
        self.assertIs(0, post_update_netconf_counters['transactions-errors'], msg)

        msg = "Netconf transactions seen during config update at " \
              "active ASR {0}".format(active_asr.name)
        self.assertEqual(pre_update_netconf_counters['transactions-total'],
                         post_update_netconf_counters['transactions-total'],
                         msg)
        self.bounce_mgmt_link(active_asr, 'up')
        # Wait for the ASR to become reachable
        self.poll_ping(active_asr, ping_success=True)
        self.verify_hosting_device_state(self.log_inspector, active_asr_hd_id, 'ACTIVE',
                                         max_time=600, sleep_for=10)
        self.verify_asrs_insync(offline_asr=active_asr)
        self.verify_vm_connectivity()
        self.verify_vm_to_vm_connectivity()



    @testtools.skipUnless(CONF.cisco.asr1,
                          'ASR1 switch not specified in tempest.conf')
    @testtools.skipUnless(CONF.cisco.asr2,
                          'ASR2 switch not specified in tempest.conf')
    @test.attr(type='tc892')
    @test.attr(type='asr-heartbeat-regress')
    def test_net_delete_active_dead(self):
        """
        While active hosting-device in 'DEAD' state,
        - disassociate floating IPs and delete VMs;
        - delete router interfaces/tenant networks;
        - unset gateway and delete router.
        """
        self.verify_asrs.check_active_asr(self.public_vlan_id)
        active_asr = self.verify_asrs.active
        active_asr_ip = self.verify_asrs.active.ip
        active_asr_hd_id = self.get_hosting_device_id(self.neutron_client,
                                                      self.hosting_device_id_list,
                                                      active_asr_ip)
        active_asr.record_cfg_size('tc892-test-start')
        test_start_cfg_size = int(active_asr.get_cfg_size('tc892-test-start'))
        self.setup_multinode_network()
        self.create_floating_ips()
        self.verify_asrs_insync()
        self.verify_vm_connectivity()
        self.verify_vm_to_vm_connectivity()
        self.bounce_mgmt_link(active_asr, 'down')
        self.verify_hosting_device_state(self.log_inspector, active_asr_hd_id, 'DEAD',
                                         max_time=600, sleep_for=10)
        pre_delete_netconf_counters = self.console_get_netconf_counters(active_asr)
        msg = "Pre-delete netconf transaction errors reported at " \
              "active ASR {0}".format(active_asr.name)
        self.assertIs(0, pre_delete_netconf_counters['transactions-errors'], msg)

        self.delete_multinode_network()

        post_delete_netconf_counters = self.console_get_netconf_counters(active_asr)
        msg = "Post-delete netconf transaction errors reported at " \
              "active ASR {0}".format(active_asr.name)
        self.assertIs(0, post_delete_netconf_counters['transactions-errors'], msg)

        msg = "Netconf transactions seen during config deletion at " \
              "active ASR {0}".format(active_asr.name)
        self.assertEqual(pre_delete_netconf_counters['transactions-total'],
                         post_delete_netconf_counters['transactions-total'],
                         msg)
        self.bounce_mgmt_link(active_asr, 'up')
        # Wait for the ASR to become reachable
        self.poll_ping(active_asr, ping_success=True)
        self.verify_hosting_device_state(self.log_inspector, active_asr_hd_id, 'ACTIVE',
                                         max_time=600, sleep_for=10)

        self.poll_cfg_size(active_asr, 'tc892-test-end', test_start_cfg_size, sleep_for=5)



    @testtools.skipUnless(CONF.cisco.asr1,
                          'ASR1 switch not specified in tempest.conf')
    @testtools.skipUnless(CONF.cisco.asr2,
                          'ASR2 switch not specified in tempest.conf')
    @test.attr(type='tc893')
    @test.attr(type='asr-heartbeat-regress')
    def test_net_create_standby_dead(self):
        """
        While standby hosting-device in 'DEAD' state,
        - create router/gateway/tenant networks and attach to router;
        - launch VMs and associate floating IPs.
        """
        self.verify_asrs.check_active_asr(self.public_vlan_id)
        standby_asr = self.verify_asrs.standby
        standby_asr_ip = self.verify_asrs.standby.ip
        standby_asr_hd_id = self.get_hosting_device_id(self.neutron_client,
                                                       self.hosting_device_id_list,
                                                       standby_asr_ip)
        self.bounce_mgmt_link(standby_asr, 'down')
        self.verify_hosting_device_state(self.log_inspector, standby_asr_hd_id, 'DEAD',
                                         max_time=600, sleep_for=10)
        self.asr_go_offline = True
        pre_update_netconf_counters = self.console_get_netconf_counters(standby_asr)
        self.setup_multinode_network()
        self.create_floating_ips()
        post_update_netconf_counters = self.console_get_netconf_counters(standby_asr)
        msg = "Pre-update netconf transaction errors reported at " \
              "standby ASR {0}".format(standby_asr.name)
        self.assertIs(0, pre_update_netconf_counters['transactions-errors'], msg)

        msg = "Post-update netconf transaction errors reported at " \
              "standby ASR {0}".format(standby_asr.name)
        self.assertIs(0, post_update_netconf_counters['transactions-errors'], msg)

        msg = "Netconf transactions seen during config update at " \
              "standby ASR {0}".format(standby_asr.name)
        self.assertEqual(pre_update_netconf_counters['transactions-total'],
                         post_update_netconf_counters['transactions-total'],
                         msg)
        self.bounce_mgmt_link(standby_asr, 'up')
        # Wait for the ASR to become reachable
        self.poll_ping(standby_asr, ping_success=True)
        self.verify_hosting_device_state(self.log_inspector, standby_asr_hd_id, 'ACTIVE',
                                         max_time=600, sleep_for=10)
        self.verify_asrs_insync(offline_asr=standby_asr)
        self.verify_vm_connectivity()
        self.verify_vm_to_vm_connectivity()



    @testtools.skipUnless(CONF.cisco.asr1,
                          'ASR1 switch not specified in tempest.conf')
    @testtools.skipUnless(CONF.cisco.asr2,
                          'ASR2 switch not specified in tempest.conf')
    @test.attr(type='tc894')
    @test.attr(type='asr-heartbeat-regress')
    @decorators.skip_because(bug="1232286")
    def test_net_delete_standby_dead(self):
        """
        While standby hosting-device in 'DEAD' state,
        - disassociate floating IPs and delete VMs;
        - delete router interfaces/tenant networks;
        - unset gateway and delete router.
        """
        self.verify_asrs.check_active_asr(self.public_vlan_id)
        standby_asr = self.verify_asrs.standby
        standby_asr_ip = self.verify_asrs.standby.ip
        standby_asr_hd_id = self.get_hosting_device_id(self.neutron_client,
                                                       self.hosting_device_id_list,
                                                       standby_asr_ip)
        standby_asr.record_cfg_size('tc894-test-start')
        test_start_cfg_size = int(standby_asr.get_cfg_size('tc894-test-start'))
        self.setup_multinode_network()
        self.create_floating_ips()
        self.verify_asrs_insync()
        self.verify_vm_connectivity()
        self.verify_vm_to_vm_connectivity()
        self.bounce_mgmt_link(standby_asr, 'down')
        self.verify_hosting_device_state(self.log_inspector, standby_asr_hd_id, 'DEAD',
                                         max_time=600, sleep_for=10)
        pre_delete_netconf_counters = self.console_get_netconf_counters(standby_asr)
        msg = "Pre-delete netconf transaction errors reported at " \
              "standby ASR {0}".format(standby_asr.name)
        self.assertIs(0, pre_delete_netconf_counters['transactions-errors'], msg)

        self.delete_multinode_network()

        post_delete_netconf_counters = self.console_get_netconf_counters(standby_asr)
        msg = "Post-delete netconf transaction errors reported at " \
              "standby ASR {0}".format(standby_asr.name)
        self.assertIs(0, post_delete_netconf_counters['transactions-errors'], msg)

        msg = "Netconf transactions seen during config deletion at " \
              "standby ASR {0}".format(standby_asr.name)
        self.assertEqual(pre_delete_netconf_counters['transactions-total'],
                         post_delete_netconf_counters['transactions-total'],
                         msg)
        self.bounce_mgmt_link(standby_asr, 'up')
        # Wait for the ASR to become reachable
        self.poll_ping(standby_asr, ping_success=True)
        self.verify_hosting_device_state(self.log_inspector, standby_asr_hd_id, 'ACTIVE',
                                         max_time=600, sleep_for=10)

        self.poll_cfg_size(standby_asr, 'tc894-test-end', test_start_cfg_size, sleep_for=5)



    @testtools.skipUnless(CONF.cisco.asr1,
                          'ASR1 switch not specified in tempest.conf')
    @testtools.skipUnless(CONF.cisco.asr2,
                          'ASR2 switch not specified in tempest.conf')
    @test.attr(type='tc895')
    @test.attr(type='asr-heartbeat-regress')
    def test_reboot_active(self):
        """
        Reboot active hosting-device.
        Verify config is replayed after the reboot.
        """
        self.verify_asrs.check_active_asr(self.public_vlan_id)
        active_asr = self.verify_asrs.active
        self.setup_multinode_network()
        self.create_floating_ips()
        self.verify_asrs_insync()
        self.verify_vm_connectivity()
        self.verify_vm_to_vm_connectivity()
        pre_reboot_netconf_counters = active_asr.get_netconf_counters()
        msg = "Pre-reboot netconf transaction errors reported at " \
              "active ASR {0}".format(active_asr.name)
        self.assertIs(0, int(pre_reboot_netconf_counters['netconf-counters.transaction-errors']), msg)
        active_asr.record_cfg_size('tc895-pre-reboot')
        pre_reboot_cfg_size = int(active_asr.get_cfg_size('tc895-pre-reboot'))
        LOG.info("Rebooting ASR {0}".format(active_asr.name))
        active_asr.reboot()
        self.reboot_asr = True
        # Wait for the ASR to become reachable
        self.poll_ping(active_asr, ping_success=True)
        self.verify_asrs_insync(rebooted_asr=active_asr)
        self.verify_vm_connectivity()
        self.verify_vm_to_vm_connectivity()
        post_reboot_netconf_counters = active_asr.get_netconf_counters()
        msg = "Post-reboot netconf transaction errors reported at " \
              "active ASR {0}".format(active_asr.name)
        self.assertIs(0, int(post_reboot_netconf_counters['netconf-counters.transaction-errors']), msg)
        active_asr.record_cfg_size('tc895-post-reboot')
        post_reboot_cfg_size = int(active_asr.get_cfg_size('tc895-post-reboot'))
        if post_reboot_cfg_size < pre_reboot_cfg_size:
            msg = "Config is not replayed post reboot at " \
                  "active ASR {0}".format(active_asr.name)
            self.assertEqual(pre_reboot_cfg_size, post_reboot_cfg_size, msg)



    @testtools.skipUnless(CONF.cisco.asr1,
                          'ASR1 switch not specified in tempest.conf')
    @testtools.skipUnless(CONF.cisco.asr2,
                          'ASR2 switch not specified in tempest.conf')
    @test.attr(type='tc896')
    @test.attr(type='asr-heartbeat-regress')
    def test_reboot_standby(self):
        """
        Reboot standby hosting-device.
        Verify config is replayed after the reboot.
        """
        self.verify_asrs.check_active_asr(self.public_vlan_id)
        standby_asr = self.verify_asrs.standby
        self.setup_multinode_network()
        self.create_floating_ips()
        self.verify_asrs_insync()
        self.verify_vm_connectivity()
        self.verify_vm_to_vm_connectivity()
        pre_reboot_netconf_counters = standby_asr.get_netconf_counters()
        msg = "Pre-reboot netconf transaction errors reported at " \
              "standby ASR {0}".format(standby_asr.name)
        self.assertIs(0, int(pre_reboot_netconf_counters['netconf-counters.transaction-errors']), msg)
        standby_asr.record_cfg_size('tc896-pre-reboot')
        pre_reboot_cfg_size = int(standby_asr.get_cfg_size('tc896-pre-reboot'))
        LOG.info("Rebooting ASR {0}".format(standby_asr.name))
        standby_asr.reboot()
        self.reboot_asr = True
        # Wait for the ASR to become reachable
        self.poll_ping(standby_asr, ping_success=True)
        self.verify_asrs_insync(rebooted_asr=standby_asr)
        self.verify_vm_connectivity()
        self.verify_vm_to_vm_connectivity()
        post_reboot_netconf_counters = standby_asr.get_netconf_counters()
        msg = "Post-reboot netconf transaction errors reported at " \
              "standby ASR {0}".format(standby_asr.name)
        self.assertIs(0, int(post_reboot_netconf_counters['netconf-counters.transaction-errors']), msg)
        standby_asr.record_cfg_size('tc896-post-reboot')
        post_reboot_cfg_size = int(standby_asr.get_cfg_size('tc896-post-reboot'))
        if post_reboot_cfg_size < pre_reboot_cfg_size:
            msg = "Config is not replayed post reboot at " \
                  "standby ASR {0}".format(standby_asr.name)
            self.assertEqual(pre_reboot_cfg_size, post_reboot_cfg_size, msg)



    @testtools.skipUnless(CONF.cisco.asr1,
                          'ASR1 switch not specified in tempest.conf')
    @testtools.skipUnless(CONF.cisco.asr2,
                          'ASR2 switch not specified in tempest.conf')
    @test.attr(type='tc897')
    @test.attr(type='asr-heartbeat-functional')
    @test.attr(type='asr-heartbeat-regress')
    def test_net_create_active_reboot(self):
        """
        During active hosting-device reboot,
        - create router/gateway/tenant networks and attach to router;
        - launch VMs and associate floating IPs.
        """
        self.verify_asrs.check_active_asr(self.public_vlan_id)
        active_asr = self.verify_asrs.active
        standby_asr = self.verify_asrs.standby
        active_asr.record_cfg_size('tc897-pre-reboot')
        pre_reboot_cfg_size = int(active_asr.get_cfg_size('tc897-pre-reboot'))
        LOG.info("Rebooting ASR {0}".format(active_asr.name))
        active_asr.reboot(wait=False)
        # Wait till the ASR is rebooted and becomes unreachable
        self.poll_ping(active_asr, ping_success=False)
        # Delete the ssh connection to ensure no stale connection exists
        active_asr.conn = None

        self.reboot_asr = True
        self.setup_multinode_network()
        self.create_floating_ips()
        standby_post_config_netconf_counters = standby_asr.get_netconf_counters()
        standby_success_transactions = int(standby_post_config_netconf_counters[
                                               'netconf-counters.transaction-success'])

        # Wait for the ASR to boot up and become reachable
        self.poll_ping(active_asr, ping_success=True)

        # Establish a new ssh connection
        active_asr.connect()

        post_reboot_netconf_counters = self.poll_netconf_ctr(active_asr,
                                                             standby_success_transactions)
        msg = "Post-reboot netconf transaction errors reported at " \
              "active ASR {0}".format(active_asr.name)
        self.assertIs(0, int(post_reboot_netconf_counters[
                                 'netconf-counters.transaction-errors']), msg)

        active_asr.record_cfg_size('tc897-post-reboot')
        post_reboot_cfg_size = int(active_asr.get_cfg_size('tc897-post-reboot'))
        if post_reboot_cfg_size <= pre_reboot_cfg_size:
            msg = "Config is not updated post reboot at " \
                  "active ASR {0}".format(active_asr.name)
            self.assertEqual(pre_reboot_cfg_size, post_reboot_cfg_size, msg)

        self.verify_asrs_insync(rebooted_asr=active_asr)
        self.verify_vm_connectivity()
        self.verify_vm_to_vm_connectivity()



    @testtools.skipUnless(CONF.cisco.asr1,
                          'ASR1 switch not specified in tempest.conf')
    @testtools.skipUnless(CONF.cisco.asr2,
                          'ASR2 switch not specified in tempest.conf')
    @test.attr(type='tc898')
    @test.attr(type='asr-heartbeat-functional')
    @test.attr(type='asr-heartbeat-regress')
    def test_net_delete_active_reboot(self):
        """
        During active hosting-device reboot,
        - disassociate floating IPs and delete VMs;
        - delete router interfaces/tenant networks;
        - unset gateway and delete router.
        """
        self.verify_asrs.check_active_asr(self.public_vlan_id)
        active_asr = self.verify_asrs.active
        active_asr.record_cfg_size('tc898-test-start')
        test_start_cfg_size = int(active_asr.get_cfg_size('tc898-test-start'))
        self.setup_multinode_network()
        self.create_floating_ips()
        self.verify_asrs_insync()
        self.verify_vm_connectivity()
        self.verify_vm_to_vm_connectivity()
        LOG.info("Rebooting ASR {0}".format(active_asr.name))
        active_asr.reboot(wait=False)
        # Need to wait for 30 seconds because the mgmt interface
        # would go offline momentarily for a couple seconds and
        # become pingable again for the next 20+ seconds before
        # eventually go offline when the system goes into reboot
        time.sleep(30)
        # Wait till the ASR is rebooted and becomes unreachable
        self.poll_ping(active_asr, ping_success=False)
        # Delete the ssh connection to ensure no stale connection exists
        active_asr.conn = None

        self.reboot_asr = True
        self.delete_multinode_network()

        # Wait for the ASR to boot up and become reachable
        self.poll_ping(active_asr, ping_success=True)

        # Establish a new ssh connection
        active_asr.connect()

        self.poll_cfg_size(active_asr, 'tc898-test-end', test_start_cfg_size, sleep_for=5)
        post_reboot_netconf_counters = active_asr.get_netconf_counters()
        msg = "Post-reboot netconf transaction errors reported at " \
              "active ASR {0}".format(active_asr.name)
        self.assertIs(0, int(post_reboot_netconf_counters[
                                 'netconf-counters.transaction-errors']), msg)



    @testtools.skipUnless(CONF.cisco.asr1,
                          'ASR1 switch not specified in tempest.conf')
    @testtools.skipUnless(CONF.cisco.asr2,
                          'ASR2 switch not specified in tempest.conf')
    @test.attr(type='tc899')
    @test.attr(type='asr-heartbeat-regress')
    def test_net_create_standby_reboot(self):
        """
        During standby hosting-device reboot,
        - create router/gateway/tenant networks and attach to router;
        - launch VMs and associate floating IPs.
        """
        self.verify_asrs.check_active_asr(self.public_vlan_id)
        active_asr = self.verify_asrs.active
        standby_asr = self.verify_asrs.standby
        standby_asr.record_cfg_size('tc899-pre-reboot')
        pre_reboot_cfg_size = int(standby_asr.get_cfg_size('tc899-pre-reboot'))
        LOG.info("Rebooting ASR {0}".format(standby_asr.name))
        standby_asr.reboot(wait=False)
        # Wait till the ASR is rebooted and becomes unreachable
        self.poll_ping(standby_asr, ping_success=False)
        # Delete the ssh connection to ensure no stale connection exists
        standby_asr.conn = None

        self.reboot_asr = True
        self.setup_multinode_network()
        self.create_floating_ips()
        active_post_config_netconf_counters = active_asr.get_netconf_counters()
        active_success_transactions = int(active_post_config_netconf_counters[
                                              'netconf-counters.transaction-success'])

        # Wait for the ASR to boot up and become reachable
        self.poll_ping(standby_asr, ping_success=True)

        # Establish a new ssh connection
        standby_asr.connect()

        post_reboot_netconf_counters = self.poll_netconf_ctr(standby_asr,
                                                             active_success_transactions)
        msg = "Post-reboot netconf transaction errors reported at " \
              "standby ASR {0}".format(standby_asr.name)
        self.assertIs(0, int(post_reboot_netconf_counters[
                                 'netconf-counters.transaction-errors']), msg)

        standby_asr.record_cfg_size('tc899-post-reboot')
        post_reboot_cfg_size = int(standby_asr.get_cfg_size('tc899-post-reboot'))
        if post_reboot_cfg_size <= pre_reboot_cfg_size:
            msg = "Config is not updated post reboot at " \
                  "standby ASR {0}".format(standby_asr.name)
            self.assertEqual(pre_reboot_cfg_size, post_reboot_cfg_size, msg)

        self.verify_asrs_insync(rebooted_asr=standby_asr)
        self.verify_vm_connectivity()
        self.verify_vm_to_vm_connectivity()



    @testtools.skipUnless(CONF.cisco.asr1,
                          'ASR1 switch not specified in tempest.conf')
    @testtools.skipUnless(CONF.cisco.asr2,
                          'ASR2 switch not specified in tempest.conf')
    @test.attr(type='tc900')
    @test.attr(type='asr-heartbeat-regress')
    def test_net_delete_standby_reboot(self):
        """
        During standby hosting-device reboot,
        - disassociate floating IPs and delete VMs;
        - delete router interfaces/tenant networks;
        - unset gateway and delete router.
        """
        self.verify_asrs.check_active_asr(self.public_vlan_id)
        standby_asr = self.verify_asrs.standby
        standby_asr.record_cfg_size('tc900-test-start')
        test_start_cfg_size = int(standby_asr.get_cfg_size('tc900-test-start'))
        self.setup_multinode_network()
        self.create_floating_ips()
        self.verify_asrs_insync()
        self.verify_vm_connectivity()
        self.verify_vm_to_vm_connectivity()
        LOG.info("Rebooting ASR {0}".format(standby_asr.name))
        standby_asr.reboot(wait=False)
        # Need to wait for 30 seconds because the mgmt interface
        # would go offline momentarily for a couple seconds and
        # become pingable again for the next 20+ seconds before
        # eventually go offline when the system goes into reboot
        time.sleep(30)
        # Wait till the ASR is rebooted and becomes unreachable
        self.poll_ping(standby_asr, ping_success=False)
        # Delete the ssh connection to ensure no stale connection exists
        standby_asr.conn = None

        self.reboot_asr = True
        self.delete_multinode_network()

        # Wait for the ASR to boot up and become reachable
        self.poll_ping(standby_asr, ping_success=True)

        # Establish a new ssh connection
        standby_asr.connect()

        self.poll_cfg_size(standby_asr, 'tc900-test-end', test_start_cfg_size, sleep_for=5)
        post_reboot_netconf_counters = standby_asr.get_netconf_counters()
        msg = "Post-reboot netconf transaction errors reported at " \
              "standby ASR {0}".format(standby_asr.name)
        self.assertIs(0, int(post_reboot_netconf_counters['netconf-counters.transaction-errors']), msg)
