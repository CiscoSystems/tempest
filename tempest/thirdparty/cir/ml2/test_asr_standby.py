
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
import re
import time
import subprocess
import signal
import tempest.thirdparty.cir.lib.asr_exceptions as asr_exceptions
import tempest.thirdparty.cir.lib.neutron_client as nc
import tempest.thirdparty.cir.lib.asr as asr
import testtools
import pdb

from tempest.thirdparty.cir.lib.device.LogInspector import LogInspector
from oslo_log import log as logging
from tempest.lib import decorators
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest import config as tempest_conf
from tempest.scenario import test_network_multi_node
from tempest import test as test

CONF = tempest_conf.CONF

LOG = logging.getLogger(__name__)
LOG.debug("TestASRStandBy")


class TestASRStandBy(test_network_multi_node.TestNetworkMultiNode):

    def setUp(self):

        self.log_inspector = LogInspector()
        self.log_inspector.find_state_reports()
        self.start_time = datetime.datetime.now()
        self.addCleanup(self.cleanup_asr_leftovers)
        self.addCleanup(self.check_log_errors)
        self.addCleanup(self.check_cfg_size)
        self.neutron_client = nc.NeutronClient(
            'NeutronClient',
            ip=CONF.network.controller_ip,
            user=CONF.network.controller_user,
            pw=CONF.network.controller_pw,
            resource_file=CONF.network.controller_rc_file)
        self.neutron_client.send_command('ls')

        self.active_asr = asr.ASR(name=CONF.cisco.asr1,
                                  ip=CONF.cisco.asr1_ip,
                                  user=CONF.cisco.user_name,
                                  pw=CONF.cisco.user_pw,
                                  external_intf=CONF.cisco.asr1_external_intf,
                                  internal_intf=CONF.cisco.asr1_internal_intf)

        self.standby_asr = asr.ASR(name=CONF.cisco.asr2,
                                   ip=CONF.cisco.asr2_ip,
                                   user=CONF.cisco.user_name,
                                   pw=CONF.cisco.user_pw,
                                   external_intf=CONF.cisco.asr2_external_intf,
                                   internal_intf=CONF.cisco.asr2_internal_intf)
        self.active_asr.record_cfg_size('test-start')
        self.standby_asr.record_cfg_size('test-start')
        self.active_asr.clear_netconf_counters()
        self.standby_asr.clear_netconf_counters()

        self.verify_asrs = asr.VerifyASRStandby(active=self.active_asr,
                                                standby=self.standby_asr)

        super(TestASRStandBy, self).setUp()
        self.active_asr.record_cfg_size('post-setup')
        self.standby_asr.record_cfg_size('post-setup')

    def check_log_errors(self):
        time.sleep(60)
        self.log_inspector.record_errors('test-end')
        self.log_inspector.compare_logs('baseline', 'test-end')

    def check_cfg_size(self):
        max_time = 120
        sleep_for = 10
        current_time = time.time()
        timeout = current_time + max_time
        previous_id = "post-test-{0}".format(current_time)
        while current_time < timeout:
            id = "post-test-{0}".format(current_time)
            current_active_cfg_size = int(self.active_asr.record_cfg_size(id))
            current_standby_cfg_size = int(self.standby_asr.record_cfg_size(
                id))

            previous_active_cfg_size = int(self.active_asr.get_cfg_size(
                previous_id))
            previous_standby_cfg_size = int(self.standby_asr.get_cfg_size(id))
            previous_id= id

            if ((current_active_cfg_size == previous_active_cfg_size) and
                    (current_standby_cfg_size == previous_standby_cfg_size)):
                break

            time.sleep(sleep_for)
            current_time = time.time()

        self.active_asr.record_cfg_size('test-end')
        self.standby_asr.record_cfg_size('test-end')
        self.verify_asrs.eot_cfg_sizes()

    def cleanup_asr_leftovers(self):
        # Sometimes nat pool definitions are not properly removed after a
        # test run. This function checks for this and, if there are such
        # leftovers, removes them. Since the cfg agent makes updates to the
        # running config of the ASRs asyncronously to the neutron server, you
        # should ensure this function is not called prematurely. In such cases,
        # apparently stale nat pool definitions are not leftovers, but lines
        # that the cfg agent is about to delete. We avoid the problem of
        # premature invocation of this function by waiting some time before
        # starting the cleanup.
        time.sleep(30)
        routers = self.routers_client.list_routers()['routers']
        r_ids = set(router['id'][:6] for router in routers)
        for asr_device in [self.active_asr, self.standby_asr]:
            asr_device.send_command('')
            size_string = asr_device.send_command("show run | inc ip nat pool")
            lines = size_string.split('\r\n')
            r_id_re = re.compile(
                r'ip nat pool nrouter-([a-f0-9A-F]{6})_nat_pool')
            remove_cmds = []
            for line in lines:
                r_id_match = r_id_re.match(line)
                if r_id_match:
                    r_id = r_id_match.group(1)
                    if r_id not in r_ids:
                        # must be a stale nat pool definition to clean up
                        remove_cmds += ['no ' + line]
            if remove_cmds:
                asr_device.send_command('configure terminal')
                for cmd in remove_cmds:
                    asr_device.send_command(cmd)
                asr_device.send_command('exit')

    def reboot_asr(self, asr, wait=False):
        asr.reboot(wait=wait)
        asr.wait_for_transactions(target=10)
        if asr == self.active_asr:
            self.active_asr = self.standby_asr
            self.standby_asr = asr

    def nx_link(self, asr, state):
        asr.interface_state(state)

    def restart_neutron(self, expect_failure=False):
        """
        Restart Neutron service on controller and verify that there is a
        neutron pid
        """

        restart_cmd = r'screen -S stack  -p q-svc -X stuff "^C^[[A\r\n"'
        neutron_pid = self.get_process_pid('neutron-server')
        time.sleep(60)
        os.system(restart_cmd)
        time.sleep(60)
        new_neutron_pid = self.get_process_pid('neutron-server')
        if expect_failure is True:
            self.assertIsNone(new_neutron_pid)
        else:
            self.assertIsNotNone(new_neutron_pid)
            self.assertIsNot(int(neutron_pid), int(new_neutron_pid))
        LOG.info("Neutron-server PID: {0}".format(new_neutron_pid))

    def get_process_cmd(self, pid):
        ps = subprocess.Popen(['cat', '-v', '/proc/{0}/cmdline'.format(pid)],
                              stdout=subprocess.PIPE)
        out, err = ps.communicate()
        cmd_args = out.split('^@')
        cmdline = " ".join(cmd_args)
        return cmdline

    def get_process_pid(self, process_name):
        ps = subprocess.Popen(['ps', '-ef'], stdout=subprocess.PIPE)
        out, err = ps.communicate()
        for line in out.splitlines():
            if process_name in line:
                pid = int(line.split()[1])
                return pid

        return None

    def terminate_process(self, process_name):
        pid = self.get_process_pid(process_name)
        self.assertIsNotNone(pid)
        os.kill(pid, signal.SIGKILL)
        pid = self.get_process_pid(process_name)
        self.assertIsNone(pid)

    def bounce_interface(self, asr):
        asr.interface_state('down')
        time.sleep(30)
        asr.interface_state('up')

    def verify_network_element_ready(self):
        super(TestASRStandBy, self).verify_network_element_ready()
        # clear counters on the ASR interfaces
        for segment_id in self.segmentation_ids:
            for asr in [self.active_asr, self.standby_asr]:
                asr.clear_traffic_counters(segment_id)

    def verify_network_element_traffic_flows(self):
        super(TestASRStandBy, self).verify_network_element_traffic_flows()

    def verify_asrs_insync(self):
        self.verify_asrs.check_active_asr(self.segmentation_ids[0])
        self.verify_asrs.netconf_counters()
        self.verify_asrs.vrfs(
                self.routers_client.list_routers()['routers'],
                self.tenant_id,
                region_id=CONF.network.region1_id)

        #pdb.set_trace()
        # TODO(bobmel): Re-enable this?
        #self.verify_asrs.nat_pool(self.routers_client,
        #                          self.tenant_id,
        #                          region_id=CONF.network.region1_id)
        #self.verify_asrs.nat_translations(self.floating_ip_tuples)
        self.verify_asrs.acls(self.subnets_client,
                              self.ports_client,
                              self.networks_client,
                              self.tenant_id,
                              self.segmentation_ids,
                              region_id=CONF.network.region1_id)
        self.verify_asrs.ext_subintf(self.subnets_client,
                                     self.routers_client,
                                     self.networks_client,
                                     self.routers,
                                     self.tenant_id,
                                     region_id=CONF.network.region1_id)
        self.verify_asrs.standby_state(self.segmentation_ids)

    def verify_asrs_insync_swo(self):
        self.verify_asrs.check_active_asr(self.segmentation_ids[0])
        self.verify_asrs.netconf_counters()
        rtrs = self.verify_asrs.get_rtrs(self.routers_client, self.tenant_id)

        self.verify_asrs.vrf(rtrs['primary'],
                             'ACTIVE',
                             region_id=CONF.network.region1_id)
        self.verify_asrs.vrf(rtrs['backup'],
                             'STANDBY',
                             region_id=CONF.network.region1_id)

        self.verify_asrs.nat_pool(self.routers_client,
                                  self.tenant_id,
                                  region_id=CONF.network.region1_id)
        self.verify_asrs.nat_translations(self.floating_ip_tuples)
        self.verify_asrs.acls(self.subnets_client,
                              self.ports_client,
                              self.networks_client,
                              self.tenant_id,
                              self.segmentation_ids,
                              region_id=CONF.network.region1_id)
        self.verify_asrs.ext_subintf(self.subnets_client,
                                     self.routers_client,
                                     self.networks_client,
                                     self.routers,
                                     self.tenant_id,
                                     region_id=CONF.network.region1_id)
        self.verify_asrs.standby_state(self.segmentation_ids)


    def verify_asrs_de918(self, rtrs):
        self.verify_asrs.check_active_asr(self.segmentation_ids[0])
        self.verify_asrs.netconf_counters()

        self.verify_asrs.vrf(rtrs['primary'],
                             'ACTIVE',
                             region_id=CONF.network.region1_id)
        self.verify_asrs.vrf(rtrs['backup'],
                             'STANDBY',
                             region_id=CONF.network.region1_id)

        self.verify_asrs.standby_state(self.segmentation_ids)

    def bounce_rtr_gateway(self):
        rtr = self.routers[0]
        external_gw_info = rtr['external_gateway_info']
        # Verify sub interface/NAT/Pool/ACLs configured on ASRs
        self.verify_asrs.nat_pool(self.routers_client,
                                  self.tenant_id,
                                  region_id=CONF.network.region1_id)
        self.verify_asrs.acls(self.subnets_client,
                              self.ports_client,
                              self.networks_client,
                              self.tenant_id,
                              self.segmentation_ids,
                              region_id=CONF.network.region1_id)
        netconf_counters = self.active_asr.get_netconf_counters()

        # Unset the gateway
        kwargs = {'external_gateway_info': None}
        router = self.routers_client.update_router(rtr['id'],
                                                   **kwargs)['router']
        min_transaction = (len(self.segmentation_ids) +
                           int(netconf_counters[
                                   'netconf-counters.transactions-total']))
        self.active_asr.wait_for_transactions(min_transaction)
        time.sleep(30)
        netconf_counters = self.active_asr.get_netconf_counters()
        self.verify_asrs.netconf_counters()
        try:
            self.verify_asrs.nat_pool(self.routers_client,
                                      self.tenant_id,
                                      region_id=CONF.network.region1_id)
            msg = "NAT Pool still configured after GW cleared"
            raise asr_exceptions.ASRTestException(msg)
        except asr_exceptions.NATPoolNotConfiguredException:
            pass

        time.sleep(90)
        # Reset the gateway
        # TODO(bobmel): Clean this up
        kwargs = {'external_gateway_info': dict(
            network_id=CONF.network.public_network_id)}
        router = self.routers_client.update_router(rtr['id'],
                                                   **kwargs)['router']
        min_transaction = (len(self.segmentation_ids) +
                           int(netconf_counters[
                                   'netconf-counters.transactions-total']))
        self.active_asr.wait_for_transactions(min_transaction)
        time.sleep(30)
        self.verify_asrs.nat_pool(self.routers_client,
                                  self.tenant_id,
                                  region_id=CONF.network.region1_id)
        self.verify_asrs.netconf_counters()

    def verify_nc_hosted_router_names(self):
        host_devices = self.neutron_client.cisco_hosting_device_list()

        i = 1
        for host_id in host_devices.keys():
            name = "ASR{0}".format(i)
            i += 1
            self.neutron_client.cisco_hosting_device_update(name=name,
                                                            hd_id=host_id)

        updated_host_devices = self.neutron_client.cisco_hosting_device_list()
        i = 1
        while i < 3:
            result = False
            expected_name = "ASR{0}".format(i)
            for host_id in updated_host_devices.keys():
                if expected_name == updated_host_devices[host_id]['name']:
                    result = True
                    break
            self.assertIs(result, True)
            i += 1

        for host_id in host_devices.keys():
            host_name = host_devices[host_id]['name']
            if host_name is None or host_name is '':
                host_name = "\'\'"
            self.neutron_client.cisco_hosting_device_update(name=host_name,
                                                            hd_id=host_id)

    @testtools.skipUnless(CONF.cisco.asr1,
                          'ASR1 switch not specified in tempest.conf')
    @testtools.skipUnless(CONF.cisco.asr2,
                          'ASR2 switch not specified in tempest.conf')
    @test.attr(type='asr-functional')
    @test.attr(type='asr-regress')
    def test_asr_basic(self):
        #pdb.set_trace()
        self.verify_network_create_events()
        self.create_floating_ips()
        self.verify_asrs_insync()
        self.verify_vm_connectivity()
        self.verify_network_element_ready()
        self.verify_vm_to_vm_connectivity()
        self.verify_network_element_traffic_flows()

    @testtools.skipUnless(CONF.cisco.asr1,
                          'ASR1 switch not specified in tempest.conf')
    @testtools.skipUnless(CONF.cisco.asr2,
                          'ASR2 switch not specified in tempest.conf')
    @test.attr(type='asr-functional')
    @test.attr(type='asr-regress')
    def test_clear_rtr_gateway(self):
        self.verify_network_create_events()
        self.verify_asrs.check_active_asr(self.segmentation_ids[0])
        self.bounce_rtr_gateway()
        self.create_floating_ips()
        self.verify_asrs_insync()
        self.verify_vm_connectivity()
        self.verify_network_element_ready()
        self.verify_vm_to_vm_connectivity()
        self.verify_network_element_traffic_flows()

    @testtools.skipUnless(CONF.cisco.asr1,
                          'ASR1 switch not specified in tempest.conf')
    @testtools.skipUnless(CONF.cisco.asr2,
                          'ASR2 switch not specified in tempest.conf')
    @test.attr(type='asr-regress')
    def test_nc_hosted_router_names(self):
        self.verify_network_create_events()
        self.create_floating_ips()
        self.verify_asrs_insync()
        self.verify_nc_hosted_router_names()

    @testtools.skipUnless(CONF.cisco.asr1,
                          'ASR1 switch not specified in tempest.conf')
    @testtools.skipUnless(CONF.cisco.asr2,
                          'ASR2 switch not specified in tempest.conf')
    @test.attr(type='asr-regress')
    def test_rtr_gw_set(self):
        self.verify_network_create_events()
        self.delete_vms()
        kwargs = {'external_gateway_info': None }
        router = self.routers_client.update_router(self.routers[0]['id'],
                                                   **kwargs)['router']

        # 1 Create a router.  Note that the VRF is configured at the ASRs.
        rtr = self.routers_client.create_router(
            name=data_utils.rand_name('rtr-de918'),
            tenant_id=self.tenant_id)['router']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.routers_client.delete_router, rtr['id'])
        rtrs = self.verify_asrs.get_backup_rtr(rtr,
                                               self.routers_client,
                                               self.tenant_id)

        # 2 Create the tenant network/subnet.
        net = self._create_network(namestart="net-de918")
        subnet = self.create_subnet(net)

        # 3 Add the router interface for the tenant subnet.
        # TODO(bobmel): Clean this up
        #subnet.add_to_router(rtr['id'])
        self.routers_client.add_router_interface(rtr['id'],
                                                 subnet_id=subnet['id'])

        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.routers_client.remove_router_interface,
                        rtr['id'], subnet_id=subnet['id'])
        time.sleep(60)

        # 4 Note that only the sub-interface is configured at the ASRs;
        # the ACL and the inside source list NAT entry are missing.
        old_segmentation_ids = self.segmentation_ids
        self.segmentation_ids = []
        self.segmentation_ids.append(net['provider:segmentation_id'])
        self.verify_asrs_de918(rtrs)
        # 5 Set the router gateway.
        # TODO(bobmel): Clean this up
        #rtr.set_gateway(CONF.network.public_network_id)
        kwargs = {'external_gateway_info': dict(
            network_id=CONF.network.public_network_id)}
        router = self.routers_client.update_router(rtr['id'],
                                                   **kwargs)['router']
        time.sleep(60)

        # 6 The ACL and the inside source list NAT entry are still not
        # configured at the ASRs
        self.verify_asrs_de918(rtrs)
        self.segmentation_ids = old_segmentation_ids

    @testtools.skipUnless(CONF.cisco.asr1,
                          'ASR1 switch not specified in tempest.conf')
    @testtools.skipUnless(CONF.cisco.asr2,
                          'ASR2 switch not specified in tempest.conf')
    @test.attr(type='asr-regress')
    def test_total_floating_ips(self):
        self.verify_network_create_events()
        self.verify_asrs.check_active_asr(self.segmentation_ids[0])
        self.create_floating_ips()
        self.verify_asrs_insync()
        rtrs = self.verify_asrs.get_rtrs(self.routers_client, self.tenant_id)
        LOG.info("RTRS: {0}".format(rtrs))
        time.sleep(90)
        state_reports = self.log_inspector.get_state_reports(self.start_time)
        LOG.info("State Reports: {0}".format(state_reports))
        last_full_report = {}
        for k, v in state_reports.items():
            state_report = state_reports[k]
            if 'configurations' in state_report:
                last_full_report = state_report

        expected_fips = len(self.floating_ip_tuples)
        LOG.info("Expected FIPS {0}".format(expected_fips))
        actual_fips = int(
            last_full_report['configurations']['total floating_ips'])
        self.assertEqual(expected_fips * 2, actual_fips)
        restart_time = datetime.datetime.now()
        self.restart_neutron()
        time.sleep(60)
        self.verify_asrs_insync()
        time.sleep(90)
        state_reports = self.log_inspector.get_state_reports(restart_time)
        LOG.info("State Reports: {0}".format(state_reports))
        for k, v in state_reports.items():
            state_report = state_reports[k]
            if 'configurations' in state_report:
                last_full_report = state_report
        LOG.info("Expected FIPS {0}".format(expected_fips))
        actual_fips = int(
            last_full_report['configurations']['total floating_ips'])
        self.assertEqual(expected_fips * 2, actual_fips)

    @testtools.skipUnless(CONF.cisco.asr1,
                          'ASR1 switch not specified in tempest.conf')
    @testtools.skipUnless(CONF.cisco.asr2,
                          'ASR2 switch not specified in tempest.conf')
    @test.attr(type='asr-hsrp')
    @test.attr(type='asr-regress')
    def test_active_hsrp_failure(self):
        self.verify_network_create_events()
        self.create_floating_ips()
        self.verify_asrs_insync()
        self.verify_vm_connectivity()
        self.verify_network_element_ready()
        self.verify_vm_to_vm_connectivity()
        self.verify_network_element_traffic_flows()
        netconf_counters = self.active_asr.get_netconf_counters()
        target_counters = int(
            int(netconf_counters['netconf-counters.transactions-total']) * .80)
        self.reboot_asr(self.active_asr, wait=True)
        self.standby_asr.wait_for_transactions(target=target_counters)
        self.verify_vm_connectivity()
        # reconnect to standby asr to avoid ssh connection timeout
        self.standby_asr.conn.relogin()
        self.verify_network_element_ready()
        self.verify_vm_to_vm_connectivity()
        self.verify_network_element_traffic_flows()
        # TODO(bobmel): Re-enable this?
        #self.verify_asrs_insync_swo()
        # reconnect to both asrs to avoid ssh connection timeout
        self.active_asr.conn.relogin()
        self.standby_asr.conn.relogin()

    @testtools.skipUnless(CONF.cisco.asr1,
                          'ASR1 switch not specified in tempest.conf')
    @testtools.skipUnless(CONF.cisco.asr2,
                          'ASR2 switch not specified in tempest.conf')
    @test.attr(type='asr-hsrp')
    def test_standby_hsrp_failure(self):
        self.verify_network_create_events()
        self.create_floating_ips()
        self.verify_asrs_insync()
        self.verify_vm_connectivity()
        self.verify_network_element_ready()
        self.verify_vm_to_vm_connectivity()
        self.verify_network_element_traffic_flows()
        self.reboot_asr(self.standby_asr, wait=True)
        # reconnect to standby asr to avoid ssh connection timeout
        self.active_asr.conn.relogin()
        self.bounce_interface(self.active_asr)
        time.sleep(120)
        self.verify_vm_connectivity()
        # reconnect to standby asr to avoid ssh connection timeout
        self.active_asr.conn.relogin()
        self.verify_network_element_ready()
        self.verify_vm_to_vm_connectivity()
        #import pdb; pdb.set_trace()
        self.verify_network_element_traffic_flows()
        #import pdb; pdb.set_trace()
        # TODO(bobmel): Re-enable this?
        #self.verify_asrs_insync()
        # reconnect to both asrs to avoid ssh connection timeout
        self.active_asr.conn.relogin()
        self.standby_asr.conn.relogin()

    @testtools.skipUnless(CONF.cisco.asr1,
                          'ASR1 switch not specified in tempest.conf')
    @testtools.skipUnless(CONF.cisco.asr2,
                          'ASR2 switch not specified in tempest.conf')
    @test.attr(type='asr-hsrp')
    def test_link_down_nx_asr(self):
        self.verify_network_create_events()
        self.create_floating_ips()
        self.verify_asrs_insync()
        self.verify_vm_connectivity()
        self.verify_network_element_ready()
        self.verify_vm_to_vm_connectivity()
        self.verify_network_element_traffic_flows()
        self.nx_link(self.active_asr, 'down')
        self.verify_vm_connectivity()
        self.verify_network_element_ready()
        self.verify_vm_to_vm_connectivity()
        self.verify_network_element_traffic_flows()
        self.nx_link(self.active_asr, 'up')
        self.active_asr.wait_for_standby(self.segmentation_ids)
        self.verify_vm_connectivity()
        self.verify_network_element_ready()
        self.verify_vm_to_vm_connectivity()
        self.verify_network_element_traffic_flows()
        # TODO(bobmel): Re-enable this?
        #self.verify_asrs_insync_swo()
