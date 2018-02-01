
# Copyright 2016 Cisco Systems
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

import collections
import datetime
import difflib
import time
import tempest.thirdparty.cir.lib.asr as asr
import tempest.thirdparty.cir.lib.neutron_client as nc

from tempest import clients
from tempest import config as tempest_conf
from tempest.thirdparty.cir.ml2 import test_asr_men_base
from tempest.scenario import test_network_multi_node
from tempest.lib.common.cred_provider import TestResources
from tempest.thirdparty.cir.lib.device.LogInspector import LogInspector
from tempest.thirdparty.cir.lib.cfg_agent_client import CfgAgentClient
from oslo_log import log as logging

CONF = tempest_conf.CONF

LOG = logging.getLogger(__name__)
LOG.debug("")

Floating_IP_tuple = collections.namedtuple('Floating_IP_tuple',
                                           ['floating_ip', 'server'])


class TestASRMenNegative(test_asr_men_base.TestASRMenBase):

    # For setting up cfg agent client
    default_params = {
        'disable_ssl_certificate_validation':
            CONF.identity.disable_ssl_certificate_validation,
        'ca_certs': CONF.identity.ca_certificates_file,
        'trace_requests': CONF.debug.trace_requests
    }

    def setUp(self):
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
        self.number_routers_per_tenant = CONF.scenario.num_routers_per_tenant
        self.network_vms = {}
        self.routers = []
        self.ping_fip_only = True

        # Classes that inherit this class can redefine packet size/count
        # based on their own needs or accept the default in the CONF
        if not hasattr(self, 'test_packet_sizes'):
            self.test_packet_sizes = map(int, CONF.scenario.test_packet_sizes)

        if not hasattr(self, 'test_packet_count'):
            self.test_packet_count = CONF.scenario.test_packet_count

        if not hasattr(self, 'max_instances_per_tenant'):
            self.max_instances_per_tenant = (
                CONF.scenario.max_instances_per_tenant)

        self.log_inspector = LogInspector()

        self.neutron_client = \
            nc.NeutronClient('NeutronClient',
                             ip=CONF.network.controller_ip,
                             user=CONF.network.controller_user,
                             pw=CONF.network.controller_pw,
                             resource_file=CONF.network.controller_rc_file)

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

        self.verify_asrs = asr.VerifyASRStandby(active=self.asr1,
                                                standby=self.asr2)

        self.asr_pair = [self.asr1, self.asr2]
        self.verify_asr_online()
        self.asr1.clear_netconf_counters()
        self.asr2.clear_netconf_counters()
        self.addCleanup(self.check_log_errors)
        self.addCleanup(self.close_console)
        self.addCleanup(self.verify_asr_online)

        # Allows the ability to place VMs on specific compute nodes
        self.external_nets = ['public', 'ext-net2', 'ext-net3']
        self.check_extnernal_nets()
        self.setup_projects()
        self.setup_users()
        self.create_project_roles()
        self.assign_users_role()
        self.create_security_groups()

        super(test_network_multi_node.TestNetworkMultiNode, self).setUp()

    def close_console(self):
        self.asr1.console = None
        self.asr2.console = None

    def check_log_errors(self):
        self.log_inspector.record_errors('test-end')
        self.log_inspector.compare_logs('baseline', 'test-end')

    def verify_asr_online(self):
        for router in self.asr_pair:
            ping_result = router.ping_ip_address(router.ip,
                                                 should_succeed=True,
                                                 ping_timeout=10)
            if ping_result is False:
                self.bounce_mgmt_link(router, 'up')

        for router in self.asr_pair:
            self.poll_ping(router, ping_success=True)

    # Verify the hosting device state from the cfg-agent log.
    def verify_hosting_device_state(self, log_inspector, id, state,
                                    max_time=300, sleep_for=60):
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
            current_state = self.get_hosting_device_state(log_inspector,
                                                          current_datetime,
                                                          hd_id, sleep_for)

            if current_state != hd_state:
                LOG.info("Waiting for hosting device {0} to reach {1} "
                         "state".format(hd_id, hd_state))
                current_time = time.time()

            else:
                LOG.info("Hosting device {0} reaches {1} "
                         "state".format(hd_id, hd_state))
                return True

        if current_time >= timeout:
            msg = "Hosting-device {0} Fail to reach the expected " \
                  "state {1}".format(hd_id, hd_state)
            self.assertEqual(hd_state, current_state, msg)

    # Get the hosting device state (ACTIVE/NOT RESPONDING/DEAD)
    # from the cfg-agent log.
    def get_hosting_device_state(self, log_inspector, start_time, id,
                                 sleep_for=60):
        hd_state = None
        log_inspector = log_inspector
        time.sleep(sleep_for)
        status_report = log_inspector.get_state_reports(start_time)

        for key in status_report.keys():
            if "configurations" in status_report[key]:
                if status_report[key]['configurations']['monitored_hosting_devices'][0]['host id'] == id:
                    hd_state = \
                        status_report[key]['configurations']['monitored_hosting_devices'][0]['hd_state']
                elif status_report[key]['configurations']['monitored_hosting_devices'][1]['host id'] == id:
                    hd_state = \
                        status_report[key]['configurations']['monitored_hosting_devices'][1]['hd_state']

        return hd_state

    def get_hosting_device_id_list(self, neutron_client):
        the_nc = neutron_client
        hosting_devices = the_nc.cisco_hosting_device_list()
        hd_id_list = []
        for key in hosting_devices.keys():
            hd_id_list.append(key)

        return hd_id_list

    # Given the IP, find its hosting device ID.
    def get_hosting_device_id(self, neutron_client, id_list, ip):
        the_nc = neutron_client
        for id in id_list:
            hd_info = the_nc.cisco_hosting_device_show(id)
            if hd_info['management_ip_address'] == ip:
                hd_id = hd_info['id']

        return hd_id

    # Given the IP, find its hosting device ID.
    def get_hosting_device_id(self, neutron_client, id_list, ip):
        the_nc = neutron_client
        for id in id_list:
            hd_info = the_nc.cisco_hosting_device_show(id)
            if hd_info['management_ip_address'] == ip:
                hd_id = hd_info['id']

        return hd_id

    # Disable/enable the ASR management interface.
    def bounce_mgmt_link(self, asr, state):
        LOG.info("Set ASR {0} management interface to {1}".format(asr.name,
                                                                  state.upper()))
        asr.mgmt_intf_state(state=state)

    def test_tc1007(self):
        #
        # Create routers with different external networks while hosting
        # device in "Not Responding" state.
        #
        # 1. Create 2 different tenants, X & Y.
        # 2. In tenant X, create external network A with a subnet and
        #    internal network B with a subnet.
        # 3. In tenant Y, create external network C with a subnet and
        #    internal network D with a subnet.
        # 4. At both ASRs, disable the management interface and wait till
        #    both hosting devices transition to "Not Responding" state.
        # 5. In tenant X, create router R1; set gateway to be external
        #    network A and add router interface for internal network B.
        # 6. Verify Global and Logical Global routers are created.
        # 7. At both ASRs, verify no config update.
        # 8. In tenant X, launch VM1 on network B.
        # 9. Create floating IP on external network A and assign to VM1.
        # 10. Verify VM1's floating IP is not accessible from the outside
        #     world.
        # 11. In tenant Y, create router R2; set gateway to be external
        #     network C and add router interface for internal network D.
        # 12. At both ASRs, verify no config update.
        # 13. In tenant Y, launch VM2 on network D.
        # 14. Create floating IP on external network C and assign to VM2.
        # 15. Verify VM2's floating IP is not accessible from the outside
        #     world.
        # 16. Enable the management interface at both ASRs.
        # 17. Wait till both hosting devices transition back to "Active" state.
        # 18. Verify config update at both ASRs where the VRFs,
        #     internal/external sub-interfaces, IP NAT pools and static NATs
        #     are added.
        # 19. Verify both VM1 and VM2's floating IP is accessible from the
        #     outside world.
        # 20. Verify from VM1, it can ping VM2's floating IP and vice versa.
        self.verify_global_logical_rtrs(state='DELETED')
        test_project1 = self.projects[0]
        test_project2 = self.projects[1]

        user, project = self.users[0]
        creds = self.identity_utils.get_credentials(user,
                                                    project,
                                                    'cisco123')
        my_creds = TestResources(creds)
        client_mgr1 = clients.Manager(my_creds)

        self.orig_admin_mgr = self.admin_manager
        self.admin_manager = client_mgr1
        self.manager = client_mgr1
        self.setup_clients()

        user, project = self.users[1]
        creds = self.identity_utils.get_credentials(user,
                                                    project,
                                                    'cisco123')
        my_creds = TestResources(creds)
        client_mgr2 = clients.Manager(my_creds)

        net_a = self._get_network_by_name(self.external_nets[0])
        net_c = self._get_network_by_name(self.external_nets[1])

        self.bounce_mgmt_link(self.verify_asrs.active, 'down')
        self.bounce_mgmt_link(self.verify_asrs.standby, 'down')
        active_hd_id = self.get_hosting_device_id(
            self.neutron_client,
            self.get_hosting_device_id_list(self.neutron_client),
            self.verify_asrs.active.ip)

        standby_hd_id = self.get_hosting_device_id(
            self.neutron_client,
            self.get_hosting_device_id_list(self.neutron_client),
            self.verify_asrs.standby.ip)

        self.verify_hosting_device_state(self.log_inspector,
                                         active_hd_id,
                                         'NOT RESPONDING',
                                         sleep_for=10)

        self.verify_hosting_device_state(self.log_inspector,
                                         standby_hd_id,
                                         'NOT RESPONDING',
                                         sleep_for=10)

        r1 = self._create_router(client_mgr1.network_client,
                                 test_project1['id'])
        r1.set_gateway(net_a['id'])
        time.sleep(10)
        self.verify_global_logical_rtrs(state='ACTIVE')

        net_b, subnet_b, r1 = \
            self.add_network(tenant_id=test_project1['id'], router=r1)

        time.sleep(10)
        vm_1, fip_1 = self.create_vm('vm1',
                                     test_project1,
                                     client_mgr1,
                                     net_b,
                                     net_a)

        self.ping_vm(fip_1, should_succeed=False)

        r2 = self._create_router(client_mgr2.network_client,
                                 test_project2['id'])
        r2.set_gateway(net_c['id'])

        net_e, subnet_e, r2 = \
            self.add_network(tenant_id=test_project2['id'], router=r2)

        time.sleep(10)
        vm_2, fip_2 = self.create_vm('vm2',
                                     test_project2,
                                     client_mgr2,
                                     net_e,
                                     net_c)

        time.sleep(30)
        self.ping_vm(fip_1, should_succeed=False)
        self.ping_vm(fip_2, should_succeed=False)

        self.bounce_mgmt_link(self.verify_asrs.active, 'up')
        self.bounce_mgmt_link(self.verify_asrs.standby, 'up')
        self.poll_ping(self.verify_asrs.active, ping_success=True)
        self.poll_ping(self.verify_asrs.standby, ping_success=True)
        self.verify_hosting_device_state(self.log_inspector,
                                         active_hd_id,
                                         'ACTIVE',
                                         sleep_for=10)

        self.verify_hosting_device_state(self.log_inspector,
                                         standby_hd_id,
                                         'ACTIVE',
                                         sleep_for=10)

        time.sleep(60)
        self.verify_global_logical_rtrs(state='ACTIVE')

        self.ping_vm(fip_1)
        self.ping_vm(fip_2)
        self.verify_vm_connectivity()
        self.verify_vm_to_vm_connectivity()

        client_mgr1.servers_client.delete_server(vm_1['server']['id'])
        time.sleep(5)
        client_mgr1.network_client.remove_router_interface_with_subnet_id(
            r1['id'], subnet_b['id'])
        client_mgr1.network_client.delete_router(r1['id'])
        self.verify_global_logical_rtrs(state='ACTIVE')

        self.ping_vm(fip_1, should_succeed=False)
        self.ping_vm(fip_2)

        client_mgr2.servers_client.delete_server(vm_2['server']['id'])
        time.sleep(5)
        client_mgr2.network_client.remove_router_interface_with_subnet_id(
            r2['id'], subnet_e['id'])
        client_mgr2.network_client.delete_router(r2['id'])
        time.sleep(60)
        self.verify_global_logical_rtrs(state='DELETED')

        self.ping_vm(fip_1, should_succeed=False)
        self.ping_vm(fip_2, should_succeed=False)

    def test_tc1008(self):
        #
        # Delete routers with different external networks while hosting device
        # in "Not Responding" state.
        #
        # 1. Create 2 different tenants, X & Y.
        # 2. In tenant X, create external network A with a subnet and internal
        #    network B with a subnet.
        # 3. In tenant Y, create external network C with a subnet and internal
        #    network D with a subnet.
        # 4. In tenant X, create router R1; set gateway to be external
        #    network A and add router interface for internal network B.
        # 5. Verify Global and Logical Global routers are created.
        # 6. At both ASRs, verify a VLAN subinterface is configured for
        #    external connectivity in the router R1 VRF.
        # 7. In tenant X, launch VM1 on network B.
        # 8. Create floating IP on external network A and assign to VM1.
        # 9. Verify VM1's floating IP is accessible from the outside world.
        # 10. In tenant Y, create router R2; set gateway to be external
        #     network C and add router interface for internal network D.
        # 11. At both ASRs, verify a second VLAN subinterface is configured
        #     for external connectivity in the router R2 VRF.
        # 12. In tenant Y, launch VM2 on network D.
        # 13. Create floating IP on external network C and assign to VM2.
        # 14. Verify VM2's floating IP is accessible from the outside world.
        # 15. Verify from VM1, it can ping VM2's floating IP and vice versa.
        # 16. At both ASRs, disable the management interface and wait till
        #     both hosting devices transition to "Not Responding" state.
        # 17. In tenant X, delete VM1, remove router R1 interface to
        #     subnet B,and delete router R1.
        # 18. Verify no config update at both ASRs.
        # 19. In tenant Y, delete VM2, remove router R2 interface to
        #     subnet D,and delete router R2.
        # 20. Verify no config update at both ASRs.
        # 21. Verify both the Global and Logical Global routers are deleted.
        # 22. Enable the management interface at both ASRs.
        # 23. Wait till both hosting devices transition back to "Active" state.
        # 24. Verify both ASRs' config is updated where the VRFs,
        #     internal/external sub-interfaces, IP NAT pools and static NATs
        #     are deleted.
        self.verify_global_logical_rtrs(state='DELETED')
        test_project1 = self.projects[0]
        test_project2 = self.projects[1]

        user, project = self.users[0]
        creds = self.identity_utils.get_credentials(user,
                                                    project,
                                                    'cisco123')
        my_creds = TestResources(creds)
        client_mgr1 = clients.Manager(my_creds)

        self.orig_admin_mgr = self.admin_manager
        self.admin_manager = client_mgr1
        self.manager = client_mgr1
        self.setup_clients()

        user, project = self.users[1]
        creds = self.identity_utils.get_credentials(user,
                                                    project,
                                                    'cisco123')
        my_creds = TestResources(creds)
        client_mgr2 = clients.Manager(my_creds)

        net_a = self._get_network_by_name(self.external_nets[0])
        net_c = self._get_network_by_name(self.external_nets[1])

        active_hd_id = self.get_hosting_device_id(
            self.neutron_client,
            self.get_hosting_device_id_list(self.neutron_client),
            self.verify_asrs.active.ip)

        standby_hd_id = self.get_hosting_device_id(
            self.neutron_client,
            self.get_hosting_device_id_list(self.neutron_client),
            self.verify_asrs.standby.ip)

        pretest_active_asr_cfg = \
            self.neutron_client.cisco_hosting_device_get_config(active_hd_id)

        pretest_standby_asr_cfg = \
            self.neutron_client.cisco_hosting_device_get_config(standby_hd_id)

        r1 = self._create_router(client_mgr1.network_client,
                                 test_project1['id'])
        r1.set_gateway(net_a['id'])

        net_b, subnet_b, r1 = \
            self.add_network(tenant_id=test_project1['id'], router=r1)

        time.sleep(30)
        self.verify_global_logical_rtrs(state='ACTIVE')

        vm_1, fip_1 = self.create_vm('vm1',
                                     test_project1,
                                     client_mgr1,
                                     net_b,
                                     net_a)
        time.sleep(10)
        self.ping_vm(fip_1)

        r2 = self._create_router(client_mgr2.network_client,
                                 test_project2['id'])
        r2.set_gateway(net_c['id'])

        net_e, subnet_e, r2 = self.add_network(tenant_id=test_project2['id'],
                                               router=r2)

        vm_2, fip_2 = self.create_vm('vm2',
                                     test_project2,
                                     client_mgr2,
                                     net_e,
                                     net_c)

        time.sleep(30)
        self.ping_vm(fip_2)
        self.verify_vm_connectivity()
        self.verify_vm_to_vm_connectivity()

        self.bounce_mgmt_link(self.verify_asrs.active, 'down')
        self.bounce_mgmt_link(self.verify_asrs.standby, 'down')
        active_hd_id = self.get_hosting_device_id(
            self.neutron_client,
            self.get_hosting_device_id_list(self.neutron_client),
            self.verify_asrs.active.ip)

        standby_hd_id = self.get_hosting_device_id(
            self.neutron_client,
            self.get_hosting_device_id_list(self.neutron_client),
            self.verify_asrs.standby.ip)

        self.verify_hosting_device_state(self.log_inspector,
                                         active_hd_id,
                                         'NOT RESPONDING',
                                         sleep_for=10)

        self.verify_hosting_device_state(self.log_inspector,
                                         standby_hd_id,
                                         'NOT RESPONDING',
                                         sleep_for=10)

        self.verify_vm_connectivity()
        self.verify_vm_to_vm_connectivity()

        client_mgr1.servers_client.delete_server(vm_1['server']['id'])
        client_mgr2.servers_client.delete_server(vm_2['server']['id'])
        time.sleep(5)

        client_mgr1.network_client.remove_router_interface_with_subnet_id(
            r1['id'], subnet_b['id'])
        client_mgr1.network_client.delete_router(r1['id'])
        self.verify_global_logical_rtrs(state='ACTIVE')

        client_mgr2.network_client.remove_router_interface_with_subnet_id(
            r2['id'], subnet_e['id'])
        client_mgr2.network_client.delete_router(r2['id'])

        time.sleep(60)
        self.bounce_mgmt_link(self.verify_asrs.active, 'up')
        self.bounce_mgmt_link(self.verify_asrs.standby, 'up')
        self.poll_ping(self.verify_asrs.active, ping_success=True)
        self.poll_ping(self.verify_asrs.standby, ping_success=True)
        self.verify_hosting_device_state(self.log_inspector,
                                         active_hd_id,
                                         'ACTIVE',
                                         sleep_for=10)

        self.verify_hosting_device_state(self.log_inspector,
                                         standby_hd_id,
                                         'ACTIVE',
                                         sleep_for=10)

        time.sleep(60)
        self.verify_global_logical_rtrs(state='DELETED')

        self.ping_vm(fip_1, should_succeed=False)
        self.ping_vm(fip_2, should_succeed=False)

        posttest_active_asr_cfg = \
            self.neutron_client.cisco_hosting_device_get_config(active_hd_id)

        asr_cfg_diff = \
            difflib.unified_diff(
                sorted(self.tidyup_asr_config(pretest_active_asr_cfg)),
                sorted(self.tidyup_asr_config(posttest_active_asr_cfg)),
                n=0)

        my_diff = []
        for diff in asr_cfg_diff:
            my_diff = diff
        self.assertEmpty(my_diff, "ASR Config diff: " + "".join(my_diff))

        posttest_standby_asr_cfg = \
            self.neutron_client.cisco_hosting_device_get_config(standby_hd_id)

        asr_cfg_diff = \
            difflib.unified_diff(
                sorted(self.tidyup_asr_config(pretest_standby_asr_cfg)),
                sorted(self.tidyup_asr_config(posttest_standby_asr_cfg)),
                n=0)

        my_diff = []
        for diff in asr_cfg_diff:
            my_diff = diff
        self.assertEmpty(my_diff, "ASR Config diff: ".join(my_diff))

    def test_tc1011(self):
        #
        # Create routers with different external networks while ASR reboots
        #
        # 1. Create 10 routers, set gateway each for different external
        #    network, add router interface for the tenant network.
        # 2. Verify config is pushed down to both ASRs correctly.
        # 3. Reboot ASR-1.
        # 4. While ASR-1 is rebooting, create another 5 routers and set
        #    gateway each for different external network.
        # 5. Verify the new config update is pushed down to ASR-2 immediately.
        # 6. Wait till ASR-1 boots up and comes online.
        # 7. Verify the config is replayed in addition to the new update.
        self.verify_global_logical_rtrs(state='DELETED')
        test_project1 = self.projects[0]

        user, project = self.users[0]
        creds = self.identity_utils.get_credentials(user,
                                                    project,
                                                    'cisco123')
        my_creds = TestResources(creds)
        client_mgr = clients.Manager(my_creds)

        self.orig_admin_mgr = self.admin_manager
        self.admin_manager = client_mgr
        self.manager = client_mgr
        self.setup_clients()

        num_ext_nets = len(self.external_nets)

        t1011_routers = []
        t1011_vms = []
        for net_i in range(0, num_ext_nets - 1):
            net_name = self.external_nets[net_i]
            rtr = self._create_router(client_mgr.network_client,
                                      test_project1['id'])
            net = self._get_network_by_name(net_name)
            rtr.set_gateway(net['id'])
            project_net, subnet, rtr = \
                self.add_network(tenant_id=test_project1['id'], router=rtr)
            t1011_routers.append((rtr, subnet))
            time.sleep(10)
            vm, fip = self.create_vm('vm',
                                     test_project1,
                                     client_mgr,
                                     project_net,
                                     net)
            t1011_vms.append((vm, fip))

        time.sleep(60)
        self.verify_global_logical_rtrs(state='ACTIVE')
        for vm, fip in t1011_vms:
            self.ping_vm(fip)

        ##
        ## Reboot ASR
        ##
        self.verify_asrs.active.reboot(wait=False)
        time.sleep(60)

        net_name = self.external_nets[-1]
        rtr = self._create_router(client_mgr.network_client,
                                  test_project1['id'])
        net = self._get_network_by_name(net_name)
        rtr.set_gateway(net['id'])
        project_net, subnet, rtr = \
                self.add_network(tenant_id=test_project1['id'], router=rtr)
        t1011_routers.append((rtr, subnet))

        vm, fip = self.create_vm('vm',
                                 test_project1,
                                 client_mgr,
                                 project_net,
                                 net)
        t1011_vms.append((vm, fip))

        ## After ASR comes back
        time.sleep(120)
        self.ping_ip_address(self.verify_asrs.active.ip,
                             should_succeed=False,
                             ping_timeout=600)
        time.sleep(60)
        self.verify_asrs.active.connect()

        self.verify_asrs.active.wait_for_transactions(10, max_time=120)
        time.sleep(30)

        for vm, fip in t1011_vms:
            self.ping_vm(fip)

        for vm, fip in t1011_vms:
            client_mgr.servers_client.delete_server(vm['server']['id'])

        time.sleep(10)
        for rtr, subnet in t1011_routers:
            client_mgr.network_client.remove_router_interface_with_subnet_id(
                rtr['id'], subnet['id'])
            time.sleep(5)
            client_mgr.network_client.delete_router(rtr['id'])

        time.sleep(30)
        self.verify_global_logical_rtrs(state='DELETED')

    def test_tc1009(self):
        #
        # Create routers with different external networks while hosting
        # device in "Dead" state.
        #
        # 1. Create 2 different tenants, X & Y.
        # 2. In tenant X, create external network A with a subnet and
        #    internal network B with a subnet.
        # 3. In tenant Y, create external network C with a subnet and
        #    internal network D with a subnet.
        # 4. At both ASRs, disable the management interface and wait till
        #    both hosting devices transition to "Dead" state.
        # 5. In tenant X, create router R1; set gateway to be external
        #    network A and add router interface for internal network B.
        # 6. Verify Global and Logical Global routers are created.
        # 7. At both ASRs, verify no config update.
        # 8. In tenant X, launch VM1 on network B.
        # 9. Create floating IP on external network A and assign to VM1.
        # 10. Verify VM1's floating IP is not accessible from the
        #     outside world.
        # 11. In tenant Y, create router R2; set gateway to be external
        #     network C and add router interface for internal network D.
        # 12. At both ASRs, verify no config update.
        # 13. In tenant Y, launch VM2 on network D.
        # 14. Create floating IP on external network C and assign to VM2.
        # 15. Verify VM2's floating IP is not accessible from the outside
        #     world.
        # 16. Enable the management interface at both ASRs.
        # 17. Wait till both hosting devices transition back to
        #     "Active" state.
        # 18. Verify config update at both ASRs where the VRFs,
        #     internal/external sub-interfaces, IP NAT pools and static NATs
        #     are added.
        # 19. Verify both VM1 and VM2's floating IP is accessible from the
        #     outside world.
        # 20. Verify from VM1, it can ping VM2's floating IP and vice versa.
        self.verify_global_logical_rtrs(state='DELETED')
        test_project1 = self.projects[0]
        test_project2 = self.projects[1]

        user, project = self.users[0]
        creds = self.identity_utils.get_credentials(user,
                                                    project,
                                                    'cisco123')
        my_creds = TestResources(creds)
        client_mgr1 = clients.Manager(my_creds)

        self.orig_admin_mgr = self.admin_manager
        self.admin_manager = client_mgr1
        self.manager = client_mgr1
        self.setup_clients()

        user, project = self.users[1]
        creds = self.identity_utils.get_credentials(user,
                                                    project,
                                                    'cisco123')
        my_creds = TestResources(creds)
        client_mgr2 = clients.Manager(my_creds)

        net_a = self._get_network_by_name(self.external_nets[0])
        net_c = self._get_network_by_name(self.external_nets[1])

        self.bounce_mgmt_link(self.verify_asrs.active, 'down')
        self.bounce_mgmt_link(self.verify_asrs.standby, 'down')
        active_hd_id = self.get_hosting_device_id(
            self.neutron_client,
            self.get_hosting_device_id_list(self.neutron_client),
            self.verify_asrs.active.ip)

        standby_hd_id = self.get_hosting_device_id(
            self.neutron_client,
            self.get_hosting_device_id_list(self.neutron_client),
            self.verify_asrs.standby.ip)

        self.verify_hosting_device_state(self.log_inspector,
                                         active_hd_id,
                                         'DEAD',
                                         sleep_for=10, max_time=600)

        self.verify_hosting_device_state(self.log_inspector,
                                         standby_hd_id,
                                         'DEAD',
                                         sleep_for=10, max_time=600)

        r1 = self._create_router(client_mgr1.network_client,
                                 test_project1['id'])
        r1.set_gateway(net_a['id'])

        net_b, subnet_b, r1 = self.add_network(tenant_id=test_project1['id'],
                                               router=r1)

        time.sleep(60)

        vm_1, fip_1 = self.create_vm('vm1',
                                     test_project1,
                                     client_mgr1,
                                     net_b,
                                     net_a)
        time.sleep(10)
        self.ping_vm(fip_1, should_succeed=False)

        r2 = self._create_router(client_mgr2.network_client,
                                 test_project2['id'])
        r2.set_gateway(net_c['id'])

        net_e, subnet_e, r2 = self.add_network(tenant_id=test_project2['id'],
                                               router=r2)

        vm_2, fip_2 = self.create_vm('vm2',
                                     test_project2,
                                     client_mgr2,
                                     net_e,
                                     net_c)

        time.sleep(30)
        self.ping_vm(fip_1, should_succeed=False)
        self.ping_vm(fip_2, should_succeed=False)

        self.bounce_mgmt_link(self.verify_asrs.active, 'up')
        self.bounce_mgmt_link(self.verify_asrs.standby, 'up')

        self.verify_hosting_device_state(self.log_inspector,
                                         active_hd_id,
                                         'ACTIVE',
                                         sleep_for=10)

        self.verify_hosting_device_state(self.log_inspector,
                                         standby_hd_id,
                                         'ACTIVE',
                                         sleep_for=10)

        time.sleep(60)
        self.verify_global_logical_rtrs(state='ACTIVE')
        self.ping_vm(fip_1)
        self.ping_vm(fip_2)
        self.verify_vm_connectivity()
        self.verify_vm_to_vm_connectivity()

        client_mgr1.servers_client.delete_server(vm_1['server']['id'])
        time.sleep(5)
        client_mgr1.network_client.remove_router_interface_with_subnet_id(
            r1['id'], subnet_b['id'])
        client_mgr1.network_client.delete_router(r1['id'])
        self.verify_global_logical_rtrs(state='ACTIVE')

        self.ping_vm(fip_1, should_succeed=False)
        self.ping_vm(fip_2)

        client_mgr2.servers_client.delete_server(vm_2['server']['id'])
        time.sleep(5)
        client_mgr2.network_client.remove_router_interface_with_subnet_id(
            r2['id'], subnet_e['id'])
        client_mgr2.network_client.delete_router(r2['id'])
        time.sleep(60)
        self.verify_global_logical_rtrs(state='DELETED')

    def test_tc1010(self):
        #
        # Delete routers with different external networks while hosting
        # device in "Dead" state.
        #
        # 1. Create 2 different tenants, X & Y.
        # 2. In tenant X, create external network A with a subnet and
        #    internal network B with a subnet.
        # 3. In tenant Y, create external network C with a subnet and
        #    internal network D with a subnet.
        # 4. In tenant X, create router R1; set gateway to be external
        #    network A and add router interface for internal network B.
        # 5. Verify Global and Logical Global routers are created.
        # 6. At both ASRs, verify a VLAN subinterface is configured for
        #    external connectivity in the router R1 VRF.
        # 7. In tenant X, launch VM1 on network B.
        # 8. Create floating IP on external network A and assign to VM1.
        # 9. Verify VM1's floating IP is accessible from the outside world.
        # 10. In tenant Y, create router R2; set gateway to be external
        #     network C and add router interface for internal network D.
        # 11. At both ASRs, verify a second VLAN subinterface is configured
        #     for external connectivity in the router R2 VRF.
        # 12. In tenant Y, launch VM2 on network D.
        # 13. Create floating IP on external network C and assign to VM2.
        # 14. Verify VM2's floating IP is accessible from the outside world.
        # 15. Verify from VM1, it can ping VM2's floating IP and vice versa.
        # 16. At both ASRs, disable the management interface and wait till
        #     both hosting devices transition to "Dead" state.
        # 17. In tenant X, delete VM1, remove router R1 interface to subnet B,
        #     and delete router R1.
        # 18. Verify no config update at both ASRs.
        # 19. In tenant Y, delete VM2, remove router R2 interface to subnet D,
        #     and delete router R2.
        # 20. Verify no config update at both ASRs.
        # 21. Verify both the Global and Logical Global routers are deleted.
        # 22. Enable the management interface at both ASRs.
        # 23. Wait till both hosting devices transition back to "Active" state.
        # 24. Verify both ASRs' config is updated where the VRFs,
        #     internal/external sub-interfaces, IP NAT pools and static NATs
        #     are deleted.
        self.verify_global_logical_rtrs(state='DELETED')
        test_project1 = self.projects[0]
        test_project2 = self.projects[1]

        user, project = self.users[0]
        creds = self.identity_utils.get_credentials(user,
                                                    project,
                                                    'cisco123')
        my_creds = TestResources(creds)
        client_mgr1 = clients.Manager(my_creds)

        self.orig_admin_mgr = self.admin_manager
        self.admin_manager = client_mgr1
        self.manager = client_mgr1
        self.setup_clients()

        user, project = self.users[1]
        creds = self.identity_utils.get_credentials(user,
                                                    project,
                                                    'cisco123')
        my_creds = TestResources(creds)
        client_mgr2 = clients.Manager(my_creds)

        net_a = self._get_network_by_name(self.external_nets[0])
        net_c = self._get_network_by_name(self.external_nets[1])

        active_hd_id = self.get_hosting_device_id(
            self.neutron_client,
            self.get_hosting_device_id_list(self.neutron_client),
            self.verify_asrs.active.ip)

        standby_hd_id = self.get_hosting_device_id(
            self.neutron_client,
            self.get_hosting_device_id_list(self.neutron_client),
            self.verify_asrs.standby.ip)

        pretest_asr_cfg = \
                self.neutron_client.cisco_hosting_device_get_config(
                    active_hd_id)

        r1 = self._create_router(client_mgr1.network_client,
                                 test_project1['id'])
        r1.set_gateway(net_a['id'])

        net_b, subnet_b, r1 = self.add_network(tenant_id=test_project1['id'],
                                               router=r1)

        time.sleep(90)
        self.verify_global_logical_rtrs(state='ACTIVE')

        vm_1, fip_1 = self.create_vm('vm1',
                                     test_project1,
                                     client_mgr1,
                                     net_b,
                                     net_a)
        time.sleep(10)
        self.ping_vm(fip_1)
        r2 = self._create_router(client_mgr2.network_client,
                                 test_project2['id'])
        r2.set_gateway(net_c['id'])

        net_e, subnet_e, r2 = self.add_network(tenant_id=test_project2['id'],
                                               router=r2)

        vm_2, fip_2 = self.create_vm('vm2',
                                     test_project2,
                                     client_mgr2,
                                     net_e,
                                     net_c)

        time.sleep(30)
        self.ping_vm(fip_2)
        self.verify_vm_connectivity()
        self.verify_vm_to_vm_connectivity()

        pre_active_netconf_counters = \
            self.verify_asrs.active.get_netconf_counters()

        pre_standby_netconf_counters = \
            self.verify_asrs.standby.get_netconf_counters()

        self.bounce_mgmt_link(self.verify_asrs.active, 'down')
        self.bounce_mgmt_link(self.verify_asrs.standby, 'down')

        self.verify_hosting_device_state(self.log_inspector,
                                         active_hd_id,
                                         'DEAD',
                                         sleep_for=10,
                                         max_time=600)

        self.verify_hosting_device_state(self.log_inspector,
                                         standby_hd_id,
                                         'DEAD',
                                         sleep_for=10,
                                         max_time=600)

        client_mgr1.servers_client.delete_server(vm_1['server']['id'])
        time.sleep(5)
        client_mgr1.network_client.remove_router_interface_with_subnet_id(
            r1['id'], subnet_b['id'])
        client_mgr1.network_client.delete_router(r1['id'])
        time.sleep(90)
        self.verify_global_logical_rtrs(state='ACTIVE')

        self.ping_vm(fip_1, should_succeed=False)
        self.ping_vm(fip_2)

        client_mgr2.servers_client.delete_server(vm_2['server']['id'])
        time.sleep(5)
        client_mgr2.network_client.remove_router_interface_with_subnet_id(
            r2['id'], subnet_e['id'])
        client_mgr2.network_client.delete_router(r2['id'])
        time.sleep(60)
        self.verify_global_logical_rtrs(state='DELETED')

        self.bounce_mgmt_link(self.verify_asrs.active, 'up')
        self.bounce_mgmt_link(self.verify_asrs.standby, 'up')

        self.verify_hosting_device_state(self.log_inspector,
                                         active_hd_id,
                                         'ACTIVE',
                                         sleep_for=10,
                                         max_time=600)

        self.verify_hosting_device_state(self.log_inspector,
                                         standby_hd_id,
                                         'ACTIVE',
                                         sleep_for=10,
                                         max_time=600)

        time.sleep(60)
        self.verify_global_logical_rtrs(state='DELETED')

        post_active_netconf_counters = \
            self.verify_asrs.active.get_netconf_counters()

        post_standby_netconf_counters = \
            self.verify_asrs.standby.get_netconf_counters()

        active_netconf_errors = \
            int(post_active_netconf_counters[
                    'netconf-counters.transaction-errors'])

        standby_netconf_errors = \
            int(post_standby_netconf_counters[
                'netconf-counters.transaction-errors'])

        msg = "Netconf transaction errors detected"
        self.assertIs(0, active_netconf_errors, msg)
        self.assertIs(0, standby_netconf_errors, msg )

        ## Verify counters moved - assumption is netconf deletes are sent
        min_active_netconf_counters = \
            int(int(pre_active_netconf_counters[
                    'netconf-counters.transaction-success']) * .4) \
            + int(pre_active_netconf_counters[
                'netconf-counters.transaction-success'])
        min_standby_netconf_counters = \
            int(int(pre_standby_netconf_counters[
                    'netconf-counters.transaction-success']) * .4) \
            + int(pre_standby_netconf_counters[
                    'netconf-counters.transaction-success'])

        active_success_counters = \
            int(post_active_netconf_counters[
                    'netconf-counters.transaction-success'])

        standby_success_counters = \
            int(post_standby_netconf_counters[
                    'netconf-counters.transaction-success'])

        self.assertGreater(active_success_counters,
                           min_active_netconf_counters)
        self.assertGreater(standby_success_counters,
                           min_standby_netconf_counters)

        posttest_asr_cfg = \
                self.neutron_client.cisco_hosting_device_get_config(
                    active_hd_id)

        asr_cfg_diff = \
            difflib.unified_diff(
                sorted(self.tidyup_asr_config(pretest_asr_cfg)),
                sorted(self.tidyup_asr_config(posttest_asr_cfg)),
                n=0)

        my_diff = []
        for diff in asr_cfg_diff:
            my_diff = diff
        self.assertEmpty(my_diff, "ASR Config diff: ".join(my_diff))

        self.ping_vm(fip_1, should_succeed=False)
        self.ping_vm(fip_2, should_succeed=False)

    def test_tc1012(self):
        #
        # Create and delete routers with different external networks
        # while ASR reboots.
        #
        # 1. Create 10 routers, set gateway each for a different external
        #    network, add router interface for the tenant network.
        # 2. Verify config is pushed down to both ASRs correctly.
        # 3. Reboot ASR-1.
        # 4. While ASR-1 is rebooting, create another 5 routers and set
        #    gateway each for a different external network.  Then immediately
        #    delete these 5 routers.
        # 5. Verify no net config changes at ASR-2.
        # 6. Wait till ASR-1 boots up.  Then check its config.
        # 7. Verify only the original 10 routers config is pushed down.
        #    There is no new config for the 5 routers in step 4
        self.verify_global_logical_rtrs(state='DELETED')
        test_project1 = self.projects[0]

        user, project = self.users[0]
        creds = self.identity_utils.get_credentials(user,
                                                    project,
                                                    'cisco123')
        my_creds = TestResources(creds)
        client_mgr = clients.Manager(my_creds)

        self.orig_admin_mgr = self.admin_manager
        self.admin_manager = client_mgr
        self.manager = client_mgr
        self.setup_clients()

        num_ext_nets = len(self.external_nets)

        t1012_routers = []
        t1012_vms = []
        for net_i in range(0, num_ext_nets - 1):
            net_name = self.external_nets[net_i]
            rtr = self._create_router(client_mgr.network_client,
                                      test_project1['id'])
            net = self._get_network_by_name(net_name)
            rtr.set_gateway(net['id'])
            project_net, subnet, rtr = \
                self.add_network(tenant_id=test_project1['id'], router=rtr)
            t1012_routers.append((rtr, subnet))
            time.sleep(10)
            vm, fip = self.create_vm('vm',
                                     test_project1,
                                     client_mgr,
                                     project_net,
                                     net)
            t1012_vms.append((vm, fip))

        time.sleep(90)
        self.verify_global_logical_rtrs(state='ACTIVE')
        for vm, fip in t1012_vms:
            self.ping_vm(fip)

        asr_hd_id = self.get_hosting_device_id(
            self.neutron_client,
            self.get_hosting_device_id_list(self.neutron_client),
            self.verify_asrs.active.ip)

        preboot_netconf_counters = \
            self.verify_asrs.active.get_netconf_counters()

        netconf_deviation = \
                int(int(
                    preboot_netconf_counters[
                        'netconf-counters.transaction-success']) * .05)
        min_netconf_counters = \
                int(preboot_netconf_counters[
                        'netconf-counters.transaction-success']) - \
                netconf_deviation
        max_netconf_counters = int(preboot_netconf_counters[
                        'netconf-counters.transaction-success']) + \
                netconf_deviation
        preboot_asr_cfg = \
                self.neutron_client.cisco_hosting_device_get_config(asr_hd_id)

        ##
        ## Reboot ASR
        ##
        self.verify_asrs.active.reboot(wait=False)
        asr = self.verify_asrs.active
        time.sleep(60)

        net_name = self.external_nets[-1]
        rtr = self._create_router(client_mgr.network_client,
                                  test_project1['id'])
        net = self._get_network_by_name(net_name)
        rtr.set_gateway(net['id'])
        project_net, subnet, rtr = \
            self.add_network(tenant_id=test_project1['id'], router=rtr)

        vm, fip = self.create_vm('vm',
                                 test_project1,
                                 client_mgr,
                                 project_net,
                                 net)

        time.sleep(30)
        client_mgr.servers_client.delete_server(vm['server']['id'])
        time.sleep(10)
        client_mgr.network_client.remove_router_interface_with_subnet_id(
                rtr['id'], subnet['id'])
        time.sleep(5)
        client_mgr.network_client.delete_router(rtr['id'])

        ## After ASR comes back
        time.sleep(120)
        self.ping_ip_address(self.verify_asrs.active.ip,
                             ping_timeout=600)
        self.verify_asrs.active.connect()
        time.sleep(30)
        self.poll_netconf_ctr(self.verify_asrs.active,
                              int(min_netconf_counters - 4))
        time.sleep(60)

        postboot_asr_cfg = \
            self.neutron_client.cisco_hosting_device_get_config(asr_hd_id)

        postboot_netconf_counters = \
            asr.get_netconf_counters()

        asr_cfg_diff = \
            difflib.unified_diff(
                sorted(self.tidyup_asr_config(preboot_asr_cfg)),
                sorted(self.tidyup_asr_config(postboot_asr_cfg)),
                n=0)

        my_diff = []
        for diff in asr_cfg_diff:
            my_diff = diff
        self.assertEmpty(my_diff, "ASR Config diff".join(my_diff))

        netconf_counters = \
            int(postboot_netconf_counters[
                        'netconf-counters.transaction-success'])

        self.assertTrue(True if netconf_counters >= min_netconf_counters
                        else False)
        self.assertTrue(True if netconf_counters <= max_netconf_counters
                        else False)

        for vm, fip in t1012_vms:
            self.ping_vm(fip)

        for vm, fip in t1012_vms:
            client_mgr.servers_client.delete_server(vm['server']['id'])

        time.sleep(10)
        for rtr, subnet in t1012_routers:
            client_mgr.network_client.remove_router_interface_with_subnet_id(
                rtr['id'], subnet['id'])
            time.sleep(5)
            client_mgr.network_client.delete_router(rtr['id'])

        time.sleep(30)
        self.verify_global_logical_rtrs(state='DELETED')

    def test_tc1013(self):
        #
        # HSRP failover via ASR reboots
        #
        # 1. Create 2 different tenants, X & Y.
        # 2. In tenant X, create external network A with a subnet and
        #    internal network B with a subnet.
        # 3. In tenant Y, create external network C with a subnet and
        #    internal network D with a subnet.
        # 4. In tenant X, create router R1; set gateway to be external
        #    network A and add router interface for internal network B.
        # 5. Verify Global and Logical Global routers are created.
        # 6. At both ASRs, verify a VLAN subinterface is configured for
        #    external connectivity in the router R1 VRF.
        # 7. In tenant X, launch VM1 on network B.
        # 8. Create floating IP on external network A and assign to VM1.
        # 9. Verify VM1's floating IP is accessible from the outside world.
        # 10. In tenant Y, create router R2; set gateway to be external
        #     network C and add router interface for internal network D.
        # 11. At both ASRs, verify a second VLAN subinterface is configured
        #     for external connectivity in the router R2 VRF.
        # 12. In tenant Y, launch VM2 on network D.
        # 13. Create floating IP on external network C and assign to VM2.
        # 14. Verify VM2's floating IP is accessible from the outside world.
        # 15. Verify from VM1, it can ping VM2's floating IP and vice versa.
        # 16. From VM1, ping VM2's floating IP continuously.
        # 17. Reboot ASR1.
        # 18. Verify the ping continues to succeed.
        # 19. Upon ASR1 boots up, verify config update is pushed down.
        # 20. Repeat with ASR2.
        self.verify_global_logical_rtrs(state='DELETED')
        test_project1 = self.projects[0]
        test_project2 = self.projects[1]

        user, project = self.users[0]
        creds = self.identity_utils.get_credentials(user,
                                                    project,
                                                    'cisco123')
        my_creds = TestResources(creds)
        client_mgr1 = clients.Manager(my_creds)

        self.orig_admin_mgr = self.admin_manager
        self.admin_manager = client_mgr1
        self.manager = client_mgr1
        self.setup_clients()

        user, project = self.users[1]
        creds = self.identity_utils.get_credentials(user,
                                                    project,
                                                    'cisco123')
        my_creds = TestResources(creds)
        client_mgr2 = clients.Manager(my_creds)

        net_a = self._get_network_by_name(self.external_nets[0])
        net_c = self._get_network_by_name(self.external_nets[1])

        r1 = self._create_router(client_mgr1.network_client,
                                 test_project1['id'])
        r1.set_gateway(net_a['id'])

        net_b, subnet_b, r1 = self.add_network(tenant_id=test_project1['id'],
                                               router=r1)

        time.sleep(60)
        self.verify_global_logical_rtrs(state='ACTIVE')

        vm_1, fip_1 = self.create_vm('vm1',
                                     test_project1,
                                     client_mgr1,
                                     net_b,
                                     net_a)
        time.sleep(10)
        self.ping_vm(fip_1)

        r2 = self._create_router(client_mgr2.network_client,
                                 test_project2['id'])
        r2.set_gateway(net_c['id'])

        net_e, subnet_e, r2 = self.add_network(tenant_id=test_project2['id'],
                                               router=r2)

        vm_2, fip_2 = self.create_vm('vm2',
                                     test_project2,
                                     client_mgr2,
                                     net_e,
                                     net_c)

        time.sleep(30)
        self.ping_vm(fip_2)
        self.verify_vm_connectivity()
        self.verify_vm_to_vm_connectivity()

        for asr in [self.verify_asrs.active, self.verify_asrs.standby]:
            asr_hd_id = self.get_hosting_device_id(
                self.neutron_client,
                self.get_hosting_device_id_list(self.neutron_client),
                asr.ip)

            preboot_netconf_counters = asr.get_netconf_counters()
            netconf_deviation = \
                int(int(
                    preboot_netconf_counters[
                        'netconf-counters.transaction-success']) * .05)
            min_netconf_counters = \
                int(preboot_netconf_counters[
                        'netconf-counters.transaction-success']) - \
                netconf_deviation
            max_netconf_counters = int(preboot_netconf_counters[
                        'netconf-counters.transaction-success']) + \
                netconf_deviation
            preboot_asr_cfg = \
                self.neutron_client.cisco_hosting_device_get_config(asr_hd_id)

            ##
            ## Reboot ASR
            ##
            asr.reboot(wait=False)
            time.sleep(30)

            start_time = time.time()
            current_time = time.time()
            max_time = 600
            while current_time < (start_time + max_time):
                self.verify_vm_to_vm_connectivity()
                if self.ping_ip_address(asr.ip, ping_timeout=5):
                    break
                current_time = time.time()

            msg = "Ping of ASR {0} failed after " \
                  "reboot".format(asr.ip)
            self.assertTrue(self.ping_ip_address(asr.ip), msg=msg)

            time.sleep(120)
            asr.connect()

            time.sleep(30)

            self.poll_netconf_ctr(asr, min_netconf_counters)
            time.sleep(60)
            postboot_netconf_counters = \
                asr.get_netconf_counters()

            postboot_asr_cfg = \
                self.neutron_client.cisco_hosting_device_get_config(asr_hd_id)

            some_cfg1 = sorted(self.tidyup_asr_config(preboot_asr_cfg))
            some_cfg2 = sorted(self.tidyup_asr_config(postboot_asr_cfg))
            asr_cfg_diff = \
                difflib.unified_diff(
                    sorted(self.tidyup_asr_config(preboot_asr_cfg)),
                    sorted(self.tidyup_asr_config(postboot_asr_cfg)),
                    n=0)

            my_diff = []
            for diff in asr_cfg_diff:
                my_diff.append(diff)
            self.assertEmpty(my_diff, "ASR Config diff: ".join(my_diff))

            netconf_counters = \
                int(postboot_netconf_counters[
                        'netconf-counters.transaction-success'])

            self.assertTrue(True if netconf_counters >= min_netconf_counters
                            else False)
            self.assertTrue(True if netconf_counters <= max_netconf_counters
                            else False)
            self.verify_vm_connectivity()
            self.verify_vm_to_vm_connectivity()

        client_mgr1.servers_client.delete_server(vm_1['server']['id'])
        time.sleep(5)
        client_mgr1.network_client.remove_router_interface_with_subnet_id(
            r1['id'], subnet_b['id'])
        client_mgr1.network_client.delete_router(r1['id'])
        self.verify_global_logical_rtrs(state='ACTIVE')

        self.ping_vm(fip_1, should_succeed=False)
        self.ping_vm(fip_2)

        client_mgr2.servers_client.delete_server(vm_2['server']['id'])
        time.sleep(5)
        client_mgr2.network_client.remove_router_interface_with_subnet_id(
            r2['id'], subnet_e['id'])
        client_mgr2.network_client.delete_router(r2['id'])
        time.sleep(60)
        self.verify_global_logical_rtrs(state='DELETED')
