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
import tempest.thirdparty.cir.lib.asr as asr
import time

from oslo_log import log as logging
from tempest import clients
from tempest.lib import exceptions
from tempest import config as tempest_conf
from tempest.thirdparty.cir.ml2 import test_asr_men_base
from tempest.scenario import test_network_multi_node
from tempest.lib.common.cred_provider import TestResources
from tempest.thirdparty.cir.lib.device.LogInspector import LogInspector

CONF = tempest_conf.CONF

LOG = logging.getLogger(__name__)
LOG.debug("")

Floating_IP_tuple = collections.namedtuple('Floating_IP_tuple',
                                           ['floating_ip', 'server'])

class TestASRMenFunctional(test_asr_men_base.TestASRMenBase):

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

        self.log_inspector = LogInspector()
        self.addCleanup(self.check_log_errors)

        # Classes that inherit this class can redefine packet size/count
        # based on their own needs or accept the default in the CONF
        if not hasattr(self, 'test_packet_sizes'):
            self.test_packet_sizes = map(int, CONF.scenario.test_packet_sizes)

        if not hasattr(self, 'test_packet_count'):
            self.test_packet_count = CONF.scenario.test_packet_count

        if not hasattr(self, 'max_instances_per_tenant'):
            self.max_instances_per_tenant = (
                CONF.scenario.max_instances_per_tenant)

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

        # Allows the ability to place VMs on specific compute nodes
        self.external_nets = ['public',
                              'ext-net2',
                              'ext-net3',
                              'ext-net4',
                              'ext-net5',
                              'ext-net6',
                              'ext-net7',
                              'ext-net8',
                              'ext-net9',
                              'ext-net10']
        self.check_extnernal_nets()
        self.setup_projects()
        self.setup_users()
        self.create_project_roles()
        self.assign_users_role()
        self.create_security_groups()

        super(test_network_multi_node.TestNetworkMultiNode, self).setUp()

    def check_log_errors(self):
        time.sleep(60)
        self.log_inspector.record_errors('test-end')
        self.log_inspector.compare_logs('baseline', 'test-end')


    def test_tc1001(self):
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

        time.sleep(60)
        self.verify_global_logical_rtrs(state='ACTIVE')

        r2 = self._create_router(client_mgr2.network_client,
                                 test_project2['id'])
        r2.set_gateway(net_c['id'])

        net_b, subnet_b, r1 = self.add_network(tenant_id=test_project1['id'],
                                               router=r1)
        net_e, subnet_e, r2 = self.add_network(tenant_id=test_project2['id'],
                                               router=r2)

        time.sleep(10)

        vm_1, fip_1 = self.create_vm('vm1',
                                     test_project1,
                                     client_mgr1,
                                     net_b,
                                     net_a)

        vm_2, fip_2 = self.create_vm('vm2',
                                     test_project2,
                                     client_mgr2,
                                     net_e,
                                     net_c)

        time.sleep(30)
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

    def test_tc1002(self):
        # Same Tenant: create multiple routers, each with a different external
        # network
        #
        # 1. Create tenant X.
        # 2. In tenant X, create external networks A, B and C; each with
        #    subnet.
        # 3. Create internal networks D, E and F; each with subnet.
        # 4. Create router R1; set gateway to be external network A and add
        #    router interface for internal network D.
        # 5. Verify Global and Logical Global routers are created.
        # 6. At both ASRs, verify a VLAN subinterface is configured for
        #    external connectivity in the router R1 VRF.
        # 7. Launch VM1 on network D.
        # 8. Create floating IP on external network A and assign to VM1.
        # 9. Verify VM1's floating IP is accessible from the outside world.
        # 10. Create router R2; set gateway to be external network B and add
        #     router interface for internal network E.
        # 11. At both ASRs, verify a second VLAN subinterface is configured
        #     for external connectivity in the router R2 VRF.
        # 12. Launch VM2 on network E.
        # 13. Create floating IP on external network B and assign to VM2.
        # 14. Verify VM2's floating IP is accessible from the outside world.
        # 15. Create router R3; set gateway to be external network C and add
        #     router interface for internal network F.
        # 16. At both ASRs, verify a third VLAN subinterface is configured
        #     for external connectivity in the router R3 VRF.
        # 17. Launch VM3 on network F.
        # 18. Create floating IP on external network C and assign to VM3.
        # 19. Verify VM3's floating IP is accessible from the outside world.
        # 20. Verify from each VM, it can ping the other 2 VMs' floating IPs.
        self.verify_global_logical_rtrs(state='DELETED')
        test_project = self.projects[0]

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

        net_a = self._get_network_by_name(self.external_nets[0])
        net_b = self._get_network_by_name(self.external_nets[1])
        net_c = self._get_network_by_name(self.external_nets[2])

        r1 = self._create_router(client_mgr.network_client, test_project['id'])
        r1.set_gateway(net_a['id'])

        r2 = self._create_router(client_mgr.network_client, test_project['id'])
        r2.set_gateway(net_b['id'])

        r3 = self._create_router(client_mgr.network_client, test_project['id'])
        r3.set_gateway(net_c['id'])

        net_d, subnet_d, r1 = \
            self.add_network(client=client_mgr.network_client,
                             tenant_id=test_project['id'],
                             router=r1)

        net_e, subnet_e, r2 = \
            self.add_network(client=client_mgr.network_client,
                             tenant_id=test_project['id'],
                             router=r2)

        net_f, subnet_f, r3 = \
            self.add_network(client=client_mgr.network_client,
                             tenant_id=test_project['id'],
                             router=r3)

        time.sleep(120)
        self.verify_global_logical_rtrs(state='ACTIVE')

        vm_1, fip_1 = self.create_vm('vm1',
                                     test_project,
                                     client_mgr,
                                     net_d,
                                     net_a)

        vm_2, fip_2 = self.create_vm('vm2',
                                     test_project,
                                     client_mgr,
                                     net_e,
                                     net_b)

        vm_3, fip_3 = self.create_vm('vm3',
                                     test_project,
                                     client_mgr,
                                     net_f,
                                     net_c)

        time.sleep(120)
        self.verify_global_logical_rtrs(state='ACTIVE')
        self.verify_vm_connectivity()
        self.verify_vm_to_vm_connectivity()

        client_mgr.servers_client.delete_server(vm_1['server']['id'])
        time.sleep(5)
        client_mgr.network_client.remove_router_interface_with_subnet_id(
            r1['id'], subnet_d['id'])
        client_mgr.network_client.delete_router(r1['id'])
        self.verify_global_logical_rtrs(state='ACTIVE')

        self.ping_vm(fip_1, should_succeed=False)
        self.ping_vm(fip_2)
        self.ping_vm(fip_3)

        client_mgr.servers_client.delete_server(vm_2['server']['id'])
        time.sleep(5)
        client_mgr.network_client.remove_router_interface_with_subnet_id(
            r2['id'], subnet_e['id'])
        client_mgr.network_client.delete_router(r2['id'])
        self.verify_global_logical_rtrs(state='ACTIVE')

        self.ping_vm(fip_2, should_succeed=False)
        self.ping_vm(fip_3)

        client_mgr.servers_client.delete_server(vm_3['server']['id'])
        time.sleep(5)
        client_mgr.network_client.remove_router_interface_with_subnet_id(
            r3['id'], subnet_f['id'])
        client_mgr.network_client.delete_router(r3['id'])

        self.ping_vm(fip_3, should_succeed=False)
        self.verify_global_logical_rtrs(state='DELETED')

    def test_tc1003(self):
        # 1. Create tenants X and Y.
        # 2. In tenant X, create external network A with a subnet and internal
        #    network B with a subnet.
        # 3. In tenant Y, create external network C with a subnet and internal
        #    network D with a subnet.
        # 4. In tenant X, create router R1; set gateway to be external network
        #    A and add router interface for internal network B.
        # 5. Verify the Global and Logical Global routers are created.
        # 6. At both ASRs, verify a VLAN subinterface is configured for
        #    external connectivity in the router R1 VRF.
        # 7. In tenant X, launch VM1 on network B.
        # 8. Create floating IP on external network A and assign to VM1.
        # 9. Verify VM1's floating IP is accessible from the outside world.
        # 10. In tenant X, clear the router R1 gateway to external network A.
        # 11. Operation should fail since a floating IP is in use.
        # 12. Disassociate the floating IP at VM1.
        # 13. Clear the router R1 gateway to external network A.
        # 14. Verify the Global and Logical Global routers are deleted.
        # 15. At both ASRs, verify the VLAN subinterface for external
        #     connectivity to network A in the router R1 VRF is deleted.
        # 16. In tenant X, create external network E with a subnet.
        # 17. Set gateway for router R1 to be external network E.
        # 18. Verify the Global and Logical Global routers are created.
        # 19. At both ASRs, verify a new VLAN subinterface is configured for
        #     external connectivity to network E in the router R1 VRF.
        # 20. Create floating IP on external network E and assign to VM1.
        # 21. Verify VM1's floating IP is accessible from the outside world.
        # 22. In tenant Y, create router R2; set gateway to be external
        #     network C and add router interface for internal network D.
        # 23. At both ASRs, verify a second VLAN subinterface is configured
        #     for external connectivity to network C in the router R2 VRF.
        # 24. In tenant Y, launch VM2 on network D.
        # 25. Create floating IP on external network C and assign to VM2.
        # 26. Verify VM2's floating IP is accessible from the outside world.
        # 27. Verify from VM1, it can ping VM2's floating IP and vice versa.
        # 28. In tenant Y, clear the router R2 gateway to external network C.
        # 29. Operation should fail since a floating IP is in use.
        # 30. Disassociate the floating IP at VM2.
        # 31. Clear the router R2 gateway to external network C.
        # 32. Verify the Global and Logical Global routers are not deleted
        #     since R1 still has its gateway set.
        # 33. At both ASRs, verify the VLAN subinterface for external
        #     connectivity to network C in the router R2 VRF is deleted.
        # 34. In tenant X, disassociate the floating IP at VM1.
        # 35. Clear the router R1 gateway to external network E.
        # 36. Verify the Global and Logical Global routers are deleted.
        # 37. At both ASRs, verify the VLAN subinterface for external
        #      connectivity to network E in the router R1 VRF is deleted.

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
        net_c = self._get_network_by_name(self.external_nets[2])

        r1 = self._create_router(client_mgr1.network_client,
                                 test_project1['id'])
        r1.set_gateway(net_a['id'])

        net_b, subnet_b, r1 = self.add_network(tenant_id=test_project1['id'],
                                               router=r1)

        time.sleep(120)
        self.verify_global_logical_rtrs(state='ACTIVE')
        self.segmentation_ids.append(net_a['provider:segmentation_id'])
        self.segmentation_ids.append(net_b['provider:segmentation_id'])

        vm_1, fip_1 = self.create_vm('vm1',
                                     test_project1,
                                     client_mgr1,
                                     net_b,
                                     net_a)
        time.sleep(10)
        self.ping_vm(fip_1)

        try:
            r1.unset_gateway()
        except exceptions.Conflict as e:
            self.assertIn("RouterExternalGatewayInUseByFloatingIp",
                          e._error_string)

        self._disassociate_floating_ip(fip_1)
        time.sleep(60)
        r1.unset_gateway()
        time.sleep(60)
        self.verify_global_logical_rtrs(state='DELETED')

        net_e = self._get_network_by_name(self.external_nets[1])
        r1.set_gateway(net_e['id'])
        time.sleep(60)
        self.verify_global_logical_rtrs(state='ACTIVE')

        r2 = self._create_router(client_mgr2.network_client,
                                 test_project2['id'])
        r2.set_gateway(net_c['id'])

        net_d, subnet_d, r2 = self.add_network(tenant_id=test_project2['id'],
                                               router=r2)

        server = {'id': vm_1['server']['id'],
                  'tenant_id': test_project1['id']}
        fip_1 = \
            self.create_floating_ip(server, external_network_id=net_e['id'])

        time.sleep(5)
        self.ping_vm(fip_1)

        vm_2, fip_2 = self.create_vm('vm2',
                                     test_project2,
                                     client_mgr2,
                                     net_d,
                                     net_c)
        time.sleep(30)
        self.ping_vm(fip_2)
        self.verify_vm_connectivity()
        #self.verify_vm_to_vm_connectivity()

        try:
            r2.unset_gateway()
        except exceptions.Conflict as e:
            self.assertIn("RouterExternalGatewayInUseByFloatingIp",
                          e._error_string)

        self._disassociate_floating_ip(fip_2)
        time.sleep(120)

        r2.unset_gateway()
        time.sleep(60)

        self.verify_global_logical_rtrs(state='ACTIVE')

        self._disassociate_floating_ip(fip_1)
        time.sleep(60)
        r1.unset_gateway()
        self.verify_global_logical_rtrs(state='DELETED')

        client_mgr1.servers_client.delete_server(vm_1['server']['id'])
        time.sleep(5)
        client_mgr1.network_client.remove_router_interface_with_subnet_id(
            r1['id'], subnet_b['id'])
        client_mgr1.network_client.delete_router(r1['id'])
        self.verify_global_logical_rtrs(state='ACTIVE')

        client_mgr2.servers_client.delete_server(vm_2['server']['id'])
        time.sleep(5)
        client_mgr2.network_client.remove_router_interface_with_subnet_id(
            r2['id'], subnet_d['id'])
        client_mgr2.network_client.delete_router(r2['id'])
        time.sleep(60)
        self.verify_global_logical_rtrs(state='DELETED')

    def test_tc1004(self):
        # 1. Create tenant X.
        # 2. In tenant X, create external networks A, B and C; each with subnet.
        # 3. Create internal networks D and E; each with subnet.
        # 4. Create router R1; set gateway to be external network A and add
        #    router interface for internal network D.
        # 5. Verify Global and Logical Global routers are created.
        # 6. At both ASRs, verify a VLAN subinterface is configured for
        #    external connectivity to network A in the router R1 VRF.
        # 7. Launch VM1 on network D.
        # 8. Create floating IP on external network A and assign to VM1.
        # 9. Verify VM1's floating IP is accessible from the outside world.
        # 10. Clear the router R1 gateway to external network A.
        # 11. Operation should fail since a floating IP is in use.
        # 12. Disassociate the floating IP at VM1.
        # 13. Clear the router R1 gateway to external network A.
        # 14. Verify the Global and Logical Global routers are deleted.
        # 15. At both ASRs, verify the VLAN subinterface for external
        #     connectivity to network A in the router R1 VRF is deleted.
        # 16. Set gateway for router R1 to be external network B.
        # 17. Verify the Global and Logical Global routers are created.
        # 18. At both ASRs, verify a new VLAN subinterface is configured for
        #     external connectivity to network B in the router R1 VRF.
        # 19. Create floating IP on external network B and assign to VM1.
        # 20. Verify VM1's floating IP is accessible from the outside world.
        # 21. Create router R2; set gateway to be external network C and add
        #     router interface for internal network E.
        # 22. At both ASRs, verify a second VLAN subinterface is configured
        #     for external connectivity to network C in the router R2 VRF.
        # 23. Launch VM2 on network E.
        # 24. Create floating IP on external network C and assign to VM2.
        # 25. Verify VM2's floating IP is accessible from the outside world.
        # 26. Verify from VM1, it can ping VM2's floating IP and vice versa.
        # 27. Clear the router R2 gateway to external network C.
        # 28. Operation should fail since a floating IP is in use.
        # 29. Disassociate the floating IP at VM2.
        # 30. Clear the router R2 gateway to external network C.
        # 31. Verify the Global and Logical Global routers are not deleted
        #     since R1 still has its gateway set.
        # 32. At both ASRs, verify the VLAN subinterface for external
        #     connectivity to network C in the router R2 VRF is deleted.
        # 33. Disassociate the floating IP at VM1.

        # 34. Clear the router R1 gateway to external network B.
        # 35. Verify the Global and Logical Global routers are deleted.
        # 36. At both ASRs, verify the VLAN subinterface for external
        #     connectivity to network B in the router R1 VRF is deleted.
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

        net_a = self._get_network_by_name(self.external_nets[0])
        net_b = self._get_network_by_name(self.external_nets[1])
        net_c = self._get_network_by_name(self.external_nets[2])

        r1 = self._create_router(client_mgr.network_client,
                                 test_project1['id'])
        r1.set_gateway(net_a['id'])

        net_d, subnet_d, r1 = self.add_network(tenant_id=test_project1['id'],
                                               router=r1)

        time.sleep(60)
        self.verify_global_logical_rtrs(state='ACTIVE')

        vm_1, fip_1 = self.create_vm('vm1',
                                     test_project1,
                                     client_mgr,
                                     net_d,
                                     net_a)
        self.ping_vm(fip_1)

        try:
            r1.unset_gateway()
        except exceptions.Conflict as e:
            self.assertIn("RouterExternalGatewayInUseByFloatingIp",
                          e._error_string)

        self._disassociate_floating_ip(fip_1)
        time.sleep(30)
        r1.unset_gateway()
        time.sleep(30)
        self.verify_global_logical_rtrs(state='DELETED')

        r1.set_gateway(net_b['id'])
        time.sleep(30)
        self.verify_global_logical_rtrs(state='ACTIVE')

        server = {'id': vm_1['server']['id'],
                  'tenant_id': test_project1['id']}
        fip_1 = \
            self.create_floating_ip(server, external_network_id=net_b['id'])

        self.ping_vm(fip_1)

        r2 = self._create_router(client_mgr.network_client,
                                 test_project1['id'])
        r2.set_gateway(net_c['id'])

        net_e, subnet_e, r2 = self.add_network(tenant_id=test_project1['id'],
                                               router=r2)

        vm_2, fip_2 = self.create_vm('vm2',
                                     test_project1,
                                     client_mgr,
                                     net_e,
                                     net_c)
        time.sleep(10)
        self.ping_vm(fip_2)

        try:
            r2.unset_gateway()
        except exceptions.Conflict as e:
            self.assertIn("RouterExternalGatewayInUseByFloatingIp",
                          e._error_string)

        self._disassociate_floating_ip(fip_2)
        time.sleep(120)
        r2.unset_gateway()
        time.sleep(30)
        self.verify_global_logical_rtrs(state='ACTIVE')

        self._disassociate_floating_ip(fip_1)
        time.sleep(60)
        r1.unset_gateway()

        self.verify_global_logical_rtrs(state='DELETED')
        client_mgr.servers_client.delete_server(vm_1['server']['id'])
        client_mgr.network_client.remove_router_interface_with_subnet_id(
            r1['id'], subnet_d['id'])
        client_mgr.network_client.delete_router(r1['id'])

        client_mgr.servers_client.delete_server(vm_2['server']['id'])
        client_mgr.network_client.remove_router_interface_with_subnet_id(
            r2['id'], subnet_e['id'])
        client_mgr.network_client.delete_router(r2['id'])

    def test_tc1005(self):
        # 1. Create 2 different tenants, X & Y.
        # 2. In tenant X, create external network A with a subnet and internal
        #    network B with a subnet.
        # 3. In tenant Y, create external network C with a subnet and internal
        #    network D with a subnet.
        # 4. In tenant X, create router R1; set gateway to be external network
        #    A and add router interface for internal network B.
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
        # 16. In tenant X, delete VM1.
        # 17. In tenant X, delete the router interface for subnet B.
        # 18. In tenant X, delete router R1.
        # 19. At both ASRs, verify the associated VRF, the VLAN subinterface
        #     and the NAT pool are deleted.
        # 20. Verify the Global and Logical Global routers are not deleted
        #     because router R2 still exists.
        # 21. In tenant Y, delete VM2.
        # 22. In tenant Y, delete the router interface for subnet D.
        # 23. In tenant Y, delete router R2.
        # 24. At both ASRs, verify the associated VRF, the VLAN subinterface
        #     and the NAT pool are deleted.
        # 25. Verify the Global and Logical Global routers are now deleted.
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
        net_c = self._get_network_by_name(self.external_nets[2])

        r1 = self._create_router(self.network_client, test_project1['id'])
        r1.set_gateway(net_a['id'])

        r2 = self._create_router(self.network_client, test_project2['id'])
        r2.set_gateway(net_c['id'])

        net_b, subnet_b, r1 = self.add_network(tenant_id=test_project1['id'],
                                               router=r1)
        net_d, subnet_d, r2 = self.add_network(tenant_id=test_project2['id'],
                                               router=r2)

        time.sleep(90)
        self.verify_global_logical_rtrs(state='ACTIVE')

        vm_1, fip_1 = self.create_vm('vm1',
                                     test_project1,
                                     client_mgr1,
                                     net_b,
                                     net_a)

        vm_2, fip_2 = self.create_vm('vm2',
                                     test_project2,
                                     client_mgr2,
                                     net_d,
                                     net_c)

        time.sleep(60)
        self.verify_vm_connectivity()

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
            r2['id'], subnet_d['id'])
        client_mgr2.network_client.delete_router(r2['id'])
        time.sleep(60)
        self.verify_global_logical_rtrs(state='DELETED')

        self.ping_vm(fip_1, should_succeed=False)
        self.ping_vm(fip_2, should_succeed=False)

    def test_tc1006(self):
        # 1. Create tenant X.
        # 2. In tenant X, create external networks A, B and C; each
        #    with subnet.
        # 3. Create internal networks D, E and F; each with subnet.
        # 4. Create router R1; set gateway to be external network A and add
        #    router interface for internal network D.
        # 5. Verify Global and Logical Global routers are created.
        # 6. At both ASRs, verify a VLAN subinterface is configured for
        #    external connectivity in the router R1 VRF.
        # 7. Launch VM1 on network D.
        # 8. Create floating IP on external network A and assign to VM1.
        # 9. Verify VM1's floating IP is accessible from the outside world.
        # 10. Create router R2; set gateway to be external network B and add
        #     router interface for internal network E.
        # 11. At both ASRs, verify a second VLAN subinterface is configured
        #     for external connectivity in the router R2 VRF.
        # 12. Launch VM2 on network E.
        # 13. Create floating IP on external network B and assign to VM2.
        # 14. Verify VM2's floating IP is accessible from the outside world.
        # 15. Create router R3; set gateway to be external network C and add
        #     router interface for internal network F.
        # 11. At both ASRs, verify a third VLAN subinterface is configured
        #     for external connectivity in the router R3 VRF.
        # 12. Launch VM3 on network F.
        # 13. Create floating IP on external network C and assign to VM3.
        # 14. Verify VM3's floating IP is accessible from the outside world.
        # 15. Verify from each VM, it can ping the other 2 VMs' floating IPs.
        # 16. Delete VM1.
        # 17. Delete router R1 interface to subnet D.
        # 18. Delete router R1.
        # 19. At both ASRs, verify the associated VRF, the VLAN subinterface
        #     and the NAT pool are deleted.
        # 20. Verify the Global and Logical Global routers are not deleted
        #     because there are still other routers R2 and R3 exist.
        # 21. Delete VM2.
        # 22. Delete the router R2 interface to subnet E.
        # 23. Delete router R2.
        # 24. At both ASRs, verify the associated VRF, the VLAN subinterface
        #     and the NAT pool are deleted.
        # 25. Verify the Global and Logical Global routers are not deleted
        #     because router R2 still exists.
        # 26. Delete VM3.
        # 27. Delete the router R3 interface to subnet E.
        # 23. Delete router R3.
        # 24. At both ASRs, verify the associated VRF, the VLAN subinterface
        #     and the NAT pool are deleted.
        # 25. Verify the Global and Logical Global routers are now deleted.

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

        net_a = self._get_network_by_name(self.external_nets[0])
        net_b = self._get_network_by_name(self.external_nets[1])
        net_c = self._get_network_by_name(self.external_nets[2])

        r1 = self._create_router(client_mgr.network_client,
                                 test_project1['id'])
        r1.set_gateway(net_a['id'])

        net_d, subnet_d, r1 = \
            self.add_network(client=client_mgr.network_client,
                             tenant_id=test_project1['id'],
                             router=r1)

        time.sleep(120)
        self.verify_global_logical_rtrs(state='ACTIVE')

        self.segmentation_ids = []
        self.segmentation_ids.append(net_a['provider:segmentation_id'])
        self.segmentation_ids.append(net_d['provider:segmentation_id'])

        vm_1, fip_1 = self.create_vm('vm1',
                                     test_project1,
                                     client_mgr,
                                     net_d,
                                     net_a)

        self.ping_vm(fip_1)

        r2 = self._create_router(client_mgr.network_client,
                                 test_project1['id'])
        r2.set_gateway(net_b['id'])

        net_e, subnet_e, r2 = \
            self.add_network(client=client_mgr.network_client,
                             tenant_id=test_project1['id'],
                             router=r2)

        self.segmentation_ids.append(net_b['provider:segmentation_id'])
        self.segmentation_ids.append(net_e['provider:segmentation_id'])

        time.sleep(120)
        self.verify_global_logical_rtrs(state='ACTIVE')

        vm_2, fip_2 = self.create_vm('vm2',
                                     test_project1,
                                     client_mgr,
                                     net_e,
                                     net_b)

        self.ping_vm(fip_2)

        r3 = self._create_router(client_mgr.network_client,
                                 test_project1['id'])
        r3.set_gateway(net_c['id'])

        net_f, subnet_f, r3 = \
            self.add_network(client=client_mgr.network_client,
                             tenant_id=test_project1['id'],
                             router=r3)

        self.segmentation_ids.append(net_c['provider:segmentation_id'])
        self.segmentation_ids.append(net_f['provider:segmentation_id'])

        time.sleep(120)
        self.verify_global_logical_rtrs(state='ACTIVE')

        vm_3, fip_3 = self.create_vm('vm3',
                                     test_project1,
                                     client_mgr,
                                     net_f,
                                     net_c)

        self.ping_vm(fip_3)

        self.verify_vm_connectivity()
        self.verify_vm_to_vm_connectivity()

        client_mgr.servers_client.delete_server(vm_1['server']['id'])
        time.sleep(10)
        client_mgr.network_client.remove_router_interface_with_subnet_id(
            r1['id'], subnet_d['id'])
        client_mgr.network_client.delete_router(r1['id'])
        self.verify_global_logical_rtrs(state='ACTIVE')

        self.ping_vm(fip_1, should_succeed=False)
        self.ping_vm(fip_2)
        self.ping_vm(fip_3)

        client_mgr.servers_client.delete_server(vm_2['server']['id'])
        time.sleep(10)
        client_mgr.network_client.remove_router_interface_with_subnet_id(
            r2['id'], subnet_e['id'])
        client_mgr.network_client.delete_router(r2['id'])
        self.verify_global_logical_rtrs(state='ACTIVE')

        self.ping_vm(fip_2, should_succeed=False)
        self.ping_vm(fip_3)

        client_mgr.servers_client.delete_server(vm_3['server']['id'])
        time.sleep(10)
        client_mgr.network_client.remove_router_interface_with_subnet_id(
            r3['id'], subnet_f['id'])
        client_mgr.network_client.delete_router(r3['id'])

        self.ping_vm(fip_3, should_succeed=False)
        self.verify_global_logical_rtrs(state='DELETED')

    def test_scale_001(self):
        self.verify_global_logical_rtrs(state='DELETED')

        routers = []
        floating_ips = []
        for i in range(0, len(self.projects)):
            test_project = self.projects[i]
            user, project = self.users[i]
            creds = self.identity_utils.get_credentials(user,
                                                        project,
                                                        'cisco123')
            my_creds = TestResources(creds)
            client_mgr = clients.Manager(my_creds)

            self.orig_admin_mgr = self.admin_manager
            self.admin_manager = client_mgr
            self.manager = client_mgr
            self.setup_clients()

            net_a = self._get_network_by_name(self.external_nets[i])

            r1 = self._create_router(client_mgr.network_client,
                                     test_project['id'])
            r1.set_gateway(net_a['id'])

            net_d, subnet_d, r1 = \
                self.add_network(client=client_mgr.network_client,
                                 tenant_id=test_project['id'],
                                 router=r1)

            vm_1, fip_1 = self.create_vm('vmA' + str(i),
                                         test_project,
                                         client_mgr,
                                         net_d,
                                         net_a)
            floating_ips.append(fip_1)
            vm_1, fip_1 = self.create_vm('vmB' + str(i),
                                         test_project,
                                         client_mgr,
                                         net_d,
                                         net_a)
            floating_ips.append(fip_1)
            routers.append(r1)

        self.verify_global_logical_rtrs(state='ACTIVE')
        time.sleep(30)

        # Ping all the VMs via the Floating IP
        failed_fips = []
        for fip in floating_ips:
            try:
                self.ping_vm(fip)
            except:
                failed_fips.append(fip)

        self.assertEmpty(failed_fips)

        rtr_gw_fixed_ips = [rtr['external_gateway_info']['external_fixed_ips'] for rtr in routers]
        ext_subnet_ids_list = [[subnet['subnet_id'] for subnet in fixed_ip] for fixed_ip in rtr_gw_fixed_ips]
        ext_subnet_ids = []
        for ext_list in ext_subnet_ids_list:
            for element in ext_list:
                ext_subnet_ids.append(element)

        port_list = self.network_client.list_ports()

        for port in port_list['ports']:
            if 'network:router_interface' in port['device_owner']:
                for fixed_ip in port['fixed_ips']:
                    if fixed_ip['subnet_id'] in ext_subnet_ids:
                        self.ping_ip_address(fixed_ip['ip_address'])


    def test_scale_002(self):
        self.verify_global_logical_rtrs(state='DELETED')

        routers = []
        floating_ips = []
        for i in range(0, len(self.projects)):
            test_project = self.projects[i]
            user, project = self.users[i]
            creds = self.identity_utils.get_credentials(user,
                                                project,
                                                'cisco123')
            my_creds = TestResources(creds)
            client_mgr = clients.Manager(my_creds)

            self.orig_admin_mgr = self.admin_manager
            self.admin_manager = client_mgr
            self.manager = client_mgr
            self.setup_clients()

            net_a = self._get_network_by_name(self.external_nets[i])

            r1 = self._create_router(client_mgr.network_client,
                             test_project['id'])
            r1.set_gateway(net_a['id'])

            net_d, subnet_d, r1 = \
                self.add_network(client=client_mgr.network_client,
                                 tenant_id=test_project['id'],
                                 router=r1)

            vm_1, fip_1 = self.create_vm('vm' + str(i),
                                         test_project,
                                         client_mgr,
                                         net_d,
                                        net_a)
            floating_ips.append(fip_1)
            routers.append(r1)

        self.verify_global_logical_rtrs(state='ACTIVE')
        time.sleep(30)

        # Ping all the VMs via the Floating IP
        for fip in floating_ips:
            self.ping_vm(fip)

        rtr_gw_fixed_ips = [rtr['external_gateway_info']['external_fixed_ips'] for rtr in routers]
        ext_subnet_ids_list = [[subnet['subnet_id'] for subnet in fixed_ip] for fixed_ip in rtr_gw_fixed_ips]
        ext_subnet_ids = []
        for ext_list in ext_subnet_ids_list:
            for element in ext_list:
                ext_subnet_ids.append(element)

        port_list = self.network_client.list_ports()

        # Ping all the external GW interfaces on the ASRs
        for port in port_list['ports']:
            if 'network:router_interface' in port['device_owner']:
                for fixed_ip in port['fixed_ips']:
                    if fixed_ip['subnet_id'] in ext_subnet_ids:
                        self.ping_ip_address(fixed_ip['ip_address'])
