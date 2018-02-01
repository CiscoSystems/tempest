
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

# The test assumes the following networks are created prior to running
#
# neutron net-create public --router:external --provider:network_type vlan --provider:segmentation_id 1501 --provider:physical_network physnet1
# neutron subnet-create --name subnet-public --allocation-pool start=21.0.0.10,end=21.0.0.200 public 21.0.0.0/8
#
# neutron net-create ext-net2 --router:external --provider:network_type vlan --provider:segmentation_id 2100 --provider:physical_network physnet2
# neutron subnet-create --name subnet-net2 --allocation-pool start=22.0.0.10,end=22.0.0.200 ext-net2 22.0.0.0/8
#
# neutron net-create ext-net3 --router:external --provider:network_type vlan --provider:segmentation_id 3100 --provider:physical_network physnet3
# neutron subnet-create --name subnet-net3 --allocation-pool start=23.0.0.10,end=23.0.0.200 ext-net3 23.0.0.0/8
#
#
#

import re
import collections
import time

from oslo_log import log as logging
from tempest import config as tempest_conf
from tempest.lib.common.utils import data_utils
#from tempest.services.network import resources as net_resources
from tempest.scenario import test_network_multi_node


CONF = tempest_conf.CONF

LOG = logging.getLogger(__name__)
LOG.debug("")
ICMP_HEADER_LEN = 8

Floating_IP_tuple = collections.namedtuple('Floating_IP_tuple',
                                           ['floating_ip', 'server'])


class TestASRMenBase(test_network_multi_node.TestNetworkMultiNode):

    # For setting up cfg agent client
    default_params = {
        'disable_ssl_certificate_validation':
            CONF.identity.disable_ssl_certificate_validation,
        'ca_certs': CONF.identity.ca_certificates_file,
        'trace_requests': CONF.debug.trace_requests
    }

    credentials = ['admin']

    def create_floating_ip(self, thing, external_network_id=None,
                           port_id=None, client=None):
        """Creates a floating IP and associates to a resource/port using
        Neutron client
        """
        if not external_network_id:
            external_network_id = CONF.network.public_network_id
        if not client:
            client = self.network_client
        if not port_id:
            port_id, ip4 = self._get_server_port_id_and_ip4(thing)
        else:
            ip4 = None
        result = client.create_floatingip(
            floating_network_id=external_network_id,
            port_id=port_id,
            tenant_id=thing['tenant_id'],
            fixed_ip_address=ip4
        )
        #floating_ip = net_resources.DeletableFloatingIp(
        #    client=client,
        #    **result['floatingip'])
        floating_ip = result['floatingip']
        self.addCleanup(self.delete_wrapper, floating_ip.delete)
        return floating_ip

    def _create_server(self, name, network, network_client=None,
                       networks_client=None, zone=None):
        create_kwargs = self.srv_kwargs
        create_kwargs['networks'] = [{'uuid': network.id}]
        if zone is not None:
            create_kwargs['availability_zone'] = zone
        server = self.create_server(name=name,
                                    network_client=network_client,
                                    networks_client=networks_client,
                                    wait_on_boot=True,
                                    create_kwargs=create_kwargs)
        return dict(server=server, keypair=self.keypair)

    def add_network(self, client=None, tenant_id=None, router=None,
                    vlan_transparent=False):
        network = self._create_network(client=client,
                                       tenant_id=tenant_id)
        if router is None:
            router = self._get_router(client=client,
                                      tenant_id=tenant_id)

        subnet = self._create_subnet(network=network, client=client)
        subnet.add_to_router(router.id)
        return network, subnet, router

    def verify_asrs_insync(self, project_id):
        self.verify_asrs.check_active_asr(self.segmentation_ids[0])
        self.verify_asrs.netconf_counters()
        self.verify_asrs.vrfs(self.network_client.list_routers()['routers'],
                              project_id,
                              region_id=CONF.network.region1_id)

        self.verify_asrs.nat_pool(self.network_client,
                                  project_id,
                                  region_id=CONF.network.region1_id)
        self.verify_asrs.nat_translations(self.floating_ip_tuples)
        self.verify_asrs.acls(self.network_client,
                              self.networks_client,
                              project_id,
                              self.segmentation_ids,
                              region_id=CONF.network.region1_id)
        self.verify_asrs.ext_subintf(self.network_client,
                                     self.networks_client,
                                     self.routers,
                                     project_id,
                                     region_id=CONF.network.region1_id)
        self.verify_asrs.standby_state(self.segmentation_ids)

    def verify_global_logical_rtrs(self, state='ACTIVE'):
        router_roles = ['Logical-Global', 'Global']
        routers = self._list_routers()
        num_global_rtrs = 0
        for router in routers:
            if router['routerrole:role'] in router_roles:
                num_global_rtrs += 1
                self.assertEquals('ACTIVE', str(router['status']))

        if state == 'ACTIVE':
            msg = "Incorrect number of Global/Logical routers configured"
            self.assertEquals(3, num_global_rtrs, msg)
        else:
            msg = "Global/Logical routers found when not expected"
            self.assertEquals(0, num_global_rtrs, msg)

    def verify_ext_network(self, project_id=None,
                           router=None,
                           nets=None,
                           state='ACTIVE'):

        self.verify_asrs.ext_subintf(self.network_client,
                                     self.networks_client,
                                     routers=None,
                                     tenant_id=project_id,
                                     region_id=CONF.network.region1_id)

    def setUp(self):
        pass

    def check_extnernal_nets(self):
        for net in self.external_nets:
            ext_net = self._get_network_by_name(net)

    def setup_projects(self):
        self.projects = []
        for i in range(1, len(self.external_nets) + 1):
            project_name = "Project{0}".format(i)
            project_desc = "Test Project {0}".format(i)
            self.projects.append(
                self.identity_utils.create_project(project_name,
                                                   project_desc))
        self.addCleanup(self.delete_projects)

    def setup_users(self):
        self.users = []
        i = 1
        for project in self.projects:
            user_name = "user{0}".format(i)
            i += 1
            project_name = str(project['name']).lower()
            email = "{0}@{1}.com".format(user_name, project_name)
            self.users.append((
                self.identity_utils.create_user(user_name,
                                                'cisco123',
                                                project,
                                                email), project))
        self.addCleanup(self.delete_users)

    def assign_users_role(self):
        self.identity_utils._check_role_exists('admin')
        admin_roles = [x for x in self.identity_utils._list_roles()
                       if x['name'] == 'admin']
        self.assertEquals(len(admin_roles), 1, "No Admin roles found")
        for user, project in self.users:
            self.identity_utils.assign_user_role(user,
                                                 project,
                                                 'admin')

    def create_project_roles(self):
        for user, project in self.users:
            role_name = project['name'] + "_role"
            self.identity_utils.create_user_role(role_name)
            self.identity_utils.assign_user_role(user, project, role_name)

    def create_security_groups(self):
        self.security_groups = []
        for user, project in self.users:
            security_group = self._create_security_group(
                tenant_id=project['id'])
            self.security_groups.append((user, security_group))

            try:
                self._create_loginable_secgroup_rule(
                    secgroup=security_group)
            except Exception as e:
                LOG.debug("Login sec group already exists: {0}".format(e))

    def create_vm(self, base_name, project, client_mgr, private_net,
                  public_net):
        server_name = data_utils.rand_name(base_name)

        self.keypair = self.create_keypair(client=client_mgr.keypairs_client)
        self.srv_kwargs = {'key_name': self.keypair['name']}
        my_user, security_group = self.get_security_grp(project['id'])
        my_security_group = [{'name': security_group['name']}]
        self.srv_kwargs['security_groups'] = my_security_group
        self.servers_client = client_mgr.servers_client
        vm = self._create_server(server_name,
                                 private_net,
                                 network_client=client_mgr.network_client,
                                 networks_client=client_mgr.networks_client)
        id = vm['server']['id']
        self.servers[id] = vm['keypair']
        server = {'id': vm['server']['id'],
                  'tenant_id': project['id']}
        fip = self.create_floating_ip(server, client=client_mgr.network_client,
                                      external_network_id=public_net['id'])

        self.floating_ip_tuple = Floating_IP_tuple(fip, server)
        self.floating_ip_tuples.append(self.floating_ip_tuple)

        return vm, fip

    def get_security_grp(self, project_id):
        for security_grp in self.security_groups:
            security_grp_description = security_grp[0]
            if project_id == security_grp_description['tenantId']:
                return security_grp

    def ping_vm(self, fip, should_succeed=True):
        if should_succeed:
            msg = "Timeout waiting for {0}".format(fip.floating_ip_address)
        else:
            msg = "Ping of {0} succeeded, " \
                  "expected failure".format(fip.floating_ip_address)

        self.assertTrue(self.ping_ip_address(fip.floating_ip_address,
                                             should_succeed=should_succeed),
                        msg=msg)

    def delete_users(self):
        for user, project in self.users:
            self.identity_utils.delete_user(user['id'])

    def delete_projects(self):
        for project in self.projects:
            self.identity_utils.delete_project(project['id'])

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
                success_counter = \
                    int(netconf_counters[
                            'netconf-counters.transaction-success'])
            except Exception:
                LOG.error("Unable to retrieve ASR {0} netconf counters".
                          format(asr_rtr.name))
                pass

            if success_counter < counter:
                LOG.info("Polling ASR {0} netconf "
                         "counters".format(asr_rtr.name))
                time.sleep(sleep_for)
                current_time = time.time()
            else:
                return netconf_counters

        msg = "ASR {0} netconf successful transaction counter is not " \
              "as expected".format(asr_rtr.name)
        self.assertIs(counter, success_counter, msg)

    def tidyup_asr_config(self, asr_cfg_str):
        cfg = asr_cfg_str.splitlines()
        asr_cfg = []
        blank_line = re.compile(r'([\s!])+.*')

        for line in cfg:
            if blank_line.match(line):
                continue
            asr_cfg.append(line)

        return asr_cfg

    def test_asr_men_base(self):
        pass

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

