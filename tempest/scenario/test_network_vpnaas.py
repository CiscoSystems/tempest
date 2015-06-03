# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
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

import os
import collections
import netaddr
import random
import time

from oslo_log import log as logging
from tempest_lib.common.utils import data_utils
from tempest_lib import exceptions as exc
from tempest import config
from tempest.scenario import manager
from tempest.services.network import resources as net_resources
from tempest import test

CONF = config.CONF
LOG = logging.getLogger(__name__)


# It stores information about a 'VPN Site' resources
Site = collections.namedtuple('Site',
                              'network subnet router router_ext_ip') # server '
                              #'server_floating_ip server_keypair')


class TestNetworkVpnaas(manager.NetworkScenarioTest):

    ip_version = 4
    public_network_id = CONF.network.public_network_id
    cidr = netaddr.IPNetwork(CONF.network.tenant_network_cidr)
    mask_cidr = CONF.network.tenant_network_mask_bits

    @classmethod
    def check_preconditions(cls):
        super(TestNetworkVpnaas, cls).check_preconditions()
        if not test.is_extension_enabled('vpnaas', 'network'):
            msg = "vpnaas extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def setUpClass(cls):
        cls.set_network_resources()
        super(TestNetworkVpnaas, cls).setUpClass()

    @classmethod
    def setup_clients(cls):
        super(TestNetworkVpnaas, cls).setup_clients()
        cls.network_client = cls.admin_manager.network_client

    @classmethod
    def resource_setup(cls):
        super(TestNetworkVpnaas, cls).resource_setup()

        # The list stores not used cidrs.
        cls.free_tenant_cidrs = list(cls.cidr.subnet(cls.mask_cidr))

    def site_setup(self):
        """Creates network, subnet, router and instance.
        """
        pop_random = lambda seq: seq.pop(random.randint(0, len(seq) - 1))
        ext_fixed_ip = lambda r: \
            r['external_gateway_info']['external_fixed_ips'][0]['ip_address']

        #keypair = self.create_keypair()
        #security_group = self._create_security_group()
        network = self._create_network()
        subnet, router = self.create_subnet_and_router(
            network.id, str(pop_random(self.free_tenant_cidrs)))

        #create_kwargs = {
        #    'networks': [
        #        {'uuid': network.id},
        #    ],
        #    'key_name': keypair['name'],
        #    'security_groups': [security_group],
        #}
        #server = self.create_server(create_kwargs=create_kwargs)
        #floating_ip = self.create_floating_ip(server, self.public_network_id)
        return Site(network=network, subnet=subnet, router=router,
                    router_ext_ip=ext_fixed_ip(router))
                    #router_ext_ip=ext_fixed_ip(router), server=server,
                    #server_floating_ip=floating_ip, server_keypair=keypair)

    def create_subnet_and_router(self, network_id, subnet_cidr):
        subnet = self.network_client.create_subnet(
            network_id=network_id, cidr=subnet_cidr,
            name=data_utils.rand_name("subnet-"),
            ip_version=self.ip_version)
        subnet = net_resources.DeletableSubnet(client=self.network_client,
                                               **subnet['subnet'])

        router = self._create_router()

        # Wait for CSR1kv router
        for i in range(10):
            time.sleep(60)

        router.set_gateway(self.public_network_id)
        time.sleep(20)
        subnet.add_to_router(router.id)
        time.sleep(20)
        self.addCleanup(self.delete_wrapper, subnet.delete)
        return subnet, router

    def create_ipsecpolicy(self):
        name = data_utils.rand_name("ipsec-")
        body = self.network_client.create_ipsecpolicy(name=name)
        ipsecpolicy = body['ipsecpolicy']
        self.addCleanup(
            self.network_client.delete_ipsecpolicy, ipsecpolicy['id'])
        return ipsecpolicy

    def create_ikepolicy(self):
        name = data_utils.rand_name("ike-")
        body = self.network_client.create_ikepolicy(name=name)
        ikepolicy = body['ikepolicy']
        self.addCleanup(
            self.network_client.delete_ikepolicy, ikepolicy['id'])
        return ikepolicy

    def create_vpnservice(self, subnet_id, router_id):
        name = data_utils.rand_name("vpn-")
        body = self.network_client.create_vpnservice(
            subnet_id=subnet_id, router_id=router_id, admin_state_up=True,
            name=name)
        vpnservice = body['vpnservice']
        self.addCleanup(
            self.network_client.delete_vpnservice, vpnservice['id'])
        return vpnservice

    def create_ipsec_site_connection(self, vpn_id, ike_id, ipsec_id,
                                     peer_gateway, peer_router, peer_subnets,
                                     secret):
        name = data_utils.rand_name("conn-")
        body = self.network_client.create_ipsec_site_connection(
            name=name, vpnservice_id=vpn_id, ikepolicy_id=ike_id,
            ipsecpolicy_id=ipsec_id, peer_address=peer_gateway,
            peer_id=peer_router, peer_cidrs=peer_subnets, psk=secret)
        ipsec_site_connection = body['ipsec_site_connection']
        self.addCleanup(
            self.network_client.delete_ipsec_site_connection,
            ipsec_site_connection['id'])
        return ipsec_site_connection

    def show_ipsec_site_connection(self, id):
        body = self.network_client.show_ipsec_site_connection(id)
        ipsec_site_connection = body['ipsec_site_connection']
        return ipsec_site_connection

    def wait_ipsec_site_connection(self, site_id, status=None):
        def _wait():
            conn = self.show_ipsec_site_connection(site_id)
            return conn['status'] == status

        try:
            if not test.call_until_true(_wait, CONF.network.build_timeout,
                                        CONF.network.build_interval):
                m = ("Timed out waiting for ipsec site connection %s "
                     "to reach %s state" % (site_id, status))
                raise exc.TimeoutException(m)
            return self.show_ipsec_site_connection(site_id)
        except exc.NotFound as ex:
            if status:
                raise ex

    def _ping(self, namespace, ip):
        """Pings ip address from network namespace.
        In order to ping it uses following cli command:
            ip netns exec <namespace> ping -c 4 -q <ip>
        """
        try:
            cmd = ['sudo', 'ip', 'netns', 'exec', namespace,
                   'ping', '-c', '4', '-q', ip]
            ping_cmd = ' '.join(cmd)
            return_code = os.system(ping_cmd)
            return return_code is 0
        except RuntimeError:
            return False

    def check_sites_connectivity(self, source_site, dest_site):
        """Test connectivity from source_site to dest_site. It tries to ping
           instance of destination site from an instance of source site
        """
        # In the scenario ip address of a dhcp port is .2
        source_dhcp_namespace = 'qdhcp-{0}'.format(source_site.network.id)
        dest_dhcp_port_ip = str(netaddr.IPNetwork(dest_site.subnet.cidr)[2])

        self.assertTrue(
            self._ping(source_dhcp_namespace, dest_dhcp_port_ip),
            "'Failed to ping IP: %s via a ssh connection from dhcp namespace: %s.'" %
            (dest_dhcp_port_ip, source_dhcp_namespace))

    @test.services('compute', 'network')
    def test_ipsec_site_connections(self):
        """The test verifies that it is possible to establish a vpn
           connection between two sites. And then it performs basic
           connectivity test, it pings instance of site2 from instance
           of site1 and vice versa.
        """
        site1 = self.site_setup()
        site2 = self.site_setup()

        ike1 = self.create_ikepolicy()
        ipsec1 = self.create_ipsecpolicy()
        vpn1 = self.create_vpnservice(subnet_id=site1.subnet['id'],
                                      router_id=site1.router['id'])

        ike2 = self.create_ikepolicy()
        ipsec2 = self.create_ipsecpolicy()
        vpn2 = self.create_vpnservice(subnet_id=site2.subnet['id'],
                                      router_id=site2.router['id'])

        secret = data_utils.rand_name()
        conn1 = self.create_ipsec_site_connection(
            vpn_id=vpn1['id'], ike_id=ike1['id'], ipsec_id=ipsec1['id'],
            peer_gateway=site2.router_ext_ip,
            peer_router=site2.router_ext_ip,
            peer_subnets=site2.subnet['cidr'], secret=secret)
        conn2 = self.create_ipsec_site_connection(
            vpn_id=vpn2['id'], ike_id=ike2['id'],
            ipsec_id=ipsec2['id'],
            peer_gateway=site1.router_ext_ip,
            peer_router=site1.router_ext_ip,
            peer_subnets=site1.subnet['cidr'], secret=secret)

        #self.wait_ipsec_site_connection(conn1['id'], 'ACTIVE')
        #self.wait_ipsec_site_connection(conn2['id'], 'ACTIVE')

        time.sleep(60)
        self.check_sites_connectivity(site1, site2)
        self.check_sites_connectivity(site2, site1)
