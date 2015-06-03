from testtools.testcase import skip
import time
import logging
import netaddr
import random
from tempest import config, test
from tempest_lib import exceptions as lib_exc
from tempest_lib.common.utils import data_utils
from tempest.services.network import resources as net_resources
from tempest.scenario import manager

CONF = config.CONF
LOG = logging.getLogger(__name__)


class TestNetworkFwaasOps(manager.NetworkScenarioTest):
    """
        Scenario tests for FWaaS

        Tested parameters and options:
            * Protocols: TCP, UDP, None (ANY)
            * Actions: ALLOW, DENY
            * Source IP address
            * Destination IP address
            * Source port
            * Destination port
            * Firewall state: UP, DOWN
            * Firewall policy
            * Rule state: Enabled, Disabled
    """

    protocols = ['udp', 'tcp']
    msg = 'Hello there!'
    port = 5000

    st_active = 'ACTIVE'
    st_down = 'DOWN'

    @classmethod
    def check_preconditions(cls):
        super(TestNetworkFwaasOps, cls).check_preconditions()
        if not CONF.network.public_network_id:
            msg = 'Public_network_id must be defined.'
            raise cls.skipException(msg)
        if not test.is_extension_enabled('fwaas', 'network'):
            msg = "FWaaS extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def setUpClass(cls):
        cls.set_network_resources()
        super(TestNetworkFwaasOps, cls).setUpClass()

    @classmethod
    def setup_clients(cls):
        super(TestNetworkFwaasOps, cls).setup_clients()
        cls.network_client = cls.admin_manager.network_client

    @classmethod
    def resource_setup(cls):
        # Create no network resources for these tests.
        super(TestNetworkFwaasOps, cls).resource_setup()

        cls.create_networks()

    @classmethod
    def resource_cleanup(cls):
        super(TestNetworkFwaasOps, cls).resource_cleanup()

        if hasattr(cls, 'subnet'):
            cls.subnet.delete()
        if hasattr(cls, 'network'):
            cls.network.delete()
        if hasattr(cls, 'router'):
            cls.router.delete()

    @classmethod
    def _create_network(cls, client=None, namestart='network-smoke-'):
        if not client:
            client = cls.network_client
        name = data_utils.rand_name(namestart)
        result = client.create_network(name=name)
        cls.network = net_resources.DeletableNetwork(client=client,
                                                     **result['network'])
        return cls.network

    @classmethod
    def _create_router(cls, client=None, namestart='router-smoke'):
        if not client:
            client = cls.network_client
        name = data_utils.rand_name(namestart)
        result = client.create_router(name=name, admin_state_up=True)
        cls.router = net_resources.DeletableRouter(client=client,
                                                   **result['router'])
        return cls.router

    @classmethod
    def _get_router(cls, client=None):
        """Retrieve a router for the given tenant id.

        If a public router has been configured, it will be returned.

        If a public router has not been configured, but a public
        network has, a tenant router will be created and returned that
        routes traffic to the public network.
        """
        if not client:
            client = cls.network_client
        network_id = CONF.network.public_network_id
        router = cls._create_router(client)

        # Wait for CSR1kv router
        time.sleep(60 * 10)

        router.set_gateway(network_id)
        time.sleep(20)
        return router

    @classmethod
    def _admin_lister(cls, resource_type):
        def temp(*args, **kwargs):
            temp_method = cls.admin_manager.network_client.__getattr__(
                'list_%s' % resource_type)
            resource_list = temp_method(*args, **kwargs)
            return resource_list[resource_type]
        return temp

    @classmethod
    def _create_subnet(cls, network, client=None, namestart='subnet-smoke',
                       **kwargs):
        """
        Create a subnet for the given network within the cidr block
        configured for tenant networks.
        """
        if not client:
            client = cls.network_client

        def cidr_in_use(cidr, tenant_id):
            """
            :return True if subnet with cidr already exist in tenant
                False else
            """
            cidr_in_use = cls._admin_lister('subnets')(tenant_id=tenant_id,
                                                       cidr=cidr)
            return len(cidr_in_use) != 0

        tenant_cidr = netaddr.IPNetwork(CONF.network.tenant_network_cidr)
        num_bits = CONF.network.tenant_network_mask_bits

        result = None
        str_cidr = None
        # Repeatedly attempt subnet creation with sequential cidr
        # blocks until an unallocated block is found.
        for subnet_cidr in tenant_cidr.subnet(num_bits):
            str_cidr = str(subnet_cidr)
            if cidr_in_use(str_cidr, tenant_id=network.tenant_id):
                continue

            subnet = dict(
                name=data_utils.rand_name(namestart),
                network_id=network.id,
                tenant_id=network.tenant_id,
                cidr=str_cidr,
                ip_version=4,
                **kwargs
            )
            try:
                result = client.create_subnet(**subnet)
                break
            except lib_exc.Conflict as e:
                is_overlapping_cidr = 'overlaps with another subnet' in str(e)
                if not is_overlapping_cidr:
                    raise
        cls.subnet = net_resources.DeletableSubnet(client=client,
                                                   **result['subnet'])
        return cls.subnet

    @classmethod
    def create_networks(cls, client=None):
        """Create a network with a subnet connected to a router.

        The baremetal driver is a special case since all nodes are
        on the same shared network.

        :param client: network client to create resources with.
        :param tenant_id: id of tenant to create resources in.
        :param dns_nameservers: list of dns servers to send to subnet.
        :returns: network, subnet, router
        """
        if not client:
            client = cls.network_client
        network = cls._create_network(client=client)
        router = cls._get_router(client=client)
        subnet = cls._create_subnet(client=client, network=network)
        response = subnet.add_to_router(router.id)
        cls.router_port_id = response['port_id']
        time.sleep(20)
        return network, subnet, router, cls.router_port_id

    # def _setup_servers(self):
    #     self.keypair = self.create_keypair()
    #     #security_group = self._create_security_group()
    #
    #     # wait for csr1kv
    #     #time.sleep(60 * 6)
    #     public_network_id = CONF.network.public_network_id
    #     create_kwargs = {
    #         'networks': [
    #             {'uuid': self.network.id},
    #         ],
    #         'key_name': self.keypair['name'],
    #         'security_groups': [security_group],
    #     }
    #     # Create two servers with floating ip.
    #     # They will be used to test connectivity
    #     self.servers = list()
    #     self.floating_ips = list()
    #     for i in range(2):
    #         server = self.create_server(create_kwargs=create_kwargs)
    #         floating_ip = self.create_floating_ip(server, public_network_id)
    #
    #         self.floating_ips.append(floating_ip)
    #         self.servers.append(server)

    def _show_firewall(self, id):
        body = self.network_client.show_firewall(id)
        return body['firewall']

    def _create_firewall(self, policy, state_up=True):
        body = self.network_client.create_firewall(
            name=data_utils.rand_name("firewall"), admin_state_up=state_up,
            firewall_policy_id=policy['id'], #router_ids=[self.router.id],
            port_id=self.router_port_id, direction='both')
        firewall = body['firewall']
        expected_status = self.st_active if state_up else self.st_down
        firewall = self._wait_firewall(firewall['id'], expected_status)
        self.addCleanup(self._delete_firewall, firewall['id'])
        return firewall

    def _delete_firewall(self, id):
        self.network_client.delete_firewall(id)
        self._wait_firewall(id)

    def _wait_firewall(self, id, status=None):
        """ Waits until a firewall gets desired status
        :param id: firewall id
        :param status: expected status
        :return: firewall dictionary
        """
        def _wait():
            body = self.network_client.show_firewall(id)
            firewall = body['firewall']
            if firewall['status'] == 'ERROR':
                raise Exception('Firewall status is {0}'.format(
                    firewall['status']))
            return firewall['status'] == status

        try:
            if not test.call_until_true(_wait, CONF.network.build_timeout,
                                        CONF.network.build_interval):
                m = ("Timed out waiting for firewall %s to reach %s state" %
                     (id, status))
                raise lib_exc.TimeoutException(m)
            return self._show_firewall(id)
        except lib_exc.NotFound as ex:
            if status:
                raise ex

    def _create_firewall_with_rules(self, firewall_rules=None):
        fr = firewall_rules or list()
        policy = self._create_policy(firewall_rules=fr)
        firewall = self._create_firewall(policy)
        return firewall

    def _create_policy(self, name=None, **kwargs):
        # A firewall rule to allow ssh to instances
        ssh_rule = self._create_rule(name='ssh_allow', action='allow',
                                     protocol='tcp', enabled=True,
                                     destination_port=22)
        # Inject "ssh allow" rule
        kwargs['firewall_rules'] = kwargs.get('firewall_rules', list())
        kwargs['firewall_rules'].insert(0, ssh_rule['id'])

        body = self.network_client.create_firewall_policy(
            name=name or data_utils.rand_name("fw-policy"),
            **kwargs)
        policy = body['firewall_policy']
        self.addCleanup(
            self.network_client.delete_firewall_policy, policy['id'])
        return policy

    def _update_policy(self, policy_id, **kwargs):
        """ Proxy method to inject "ssh allow" rule
        """
        body = self.network_client.show_firewall_policy(policy_id)
        policy = body['firewall_policy']
        # 'ssh rule' was added in '_create_policy' method at 0 position
        rules = policy['firewall_rules'][:1]
        rules.extend(kwargs.get('firewall_rules', list()))
        kwargs['firewall_rules'] = rules

        body = self.network_client.update_firewall_policy(policy_id, **kwargs)
        return body['firewall_policy']

    def _create_rule(self, name=None, **kwargs):
        body = self.network_client.create_firewall_rule(
            name=name or data_utils.rand_name("fw-rule"),
            **kwargs)
        rule = body['firewall_rule']
        self.addCleanup(self.network_client.delete_firewall_rule, rule['id'])
        return rule

    def _send_msg(self, protocol, source_port, dest_port, reverse=False):
        """ Send messsage from server #1 to server #2 using 'nc' command
        """
        private_key = self.keypair['private_key']
        # It is going to send message from floating ip of ...
        if reverse:
            # ... server #2 to floating ip of server #1
            source_ip = self.floating_ips[1]['floating_ip_address']
            dest_ip = self.floating_ips[0]['floating_ip_address']
        else:
            # ... server #1 to floating ip of server #2
            source_ip = self.floating_ips[0]['floating_ip_address']
            dest_ip = self.floating_ips[1]['floating_ip_address']

        ssh_source = self._ssh_to_server(source_ip, private_key)
        ssh_dest = self._ssh_to_server(dest_ip, private_key)
        # The server #2 listens on fixed ip
        listen_ip = self.floating_ips[1]['fixed_ip_address']

        nc = 'nc %s' % ('-u' if protocol == 'udp' else '')
        # Run listener
        ssh_dest.exec_command('kill -9 `pidof "nc"` || true')
        ssh_dest.exec_command('%s -l -p %s -s %s > out.log &' %
                              (nc, dest_port, listen_ip))
        # Send message
        ssh_source.exec_command(
            'echo -n "%s" | %s -w1 -p %s %s %s || true' %
            (self.msg, nc, source_port, dest_ip, dest_port))
        # Read received message
        received = ssh_dest.exec_command("cat out.log; rm out.log")
        return received == self.msg

    def _test_allow_protocol(self, protocol):
        """  Tests 'ALLOW' action for protocols
             1. Creates 'allow' rule for each protocol
             2. Updates a policy with a rule
             3. Sends message via allowed protocol
             4. Tried to send message via blocked protocol
        """
        #self._setup_servers()
        rule = self._create_rule(
            action='allow', protocol=protocol, enabled=True)
        self._create_firewall_with_rules(firewall_rules=[rule['id']])
        # for p in self.protocols:
        #     if protocol == p:
        #         self.assertTrue(
        #             self._send_msg(p, self.port, self.port),
        #             "Firewall allows %s protocol" % p)
        #     else:
        #         self.assertFalse(
        #             self._send_msg(p, self.port, self.port),
        #             "Firewall blocks %s protocol by default" % p)

    @skip('Known issue. CSR RESP API does not support "any". I think I will '
          'map "protocol any" to "protocol all"')
    def test_allow_any(self):
        #self._setup_servers()
        allow_any_rule = self._create_rule(
            action='allow', protocol=None, enabled=True)
        self._create_firewall_with_rules(
            firewall_rules=[allow_any_rule['id']])
        for p in self.protocols:
            self.assertTrue(
                self._send_msg(p, self.port, self.port),
                "Firewall allows %s protocol." % p)

    def test_allow_protocol_udp(self):
        self._test_allow_protocol('udp')

    def test_allow_protocol_tcp(self):
        self._test_allow_protocol('tcp')

    def test_allow_ports(self):
        """ Tests 'ALLOW' action for ports
            1. Creates allow rule for a random source port, destination port
            2. Updates a policy with the created rule
            3. Sends message from allowed port to allowed port
            4. Tries to send message from random port
            5. Tries to send message to random port
        """
        #self._setup_servers()
        port = random.randint(4500, 5500)
        blocked_port = port + random.randint(-1000, 1000)
        protocol = random.choice(self.protocols)
        rule = self._create_rule(
            action='allow', protocol=protocol, enabled=True,
            destination_port=port,
            source_port=port)
        self._create_firewall_with_rules(firewall_rules=[rule['id']])
        # self.assertTrue(self._send_msg(protocol, port, port),
        #                 "Protocol %s. Firewall allows source port %s, "
        #                 "dest port %s" % (protocol, port, port))
        # self.assertFalse(self._send_msg(protocol, blocked_port, port),
        #                 "Protocol %s. Other source port %s is blocked"
        #                  % (protocol, blocked_port))
        # self.assertFalse(self._send_msg(protocol, port, blocked_port),
        #                 "Protocol %s. Other dest port %s is blocked"
        #                  % (protocol, blocked_port))

    def test_allow_addresses(self):
        """ Tests 'ALLOW' action for addresses
            1. Creates an allow rule with source ip = fixed ip of instance #1
            2. Creates an allow rule with dest ip = floating ip of instance #2
            3. Updates a policy with the created rules
            4. Sends message from instance #1 to instance #2
            5. Tries to send message from instance #2 to instance #1
        """
        # self._setup_servers()
        protocol = random.choice(self.protocols)
        # Create firewall rules for a addresses
        rules = list()
        rules.append(self._create_rule(
            action='allow', protocol=protocol, enabled=True,
            source_ip_address='10.0.11.0/24'))
            # source_ip_address=self.floating_ips[0]['floating_ip_address']))
        rules.append(self._create_rule(
            action='allow', protocol=protocol, enabled=True,
            destination_ip_address='10.0.197.0/24'))
            # destination_ip_address=self.floating_ips[1]['fixed_ip_address']))
        self._create_firewall_with_rules(firewall_rules=[r['id'] for r in rules])
        # self.assertTrue(self._send_msg(protocol, self.port, self.port),
        #                 "Protocol %s. Firewall allows traffic "
        #                 "from instance #1, to instance #2 " % protocol)
        # self.assertFalse(
        #     self._send_msg(protocol, self.port, self.port, reverse=True),
        #     "Protocol %s. Firewall does not allow traffic "
        #     "from instance #2, to instance #1 " % protocol)

    def test_deny_protocols(self):
        """ Tests 'DENY' action
            1. Creates 'allow any' rule
            2. Creates deny rules for each protocol
            3. Create firewall
            4. Tries to send message via each protocol
        """
        # self._setup_servers()
        # allow_any_rule = self._create_rule(
        #     action='allow', protocol=None, enabled=True)
        rules = list()
        for protocol in self.protocols:
            rules.append(self._create_rule(
                action='deny', protocol=protocol, enabled=True))
        # "Deny rules" are placed before "allow any" rule
        self._create_firewall_with_rules(
            firewall_rules=[r['id'] for r in rules])
            # firewall_rules=[r['id'] for r in rules] + [allow_any_rule['id']])
        # for p in self.protocols:
        #     self.assertFalse(
        #         self._send_msg(p, self.port, self.port),
        #         "Firewall blocks %s protocol." % p)

    @skip('Can not add ACE: error-message Add ACE failure, ONEP_FAIL')
    def test_enable_disable_firewall_and_rule(self):
        """ Tests 'ENABLED' property of a firewall and a rule
            1. Creates allow rules with Enabled=True (protocol #1)
            2. Creates allow rule with Enabled=False (protocol #2)
            3. Updates a policy with created rules
            4. Creates a firewall with State_up=False, uses created policy
            5. Enables the firewall (set State_up=True)
            6. Sends message via protocol #1
            7. Tries to send message via protocol #2
            8. Enable disabled rule (protocol #2)
            9. Sends message via protocol #2
            10. Disables enabled rule (protocol #1)
            11. Tries to send message via protocol #1
            12. Disables firewall
            13. Verifies status of the firewall
        """
        # self._setup_servers()

        protocols = list(self.protocols)
        random.shuffle(protocols)
        protocol_enabled = protocols[0]
        protocol_disabled = protocols[1]
        rule_enabled = self._create_rule(
            action='allow', protocol=protocol_enabled, enabled=True)
        rule_disabled = self._create_rule(
            action='allow', protocol=protocol_disabled, enabled=False)

        policy = self._create_policy(
            firewall_rules=[rule_enabled['id'], rule_disabled['id']])
        firewall = self._create_firewall(policy, state_up=False)
        firewall_id = firewall['id']

        self.assertEqual(self.st_down, firewall['status'], "Firewall is DOWN")

        # Enable firewall
        self.network_client.update_firewall(firewall_id, admin_state_up=True)
        self._wait_firewall(firewall_id, self.st_active)
        # self.assertTrue(self._send_msg(protocol_enabled,
        #                                self.port, self.port),
        #                 "Firewall is ACTIVE. "
        #                 "The rule is ENABLED. %s" % rule_enabled)
        # self.assertFalse(self._send_msg(protocol_disabled,
        #                                 self.port, self.port),
        #                  "Firewall is ACTIVE. "
        #                  "The rule is DISABLED. %s" % rule_disabled)
        # Enable rule
        body = self.network_client.update_firewall_rule(
            rule_disabled['id'], enabled=True)
        self._wait_firewall(firewall_id, self.st_active)
        # self.assertTrue(self._send_msg(protocol_disabled,
        #                                self.port, self.port),
        #                 "The rule is ENABLED. %s" % body)
        # Disable rule
        body = self.network_client.update_firewall_rule(
            rule_enabled['id'], enabled=False)
        self._wait_firewall(firewall_id, self.st_active)
        # self.assertFalse(self._send_msg(protocol_enabled,
        #                                 self.port, self.port),
        #                  "The rule is DISABLED. %s" % body)
        # Disable firewall
        self.network_client.update_firewall(firewall_id, admin_state_up=False)
        self._wait_firewall(firewall_id, self.st_down)

    @skip('Can not add ACE: error-message Add ACE failure, ONEP_FAIL')
    def test_replace_firewall_policy_and_replace_rules(self):
        """ Tests replacing a policy and replacing rule
            1. Creates two 'allow rules'
            2. Creates two policies. One policy for each rule
            3. Creates a firewall with first policy
            4. Sends message. Verify the policy works
            5. Changes the firewall policy to second policy
            6. Sends message. Verifies the second policy is enabled
            7. Tries to send message. Verifies the first policy is disabled
            8. Replaces rule of second policy with with rule of first policy
            9. Sends message. Verifies the rule of first policy is in use
            10. Tries to send message. Verify the rule has been replaced
        """
        # self._setup_servers()

        protocols = list(self.protocols)
        random.shuffle(protocols)
        rule1 = self._create_rule(
            action='allow', protocol=protocols[0], enabled=True)
        rule2 = self._create_rule(
            action='allow', protocol=protocols[1], enabled=True)

        policy1 = self._create_policy(firewall_rules=[rule1['id']])
        policy2 = self._create_policy(firewall_rules=[rule2['id']])
        firewall = self._create_firewall(policy1)

        # self.assertTrue(self._send_msg(rule1['protocol'],
        #                                self.port, self.port),
        #                 "Policy #1 is applied. %s" % policy1)
        # Change firewall policy
        self.network_client.update_firewall(firewall['id'],
                                            firewall_policy_id=policy2['id'])
        self._wait_firewall(firewall['id'], self.st_active)

        # self.assertTrue(self._send_msg(rule2['protocol'],
        #                                self.port, self.port),
        #                 "Policy #2 is applied. %s" % policy2)
        # self.assertFalse(self._send_msg(rule1['protocol'],
        #                                 self.port, self.port),
        #                  "Policy #1 is not applied. %s" % policy1)

        # Delete rule #1 from policy #1 to make it to be available
        self.network_client.remove_firewall_rule_from_policy(
            policy1['id'], rule1['id'])
        # Replace rule with another one
        self.network_client.insert_firewall_rule_in_policy(
            policy2['id'], rule1['id'], '', rule2['id'])
        self._wait_firewall(firewall['id'], self.st_active)
        self.network_client.remove_firewall_rule_from_policy(
            policy2['id'], rule2['id'])
        self._wait_firewall(firewall['id'], self.st_active)
        # self.assertTrue(self._send_msg(rule1['protocol'],
        #                                self.port, self.port),
        #                 "Rule #1 has been added. %s" % rule1)
        # self.assertFalse(self._send_msg(rule2['protocol'],
        #                                 self.port, self.port),
        #                  "Rule #2 has been removed. %s" % rule2)
