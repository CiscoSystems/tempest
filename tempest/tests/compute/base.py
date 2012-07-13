# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack, LLC
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

import logging
import time

import unittest2 as unittest

from tempest import config
from tempest import exceptions
from tempest import openstack
from tempest.common.utils.data_utils import rand_name
from tempest.services.identity.json.admin_client import AdminClient

LOG = logging.getLogger(__name__)


class BaseComputeTest(unittest.TestCase):

    """Base test case class for all Compute API tests"""

    @classmethod
    def setUpClass(cls):
        cls.config = config.TempestConfig()
        cls.isolated_creds = []

        if cls.config.compute.allow_tenant_isolation:
            creds = cls._get_isolated_creds()
            username, tenant_name, password = creds
            os = openstack.Manager(username=username,
                                   password=password,
                                   tenant_name=tenant_name)
        else:
            os = openstack.Manager()

        cls.os = os
        cls.servers_client = os.servers_client
        cls.flavors_client = os.flavors_client
        cls.images_client = os.images_client
        cls.extensions_client = os.extensions_client
        cls.floating_ips_client = os.floating_ips_client
        cls.keypairs_client = os.keypairs_client
        cls.security_groups_client = os.security_groups_client
        cls.console_outputs_client = os.console_outputs_client
        cls.limits_client = os.limits_client
        cls.volumes_client = os.volumes_client
        cls.build_interval = cls.config.compute.build_interval
        cls.build_timeout = cls.config.compute.build_timeout
        cls.ssh_user = cls.config.compute.ssh_user
        cls.image_ref = cls.config.compute.image_ref
        cls.image_ref_alt = cls.config.compute.image_ref_alt
        cls.flavor_ref = cls.config.compute.flavor_ref
        cls.flavor_ref_alt = cls.config.compute.flavor_ref_alt
        cls.servers = []

    @classmethod
    def _get_identity_admin_client(cls):
        """
        Returns an instance of the Identity Admin API client
        """
        client_args = (cls.config,
                       cls.config.identity_admin.username,
                       cls.config.identity_admin.password,
                       cls.config.identity.auth_url)
        tenant_name = cls.config.identity_admin.tenant_name
        admin_client = AdminClient(*client_args, tenant_name=tenant_name)
        return admin_client

    @classmethod
    def _get_isolated_creds(cls):
        """
        Creates a new set of user/tenant/password credentials for a
        **regular** user of the Compute API so that a test case can
        operate in an isolated tenant container.
        """
        admin_client = cls._get_identity_admin_client()
        rand_name_root = cls.__name__ + '-tempest'
        if cls.isolated_creds:
            # Main user already created. Create the alt one...
            rand_name_root += '-alt'
        username = rand_name_root + "-user"
        email = rand_name_root + "@example.com"
        tenant_name = rand_name_root + "-tenant"
        tenant_desc = tenant_name + "-desc"
        password = "pass"

        resp, tenant = admin_client.create_tenant(name=tenant_name,
                                                  description=tenant_desc)
        resp, user = admin_client.create_user(username,
                                              password,
                                              tenant['id'],
                                              email)
        # Store the complete creds (including UUID ids...) for later
        # but return just the username, tenant_name, password tuple
        # that the various clients will use.
        cls.isolated_creds.append((user, tenant))

        return username, tenant_name, password

    @classmethod
    def clear_isolated_creds(cls):
        if not cls.isolated_creds:
            pass
        admin_client = cls._get_identity_admin_client()

        for user, tenant in cls.isolated_creds:
            admin_client.delete_user(user['id'])
            admin_client.delete_tenant(tenant['id'])

    @classmethod
    def tearDownClass(cls):
        cls.clear_isolated_creds()

    def create_server(self, image_id=None):
        """Wrapper utility that returns a test server"""
        server_name = rand_name(self.__class__.__name__ + "-instance")
        flavor = self.flavor_ref
        if not image_id:
            image_id = self.image_ref

        resp, server = self.servers_client.create_server(
                                                server_name, image_id, flavor)
        self.servers_client.wait_for_server_status(server['id'], 'ACTIVE')
        self.servers.append(server)
        return server

    def wait_for(self, condition):
        """Repeatedly calls condition() until a timeout"""
        start_time = int(time.time())
        while True:
            try:
                condition()
            except:
                pass
            else:
                return
            if int(time.time()) - start_time >= self.build_timeout:
                condition()
                return
            time.sleep(self.build_interval)


class BaseComputeAdminTest(unittest.TestCase):

    """Base test case class for all Compute Admin API tests"""

    @classmethod
    def setUpClass(cls):
        cls.config = config.TempestConfig()
        cls.admin_username = cls.config.compute_admin.username
        cls.admin_password = cls.config.compute_admin.password
        cls.admin_tenant = cls.config.compute_admin.tenant_name

        if not cls.admin_username and cls.admin_password and cls.admin_tenant:
            msg = ("Missing Compute Admin API credentials "
                   "in configuration.")
            raise nose.SkipTest(msg)

        cls.os = openstack.AdminManager()
