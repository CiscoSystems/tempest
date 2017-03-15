# Copyright 2012 OpenStack Foundation
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

from tempest.api.volume import base
from tempest.common import waiters
from tempest.lib import decorators


class VolumesV2ExtendTest(base.BaseVolumeTest):

    @decorators.idempotent_id('9a36df71-a257-43a5-9555-dc7c88e66e0e')
    def test_volume_extend(self):
        # Extend Volume Test.
        volume = self.create_volume()
        extend_size = volume['size'] + 1
        self.volumes_client.extend_volume(volume['id'],
                                          new_size=extend_size)
        waiters.wait_for_volume_resource_status(self.volumes_client,
                                                volume['id'], 'available')
        volume = self.volumes_client.show_volume(volume['id'])['volume']
        self.assertEqual(volume['size'], extend_size)
