# Copyright (c) 2014 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest

from swift3.response import AccessDenied
from swift3.subresource import User, AuthenticatedUsers, AllUsers, \
    ACLPrivate, ACLPublicRead, ACLPublicReadWrite, ACLAuthenticatedRead, \
    ACLBucketOwnerRead, ACLBucketOwnerFullControl, Owner, ACL


class TestSwift3Subresource(unittest.TestCase):
    def test_acl_canonical_user(self):
        grantee = User('test:tester')

        self.assertTrue('test:tester' in grantee)
        self.assertTrue('test:tester2' not in grantee)
        self.assertEquals(str(grantee), 'test:tester')
        self.assertEquals(grantee.elem().find('./ID').text, 'test:tester')

    def test_acl_authenticated_users(self):
        grantee = AuthenticatedUsers()

        self.assertTrue('test:tester' in grantee)
        self.assertTrue('test:tester2' in grantee)
        uri = 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
        self.assertEquals(grantee.elem().find('./URI').text, uri)

    def test_acl_all_users(self):
        grantee = AllUsers()

        self.assertTrue('test:tester' in grantee)
        self.assertTrue('test:tester2' in grantee)
        uri = 'http://acs.amazonaws.com/groups/global/AllUsers'
        self.assertEquals(grantee.elem().find('./URI').text, uri)

    def check_permission(self, acl, user_id, permission):
        try:
            acl.check_permission(user_id, permission)
            return True
        except AccessDenied:
            return False

    def test_acl_private(self):
        acl = ACLPrivate(Owner(id='test:tester',
                               name='test:tester'))

        self.assertTrue(self.check_permission(acl, 'test:tester', 'READ'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'WRITE'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'READ_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'WRITE_ACP'))
        self.assertFalse(self.check_permission(acl, 'test:tester2', 'READ'))
        self.assertFalse(self.check_permission(acl, 'test:tester2', 'WRITE'))
        self.assertFalse(self.check_permission(acl, 'test:tester2',
                                               'READ_ACP'))
        self.assertFalse(self.check_permission(acl, 'test:tester2',
                                               'WRITE_ACP'))

    def test_acl_public_read(self):
        acl = ACLPublicRead(Owner(id='test:tester',
                                  name='test:tester'))

        self.assertTrue(self.check_permission(acl, 'test:tester', 'READ'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'WRITE'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'READ_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'WRITE_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester2', 'READ'))
        self.assertFalse(self.check_permission(acl, 'test:tester2', 'WRITE'))
        self.assertFalse(self.check_permission(acl, 'test:tester2',
                                               'READ_ACP'))
        self.assertFalse(self.check_permission(acl, 'test:tester2',
                                               'WRITE_ACP'))

    def test_acl_public_read_write(self):
        acl = ACLPublicReadWrite(Owner(id='test:tester',
                                       name='test:tester'))

        self.assertTrue(self.check_permission(acl, 'test:tester', 'READ'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'WRITE'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'READ_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'WRITE_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester2', 'READ'))
        self.assertTrue(self.check_permission(acl, 'test:tester2', 'WRITE'))
        self.assertFalse(self.check_permission(acl, 'test:tester2',
                                               'READ_ACP'))
        self.assertFalse(self.check_permission(acl, 'test:tester2',
                                               'WRITE_ACP'))

    def test_acl_authenticated_read(self):
        acl = ACLAuthenticatedRead(Owner(id='test:tester',
                                         name='test:tester'))

        self.assertTrue(self.check_permission(acl, 'test:tester', 'READ'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'WRITE'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'READ_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'WRITE_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester2', 'READ'))
        self.assertFalse(self.check_permission(acl, 'test:tester2', 'WRITE'))
        self.assertFalse(self.check_permission(acl, 'test:tester2',
                                               'READ_ACP'))
        self.assertFalse(self.check_permission(acl, 'test:tester2',
                                               'WRITE_ACP'))

    def test_acl_bucket_owner_read(self):
        acl = ACLBucketOwnerRead(
            bucket_owner=Owner('test:tester2', 'test:tester2'),
            object_owner=Owner('test:tester', 'test:tester'))

        self.assertTrue(self.check_permission(acl, 'test:tester', 'READ'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'WRITE'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'READ_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'WRITE_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester2', 'READ'))
        self.assertFalse(self.check_permission(acl, 'test:tester2', 'WRITE'))
        self.assertFalse(self.check_permission(acl, 'test:tester2',
                                               'READ_ACP'))
        self.assertFalse(self.check_permission(acl, 'test:tester2',
                                               'WRITE_ACP'))

    def test_acl_bucket_owner_full_control(self):
        acl = ACLBucketOwnerFullControl(
            bucket_owner=Owner('test:tester2', 'test:tester2'),
            object_owner=Owner('test:tester', 'test:tester'))

        self.assertTrue(self.check_permission(acl, 'test:tester', 'READ'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'WRITE'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'READ_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'WRITE_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester2', 'READ'))
        self.assertTrue(self.check_permission(acl, 'test:tester2', 'WRITE'))
        self.assertTrue(self.check_permission(acl, 'test:tester2', 'READ_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester2',
                                              'WRITE_ACP'))

    def test_acl_elem(self):
        acl = ACLPrivate(Owner(id='test:tester',
                               name='test:tester'))
        elem = acl.elem()
        self.assertTrue(elem.find('./Owner') is not None)
        self.assertTrue(elem.find('./AccessControlList') is not None)
        grants = [e for e in elem.findall('./AccessControlList/Grant')]
        self.assertEquals(len(grants), 1)
        self.assertEquals(grants[0].find('./Grantee/ID').text, 'test:tester')
        self.assertEquals(
            grants[0].find('./Grantee/DisplayName').text, 'test:tester')

    def test_acl_from_elem(self):
        # check translation from element
        acl = ACLPrivate(Owner(id='test:tester',
                               name='test:tester'))
        elem = acl.elem()
        acl = ACL.from_elem(elem)
        self.assertTrue(self.check_permission(acl, 'test:tester', 'READ'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'WRITE'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'READ_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'WRITE_ACP'))
        self.assertFalse(self.check_permission(acl, 'test:tester2', 'READ'))
        self.assertFalse(self.check_permission(acl, 'test:tester2', 'WRITE'))
        self.assertFalse(self.check_permission(acl, 'test:tester2',
                                               'READ_ACP'))
        self.assertFalse(self.check_permission(acl, 'test:tester2',
                                               'WRITE_ACP'))


if __name__ == '__main__':
    unittest.main()
