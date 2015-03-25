# Copyright (c) 2015 OpenStack Foundation
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
from swift3.test.functional import Swift3FunctionalTestCase
from nose.plugins.attrib import attr
from swift3.etree import fromstring

ALL_USERS = 'http://acs.amazonaws.com/groups/global/AllUsers'
AUTHENTICATED_USERS = \
    'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
XMLNS_XSI = 'http://www.w3.org/2001/XMLSchema-instance'


@attr(s3acl=True)
class TestSwift3S3Acl(Swift3FunctionalTestCase):
    def setUp(self):
        super(TestSwift3S3Acl, self).setUp()
        self.bucket = 'bucket'
        self.conn.make_request('PUT', self.bucket)
        self.obj = 'object'

    def _generate_expected_grants(self, permission, user_id, bucket_owner):
        expected_grants = []
        if permission == 'private':
            expected_grants = [('FULL_CONTROL', user_id)]
        elif permission == 'public-read':
            expected_grants = [('FULL_CONTROL', user_id),
                               ('READ', ALL_USERS)]
        elif permission == 'public-read-write':
            expected_grants = [('FULL_CONTROL', user_id),
                               ('READ', ALL_USERS),
                               ('WRITE', ALL_USERS)]
        elif permission == 'authenticated-read':
            expected_grants = [('FULL_CONTROL', user_id),
                               ('READ', AUTHENTICATED_USERS)]
        elif permission == 'bucket-owner-read':
            expected_grants = [('FULL_CONTROL', user_id),
                               ('READ', bucket_owner)]
        elif permission == 'bucket-owner-full-control':
            expected_grants = [('FULL_CONTROL', user_id),
                               ('FULL_CONTROL', bucket_owner)]
        return expected_grants

    def _check_canned_acl(self, xml, expected_grants, user_id):
        elem = fromstring(xml, 'AccessControlPolicy')
        owner = elem.find('Owner')
        self.assertEquals(owner.find('ID').text, user_id)
        self.assertEquals(owner.find('DisplayName').text, user_id)
        acl = elem.find('AccessControlList')

        grants = acl.findall('Grant')
        self.assertEquals(len(grants), len(expected_grants))

        for grant in grants:
            permission = grant.find('Permission').text
            grantee = grant.find('Grantee')
            grantee_type = grantee.get('{%s}type' % XMLNS_XSI)
            if grantee_type == 'Group':
                grantee_value = grantee.find('URI').text
            elif grantee_type == 'CanonicalUser':
                grantee_value = grantee.find('ID').text
            else:
                grantee_value = None
            self.assertTrue((permission, grantee_value) in expected_grants)

    def _test_x_amz_acl(self, permission, bucket, obj=''):
        headers = {'x-amz-acl': permission}
        status, _, _ = \
            self.conn.make_request('PUT', bucket, obj, headers=headers,
                                   query='acl')
        self.assertEquals(status, 200)

        _, _, body = self.conn.make_request('GET', bucket, query='acl')
        elem = fromstring(body)
        bucket_owner = elem.find('Owner/ID').text
        if obj:
            _, _, body = \
                self.conn.make_request('GET', bucket, obj, query='acl')

        expected_grants = self._generate_expected_grants(permission,
                                                         self.conn.user_id,
                                                         bucket_owner)
        self._check_canned_acl(body, expected_grants, self.conn.user_id)

    def test_x_amz_acl_bucket(self):
        self._test_x_amz_acl('private', self.bucket)
        self._test_x_amz_acl('public-read', self.bucket)
        self._test_x_amz_acl('public-read-write', self.bucket)
        self._test_x_amz_acl('authenticated-read', self.bucket)

    def test_x_amz_acl_object(self):
        self.conn.make_request('PUT', self.bucket, self.obj)

        self._test_x_amz_acl('private', self.bucket, self.obj)
        self._test_x_amz_acl('public-read', self.bucket, self.obj)
        self._test_x_amz_acl('public-read-write', self.bucket, self.obj)
        self._test_x_amz_acl('authenticated-read', self.bucket, self.obj)
        self._test_x_amz_acl('bucket-owner-read', self.bucket, self.obj)
        self._test_x_amz_acl('bucket-owner-full-control',
                             self.bucket, self.obj)

if __name__ == '__main__':
    unittest.main()
