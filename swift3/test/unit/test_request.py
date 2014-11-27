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

from contextlib import nested
from mock import patch
import unittest

from swift.common.swob import Request

from swift3.subresource import ACL, User, Owner, Grant
from swift3.test.unit.test_middleware import Swift3TestCase
from swift3.cfg import CONF
from swift3.request import Request as S3_Request


Fake_ACL_MAP = {
    # HEAD Bucket
    ('HEAD', 'HEAD', 'container'):
    {'Resource': 'container',
     'Permission': 'READ'},
    # GET Bucket
    ('GET', 'GET', 'container'):
    {'Resource': 'container',
     'Permission': 'READ'},
    # HEAD Object
    ('HEAD', 'HEAD', 'object'):
    {'Resource': 'object',
     'Permission': 'READ'},
    # GET Object
    ('GET', 'GET', 'object'):
    {'Resource': 'object',
     'Permission': 'READ'},
}


def _gen_test_acl(owner, permission=None, grantee=None):
    if permission is None:
        return ACL(owner, [])

    if grantee is None:
        grantee = User('test:tester')
    return ACL(owner, [Grant(grantee, permission)])


class FakeResponse(object):
    def __init__(self, s3_acl):
        self.bucket_acl = None
        self.object_acl = None
        if s3_acl:
            owner = Owner(id='test:tester', name='test:tester')
            self.bucket_acl = _gen_test_acl(owner, 'FULL_CONTROL')
            self.object_acl = _gen_test_acl(owner, 'FULL_CONTROL')


class TestRequest(Swift3TestCase):

    def setUp(self):
        super(TestRequest, self).setUp()
        CONF.s3_acl = True

    def tearDown(self):
        CONF.s3_acl = False

    @patch('swift3.request.ACL_MAP', Fake_ACL_MAP)
    def _test_get_response(self, method, path='/bucket', permission=None,
                           skip_check=False):
        req = Request.blank(path,
                            environ={'REQUEST_METHOD': method},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        s3_req = S3_Request(req.environ)

        with nested(patch('swift3.request.Request._get_response'),
                    patch('swift3.subresource.ACL.check_permission')) \
                as (m_resp, m_check_permission):
            m_resp.return_value = FakeResponse(CONF.s3_acl)
            return m_resp, m_check_permission,\
                s3_req.get_response(self.swift3, permission=permission,
                                    skip_check=skip_check)

    def test_get_response_without_s3_acl(self):
        CONF.s3_acl = False
        m_resp, m_check_permission, s3_resp = \
            self._test_get_response('HEAD')
        self.assertIsNone(s3_resp.bucket_acl)
        self.assertIsNone(s3_resp.object_acl)
        self.assertEqual(m_resp.call_count, 1)
        self.assertEqual(m_check_permission.call_count, 0)

    def test_get_response_without_check_permission(self):
        m_resp, m_check_permission, s3_resp = \
            self._test_get_response('HEAD', skip_check=True)
        self.assertIsNotNone(s3_resp.bucket_acl)
        self.assertIsNotNone(s3_resp.object_acl)
        self.assertEqual(m_resp.call_count, 1)
        self.assertEqual(m_check_permission.call_count, 0)

    def test_get_response_with_permission_specified(self):
        m_resp, m_check_permission, s3_resp = \
            self._test_get_response('GET', path='/bucket/object',
                                    permission='READ_ACP')
        self.assertIsNotNone(s3_resp.bucket_acl)
        self.assertIsNotNone(s3_resp.object_acl)
        self.assertEqual(m_resp.call_count, 2)
        args, kargs = m_resp.call_args_list[0]
        isObject = args[3]
        self.assertIsNotNone(isObject)
        self.assertEqual(m_check_permission.call_count, 1)
        args, kargs = m_check_permission.call_args
        permission = args[1]
        self.assertEqual(permission, 'READ_ACP')

    def test_get_response_without_match_ACL_MAP(self):
        m_resp, m_check_permission, s3_resp = \
            self._test_get_response('POST')
        self.assertIsNotNone(s3_resp.bucket_acl)
        self.assertIsNotNone(s3_resp.object_acl)
        self.assertEqual(m_resp.call_count, 1)
        self.assertEqual(m_check_permission.call_count, 0)

    def test_get_response_without_duplication_HEAD_request(self):
        m_resp, m_check_permission, s3_resp = \
            self._test_get_response('HEAD', path='/bucket/object')
        self.assertIsNotNone(s3_resp.bucket_acl)
        self.assertIsNotNone(s3_resp.object_acl)
        self.assertEqual(m_resp.call_count, 1)
        args, kargs = m_resp.call_args_list[0]
        isObject = args[3]
        self.assertIsNotNone(isObject)
        self.assertEqual(m_check_permission.call_count, 1)
        args, kargs = m_check_permission.call_args
        permission = args[1]
        self.assertEqual(permission, 'READ')

    def test_get_response_with_check_object_permission(self):
        m_resp, m_check_permission, s3_resp = \
            self._test_get_response('GET', path='/bucket/object')
        self.assertIsNotNone(s3_resp.bucket_acl)
        self.assertIsNotNone(s3_resp.object_acl)
        self.assertEqual(m_resp.call_count, 2)
        args, kargs = m_resp.call_args_list[0]
        isObject = args[3]
        self.assertIsNotNone(isObject)
        self.assertEqual(m_check_permission.call_count, 1)
        args, kargs = m_check_permission.call_args
        permission = args[1]
        self.assertEqual(permission, 'READ')

    def test_get_response_with_check_container_permission(self):
        m_resp, m_check_permission, s3_resp = \
            self._test_get_response('GET')
        self.assertIsNotNone(s3_resp.bucket_acl)
        self.assertIsNotNone(s3_resp.object_acl)
        self.assertEqual(m_resp.call_count, 2)
        args, kargs = m_resp.call_args_list[0]
        isObject = args[3]
        self.assertIsNone(isObject)
        self.assertEqual(m_check_permission.call_count, 1)
        args, kargs = m_check_permission.call_args
        permission = args[1]
        self.assertEqual(permission, 'READ')

if __name__ == '__main__':
    unittest.main()
