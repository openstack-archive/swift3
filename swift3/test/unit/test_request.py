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
from mock import patch, MagicMock
import unittest

from swift.common.swob import Request

from swift3.subresource import ACL, User, Owner, Grant, encode_acl
from swift3.test.unit.test_middleware import Swift3TestCase
from swift3.cfg import CONF
from swift3.request import Request as S3_Request
from swift3.request import S3AclRequest


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


def _gen_test_acl_header(owner, permission=None, grantee=None,
                         resource='container'):
    if permission is None:
        return ACL(owner, [])

    if grantee is None:
        grantee = User('test:tester')
    return encode_acl(resource, ACL(owner, [Grant(grantee, permission)]))


class FakeResponse(object):
    def __init__(self, s3_acl):
        self.sysmeta_headers = {}
        if s3_acl:
            owner = Owner(id='test:tester', name='test:tester')
            self.sysmeta_headers.update(
                _gen_test_acl_header(owner, 'FULL_CONTROL',
                                     resource='container'))
            self.sysmeta_headers.update(
                _gen_test_acl_header(owner, 'FULL_CONTROL',
                                     resource='object'))


class TestRequest(Swift3TestCase):

    def setUp(self):
        super(TestRequest, self).setUp()
        CONF.s3_acl = True

    def tearDown(self):
        CONF.s3_acl = False

    @patch('swift3.acl_handlers.ACL_MAP', Fake_ACL_MAP)
    @patch('swift3.request.S3AclRequest.authenticate', lambda x, y: None)
    def _test_get_response(self, method, container='bucket', obj=None,
                           permission=None, skip_check=False,
                           req_klass=S3_Request):
        path = '/' + container + ('/' + obj if obj else '')
        req = Request.blank(path,
                            environ={'REQUEST_METHOD': method},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        if issubclass(req_klass, S3AclRequest):
            s3_req = req_klass(req.environ, MagicMock())
        else:
            s3_req = req_klass(req.environ)
        with nested(patch('swift3.request.Request._get_response'),
                    patch('swift3.subresource.ACL.check_permission')) \
                as (mock_get_resp, m_check_permission):
            mock_get_resp.return_value = FakeResponse(CONF.s3_acl)
            return mock_get_resp, m_check_permission,\
                s3_req.get_response(self.swift3)

    def test_get_response_without_s3_acl(self):
        with patch('swift3.cfg.CONF.s3_acl', False):
            mock_get_resp, m_check_permission, s3_resp = \
                self._test_get_response('HEAD')
        self.assertFalse(hasattr(s3_resp, 'bucket_acl'))
        self.assertFalse(hasattr(s3_resp, 'object_acl'))
        self.assertEqual(mock_get_resp.call_count, 1)
        self.assertEqual(m_check_permission.call_count, 0)

    def test_get_response_without_match_ACL_MAP(self):
        mock_get_resp, m_check_permission, s3_resp = \
            self._test_get_response('POST',
                                    req_klass=S3AclRequest)
        self.assertTrue(s3_resp.bucket_acl is not None)
        self.assertTrue(s3_resp.object_acl is not None)
        self.assertEqual(mock_get_resp.call_count, 1)
        self.assertEqual(m_check_permission.call_count, 0)

    def test_get_response_without_duplication_HEAD_request(self):
        obj = 'object'
        mock_get_resp, m_check_permission, s3_resp = \
            self._test_get_response('HEAD', obj=obj,
                                    req_klass=S3AclRequest)
        self.assertTrue(s3_resp.bucket_acl is not None)
        self.assertTrue(s3_resp.object_acl is not None)
        self.assertEqual(mock_get_resp.call_count, 1)
        args, kargs = mock_get_resp.call_args_list[0]
        get_resp_obj = args[3]
        self.assertEqual(get_resp_obj, obj)
        self.assertEqual(m_check_permission.call_count, 1)
        args, kargs = m_check_permission.call_args
        permission = args[1]
        self.assertEqual(permission, 'READ')

    def test_get_response_with_check_object_permission(self):
        obj = 'object'
        mock_get_resp, m_check_permission, s3_resp = \
            self._test_get_response('GET', obj=obj,
                                    req_klass=S3AclRequest)
        self.assertTrue(s3_resp.bucket_acl is not None)
        self.assertTrue(s3_resp.object_acl is not None)
        self.assertEqual(mock_get_resp.call_count, 2)
        args, kargs = mock_get_resp.call_args_list[0]
        get_resp_obj = args[3]
        self.assertEqual(get_resp_obj, obj)
        self.assertEqual(m_check_permission.call_count, 1)
        args, kargs = m_check_permission.call_args
        permission = args[1]
        self.assertEqual(permission, 'READ')

    def test_get_response_with_check_container_permission(self):
        mock_get_resp, m_check_permission, s3_resp = \
            self._test_get_response('GET',
                                    req_klass=S3AclRequest)
        self.assertTrue(s3_resp.bucket_acl is not None)
        self.assertTrue(s3_resp.object_acl is not None)
        self.assertEqual(mock_get_resp.call_count, 2)
        args, kargs = mock_get_resp.call_args_list[0]
        get_resp_obj = args[3]
        self.assertTrue(get_resp_obj is '')
        self.assertEqual(m_check_permission.call_count, 1)
        args, kargs = m_check_permission.call_args
        permission = args[1]
        self.assertEqual(permission, 'READ')


if __name__ == '__main__':
    unittest.main()
