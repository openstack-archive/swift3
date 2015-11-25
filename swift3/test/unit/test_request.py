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

from swift.common import swob
from swift.common.swob import Request, HTTPNoContent

from swift3.subresource import ACL, User, Owner, Grant, encode_acl
from swift3.test.unit.test_middleware import Swift3TestCase
from swift3.cfg import CONF
from swift3.request import Request as S3_Request
from swift3.request import S3AclRequest
from swift3.response import InvalidArgument, NoSuchBucket, InternalError


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


class FakeSwiftResponse(object):
    def __init__(self):
        self.environ = {
            'PATH_INFO': '/v1/AUTH_test',
            'HTTP_X_TENANT_NAME': 'test',
            'HTTP_X_USER_NAME': 'tester',
            'HTTP_X_AUTH_TOKEN': 'token',
        }


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
                           req_klass=S3_Request, fake_swift_resp=None):
        path = '/' + container + ('/' + obj if obj else '')
        req = Request.blank(path,
                            environ={'REQUEST_METHOD': method},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        if issubclass(req_klass, S3AclRequest):
            s3_req = req_klass(req.environ, MagicMock())
        else:
            s3_req = req_klass(req.environ)
        with nested(patch('swift3.request.Request._get_response'),
                    patch('swift3.subresource.ACL.check_permission')) \
                as (mock_get_resp, m_check_permission):
            mock_get_resp.return_value = fake_swift_resp \
                or FakeResponse(CONF.s3_acl)
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
        with self.assertRaises(Exception) as e:
            self._test_get_response('POST', req_klass=S3AclRequest)
        self.assertEquals(e.exception.message,
                          'No permission to be checked exists')

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

    def test_get_validate_param(self):
        def create_s3request_with_param(param, value):
            req = Request.blank(
                '/bucket?%s=%s' % (param, value),
                environ={'REQUEST_METHOD': 'GET'},
                headers={'Authorization': 'AWS test:tester:hmac',
                         'Date': self.get_date_header()})
            return S3_Request(req.environ, True)

        s3req = create_s3request_with_param('max-keys', '1')

        # a param in the range
        self.assertEquals(s3req.get_validated_param('max-keys', 1000, 1000), 1)
        self.assertEquals(s3req.get_validated_param('max-keys', 0, 1), 1)

        # a param in the out of the range
        self.assertEquals(s3req.get_validated_param('max-keys', 0, 0), 0)

        # a param in the out of the integer range
        s3req = create_s3request_with_param('max-keys', '1' * 30)
        with self.assertRaises(InvalidArgument) as result:
            s3req.get_validated_param('max-keys', 1)
        self.assertTrue(
            'not an integer or within integer range' in result.exception.body)
        self.assertEquals(
            result.exception.headers['content-type'], 'application/xml')

        # a param is negative integer
        s3req = create_s3request_with_param('max-keys', '-1')
        with self.assertRaises(InvalidArgument) as result:
            s3req.get_validated_param('max-keys', 1)
        self.assertTrue(
            'must be an integer between 0 and' in result.exception.body)
        self.assertEquals(
            result.exception.headers['content-type'], 'application/xml')

        # a param is not integer
        s3req = create_s3request_with_param('max-keys', 'invalid')
        with self.assertRaises(InvalidArgument) as result:
            s3req.get_validated_param('max-keys', 1)
        self.assertTrue(
            'not an integer or within integer range' in result.exception.body)
        self.assertEquals(
            result.exception.headers['content-type'], 'application/xml')

    def test_authenticate_delete_Authorization_from_s3req_headers(self):
        req = Request.blank('/bucket/obj',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        with nested(patch.object(Request, 'get_response'),
                    patch.object(Request, 'remote_user', 'authorized')) \
                as (m_swift_resp, m_remote_user):

            m_swift_resp.return_value = FakeSwiftResponse()
            s3_req = S3AclRequest(req.environ, MagicMock())
            self.assertTrue('HTTP_AUTHORIZATION' not in s3_req.environ)
            self.assertTrue('Authorization' not in s3_req.headers)
            self.assertEquals(s3_req.token, 'token')

    def test_to_swift_req_Authorization_not_exist_in_swreq_headers(self):
        container = 'bucket'
        obj = 'obj'
        method = 'GET'
        req = Request.blank('/%s/%s' % (container, obj),
                            environ={'REQUEST_METHOD': method},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        with nested(patch.object(Request, 'get_response'),
                    patch.object(Request, 'remote_user', 'authorized')) \
                as (m_swift_resp, m_remote_user):

            m_swift_resp.return_value = FakeSwiftResponse()
            s3_req = S3AclRequest(req.environ, MagicMock())
            sw_req = s3_req.to_swift_req(method, container, obj)
            self.assertTrue('HTTP_AUTHORIZATION' not in sw_req.environ)
            self.assertTrue('Authorization' not in sw_req.headers)
            self.assertEquals(sw_req.headers['X-Auth-Token'], 'token')

    def test_to_swift_req_subrequest_proxy_access_log(self):
        container = 'bucket'
        obj = 'obj'
        method = 'GET'

        # force_swift_request_proxy_log is True
        req = Request.blank('/%s/%s' % (container, obj),
                            environ={'REQUEST_METHOD': method,
                                     'swift.proxy_access_log_made': True},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        with nested(patch.object(Request, 'get_response'),
                    patch.object(Request, 'remote_user', 'authorized'),
                    patch('swift3.cfg.CONF.force_swift_request_proxy_log',
                    True)) \
                as (m_swift_resp, m_remote_user, m_cfg):

            m_swift_resp.return_value = FakeSwiftResponse()
            s3_req = S3AclRequest(req.environ, MagicMock())
            sw_req = s3_req.to_swift_req(method, container, obj)
            self.assertFalse(sw_req.environ['swift.proxy_access_log_made'])

        # force_swift_request_proxy_log is False
        req = Request.blank('/%s/%s' % (container, obj),
                            environ={'REQUEST_METHOD': method,
                                     'swift.proxy_access_log_made': True},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        with nested(patch.object(Request, 'get_response'),
                    patch.object(Request, 'remote_user', 'authorized')) \
                as (m_swift_resp, m_remote_user):

            m_swift_resp.return_value = FakeSwiftResponse()
            s3_req = S3AclRequest(req.environ, MagicMock())
            sw_req = s3_req.to_swift_req(method, container, obj)
            self.assertTrue(sw_req.environ['swift.proxy_access_log_made'])

    def test_get_container_info(self):
        self.swift.register('HEAD', '/v1/AUTH_test/bucket', HTTPNoContent,
                            {'x-container-read': 'foo',
                             'X-container-object-count': 5,
                             'X-container-meta-foo': 'bar'}, None)
        req = Request.blank('/bucket', environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        s3_req = S3_Request(req.environ, True)
        # first, call get_response('HEAD')
        info = s3_req.get_container_info(self.app)
        self.assertTrue('status' in info)  # sanity
        self.assertEquals(204, info['status'])  # sanity
        self.assertEquals('foo', info['read_acl'])  # sanity
        self.assertEquals('5', info['object_count'])  # sanity
        self.assertEquals({'foo': 'bar'}, info['meta'])  # sanity
        with patch('swift3.request.get_container_info',
                   return_value={'status': 204}) as mock_info:
            # Then all calls goes to get_container_info
            for x in xrange(10):
                info = s3_req.get_container_info(self.swift)
                self.assertTrue('status' in info)  # sanity
                self.assertEquals(204, info['status'])  # sanity
            self.assertEquals(10, mock_info.call_count)

        expected_errors = [(404, NoSuchBucket), (0, InternalError)]
        for status, expected_error in expected_errors:
            with patch('swift3.request.get_container_info',
                       return_value={'status': status}):
                self.assertRaises(
                    expected_error, s3_req.get_container_info, MagicMock())

    def test_date_header_missing(self):
        self.swift.register('HEAD', '/v1/AUTH_test/nojunk', swob.HTTPNotFound,
                            {}, None)
        req = Request.blank('/nojunk',
                            environ={'REQUEST_METHOD': 'HEAD'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '403')
        self.assertEquals(body, '')

    def test_date_header_expired(self):
        self.swift.register('HEAD', '/v1/AUTH_test/nojunk', swob.HTTPNotFound,
                            {}, None)
        req = Request.blank('/nojunk',
                            environ={'REQUEST_METHOD': 'HEAD'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': 'Fri, 01 Apr 2014 12:00:00 GMT'})

        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '403')
        self.assertEquals(body, '')

    def test_date_header_with_x_amz_date_valid(self):
        self.swift.register('HEAD', '/v1/AUTH_test/nojunk', swob.HTTPNotFound,
                            {}, None)
        req = Request.blank('/nojunk',
                            environ={'REQUEST_METHOD': 'HEAD'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': 'Fri, 01 Apr 2014 12:00:00 GMT',
                                     'x-amz-date': self.get_date_header()})

        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '404')
        self.assertEquals(body, '')

    def test_date_header_with_x_amz_date_expired(self):
        self.swift.register('HEAD', '/v1/AUTH_test/nojunk', swob.HTTPNotFound,
                            {}, None)
        req = Request.blank('/nojunk',
                            environ={'REQUEST_METHOD': 'HEAD'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'x-amz-date':
                                     'Fri, 01 Apr 2014 12:00:00 GMT'})

        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '403')
        self.assertEquals(body, '')

if __name__ == '__main__':
    unittest.main()
