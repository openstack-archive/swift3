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
from datetime import datetime
import hashlib
from os.path import join
from mock import patch

from swift.common import swob
from swift.common.swob import Request

from swift3.test.unit import Swift3TestCase
from swift3.test.unit.test_s3_acl import s3acl
from swift3.subresource import ACL, User, encode_acl, Owner, Grant
from swift3.etree import fromstring
from swift3.test.unit.helpers import FakeSwift


def _wrap_fake_auth_middleware(org_func):
    def fake_fake_auth_middleware(self, env):
        org_func(env)

        if 'swift.authorize_override' in env:
            return

        if 'HTTP_AUTHORIZATION' not in env:
            return

        _, authorization = env['HTTP_AUTHORIZATION'].split(' ')
        tenant_user, sign = authorization.rsplit(':', 1)
        tenant, user = tenant_user.rsplit(':', 1)

        env['HTTP_X_TENANT_NAME'] = tenant
        env['HTTP_X_USER_NAME'] = user

    return fake_fake_auth_middleware


class TestSwift3Obj(Swift3TestCase):

    def setUp(self):
        super(TestSwift3Obj, self).setUp()

        self.object_body = 'hello'
        self.etag = hashlib.md5(self.object_body).hexdigest()
        self.last_modified = 'Fri, 01 Apr 2014 12:00:00 GMT'

        self.response_headers = {'Content-Type': 'text/html',
                                 'Content-Length': len(self.object_body),
                                 'Content-Disposition': 'inline',
                                 'Content-Language': 'en',
                                 'x-object-meta-test': 'swift',
                                 'etag': self.etag,
                                 'last-modified': self.last_modified,
                                 'expires': 'Mon, 21 Sep 2015 12:00:00 GMT',
                                 'x-robots-tag': 'nofollow',
                                 'cache-control': 'private'}

        self.swift.register('GET', '/v1/AUTH_test/bucket/object',
                            swob.HTTPOk, self.response_headers,
                            self.object_body)
        self.swift.register('PUT', '/v1/AUTH_test/bucket/object',
                            swob.HTTPCreated,
                            {'etag': self.etag,
                             'last-modified': self.last_modified,
                             'x-object-meta-something': 'oh hai'},
                            None)

    def _test_object_GETorHEAD(self, method):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': method},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

        unexpected_headers = []
        for key, val in self.response_headers.iteritems():
            if key in ('Content-Length', 'Content-Type', 'content-encoding',
                       'last-modified', 'cache-control', 'Content-Disposition',
                       'Content-Language', 'expires', 'x-robots-tag'):
                self.assertIn(key, headers)
                self.assertEquals(headers[key], str(val))

            elif key == 'etag':
                self.assertEquals(headers[key], '"%s"' % val)

            elif key.startswith('x-object-meta-'):
                self.assertIn('x-amz-meta-' + key[14:], headers)
                self.assertEquals(headers['x-amz-meta-' + key[14:]], val)

            else:
                unexpected_headers.append((key, val))

        if unexpected_headers:
                self.fail('unexpected headers: %r' % unexpected_headers)

        self.assertEquals(headers['etag'],
                          '"%s"' % self.response_headers['etag'])

        if method == 'GET':
            self.assertEquals(body, self.object_body)

    @s3acl
    def test_object_HEAD_error(self):
        # HEAD does not return the body even an error resonse in the
        # specifications of the REST API.
        # So, check the response code for error test of HEAD.
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'HEAD'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        self.swift.register('HEAD', '/v1/AUTH_test/bucket/object',
                            swob.HTTPUnauthorized, {}, None)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '403')
        self.assertEquals(body, '')  # sanifty
        self.swift.register('HEAD', '/v1/AUTH_test/bucket/object',
                            swob.HTTPForbidden, {}, None)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '403')
        self.assertEquals(body, '')  # sanifty
        self.swift.register('HEAD', '/v1/AUTH_test/bucket/object',
                            swob.HTTPNotFound, {}, None)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '404')
        self.assertEquals(body, '')  # sanifty
        self.swift.register('HEAD', '/v1/AUTH_test/bucket/object',
                            swob.HTTPPreconditionFailed, {}, None)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '412')
        self.assertEquals(body, '')  # sanifty
        self.swift.register('HEAD', '/v1/AUTH_test/bucket/object',
                            swob.HTTPServerError, {}, None)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '500')
        self.assertEquals(body, '')  # sanifty
        self.swift.register('HEAD', '/v1/AUTH_test/bucket/object',
                            swob.HTTPServiceUnavailable, {}, None)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '500')
        self.assertEquals(body, '')  # sanifty

    def test_object_HEAD(self):
        self._test_object_GETorHEAD('HEAD')

    def _test_object_HEAD_Range(self, range_value):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'HEAD'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Range': range_value,
                                     'Date': self.get_date_header()})
        return self.call_swift3(req)

    @s3acl
    def test_object_HEAD_Range_with_invalid_value(self):
        range_value = ''
        status, headers, body = self._test_object_HEAD_Range(range_value)
        self.assertEquals(status.split()[0], '200')
        self.assertTrue('content-length' in headers)
        self.assertEqual(headers['content-length'], '5')
        self.assertTrue('content-range' not in headers)

        range_value = 'hoge'
        status, headers, body = self._test_object_HEAD_Range(range_value)
        self.assertEquals(status.split()[0], '200')
        self.assertTrue('content-length' in headers)
        self.assertEqual(headers['content-length'], '5')
        self.assertTrue('content-range' not in headers)

        range_value = 'bytes='
        status, headers, body = self._test_object_HEAD_Range(range_value)
        self.assertEquals(status.split()[0], '200')
        self.assertTrue('content-length' in headers)
        self.assertEqual(headers['content-length'], '5')
        self.assertTrue('content-range' not in headers)

        range_value = 'bytes=1'
        status, headers, body = self._test_object_HEAD_Range(range_value)
        self.assertEquals(status.split()[0], '200')
        self.assertTrue('content-length' in headers)
        self.assertEqual(headers['content-length'], '5')
        self.assertTrue('content-range' not in headers)

        range_value = 'bytes=5-1'
        status, headers, body = self._test_object_HEAD_Range(range_value)
        self.assertEquals(status.split()[0], '200')
        self.assertTrue('content-length' in headers)
        self.assertEqual(headers['content-length'], '5')
        self.assertTrue('content-range' not in headers)

        range_value = 'bytes=5-10'
        status, headers, body = self._test_object_HEAD_Range(range_value)
        self.assertEquals(status.split()[0], '416')

    @s3acl
    def test_object_HEAD_Range(self):
        # update response headers
        self.swift.register('HEAD', '/v1/AUTH_test/bucket/object',
                            swob.HTTPOk, self.response_headers,
                            self.object_body)
        range_value = 'bytes=0-3'
        status, headers, body = self._test_object_HEAD_Range(range_value)
        self.assertEquals(status.split()[0], '206')
        self.assertTrue('content-length' in headers)
        self.assertEqual(headers['content-length'], '4')
        self.assertTrue('content-range' in headers)
        self.assertTrue(headers['content-range'].startswith('bytes 0-3'))
        self.assertTrue('x-amz-meta-test' in headers)
        self.assertEqual('swift', headers['x-amz-meta-test'])

        range_value = 'bytes=3-3'
        status, headers, body = self._test_object_HEAD_Range(range_value)
        self.assertEquals(status.split()[0], '206')
        self.assertTrue('content-length' in headers)
        self.assertEqual(headers['content-length'], '1')
        self.assertTrue('content-range' in headers)
        self.assertTrue(headers['content-range'].startswith('bytes 3-3'))
        self.assertTrue('x-amz-meta-test' in headers)
        self.assertEqual('swift', headers['x-amz-meta-test'])

        range_value = 'bytes=1-'
        status, headers, body = self._test_object_HEAD_Range(range_value)
        self.assertEquals(status.split()[0], '206')
        self.assertTrue('content-length' in headers)
        self.assertEqual(headers['content-length'], '4')
        self.assertTrue('content-range' in headers)
        self.assertTrue(headers['content-range'].startswith('bytes 1-4'))
        self.assertTrue('x-amz-meta-test' in headers)
        self.assertEqual('swift', headers['x-amz-meta-test'])

        range_value = 'bytes=-3'
        status, headers, body = self._test_object_HEAD_Range(range_value)
        self.assertEquals(status.split()[0], '206')
        self.assertTrue('content-length' in headers)
        self.assertEqual(headers['content-length'], '3')
        self.assertTrue('content-range' in headers)
        self.assertTrue(headers['content-range'].startswith('bytes 2-4'))
        self.assertTrue('x-amz-meta-test' in headers)
        self.assertEqual('swift', headers['x-amz-meta-test'])

    @s3acl
    def test_object_GET_error(self):
        code = self._test_method_error('GET', '/bucket/object',
                                       swob.HTTPUnauthorized)
        self.assertEquals(code, 'SignatureDoesNotMatch')
        code = self._test_method_error('GET', '/bucket/object',
                                       swob.HTTPForbidden)
        self.assertEquals(code, 'AccessDenied')
        code = self._test_method_error('GET', '/bucket/object',
                                       swob.HTTPNotFound)
        self.assertEquals(code, 'NoSuchKey')
        code = self._test_method_error('GET', '/bucket/object',
                                       swob.HTTPServerError)
        self.assertEquals(code, 'InternalError')
        code = self._test_method_error('GET', '/bucket/object',
                                       swob.HTTPPreconditionFailed)
        self.assertEquals(code, 'PreconditionFailed')
        code = self._test_method_error('GET', '/bucket/object',
                                       swob.HTTPServiceUnavailable)
        self.assertEquals(code, 'InternalError')

    @s3acl
    def test_object_GET(self):
        self._test_object_GETorHEAD('GET')

    @s3acl(s3acl_only=True)
    def test_object_GET_with_s3acl_and_keystone(self):
        # for passing keystone authentication root
        fake_auth = self.swift._fake_auth_middleware
        with patch.object(FakeSwift, '_fake_auth_middleware',
                          _wrap_fake_auth_middleware(fake_auth)):

            self._test_object_GETorHEAD('GET')
            _, _, headers = self.swift.calls_with_headers[-1]
            self.assertTrue('Authorization' not in headers)
            _, _, headers = self.swift.calls_with_headers[0]
            self.assertTrue('Authorization' not in headers)

    @s3acl
    def test_object_GET_Range(self):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Range': 'bytes=0-3',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '206')

        self.assertTrue('content-range' in headers)
        self.assertTrue(headers['content-range'].startswith('bytes 0-3'))

    @s3acl
    def test_object_GET_Range_error(self):
        code = self._test_method_error('GET', '/bucket/object',
                                       swob.HTTPRequestedRangeNotSatisfiable)
        self.assertEquals(code, 'InvalidRange')

    @s3acl
    def test_object_GET_Response(self):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'GET',
                                     'QUERY_STRING':
                                     'response-content-type=%s&'
                                     'response-content-language=%s&'
                                     'response-expires=%s&'
                                     'response-cache-control=%s&'
                                     'response-content-disposition=%s&'
                                     'response-content-encoding=%s&'
                                     % ('text/plain', 'en',
                                        'Fri, 01 Apr 2014 12:00:00 GMT',
                                        'no-cache',
                                        'attachment',
                                        'gzip')},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

        self.assertTrue('content-type' in headers)
        self.assertEquals(headers['content-type'], 'text/plain')
        self.assertTrue('content-language' in headers)
        self.assertEquals(headers['content-language'], 'en')
        self.assertTrue('expires' in headers)
        self.assertEquals(headers['expires'], 'Fri, 01 Apr 2014 12:00:00 GMT')
        self.assertTrue('cache-control' in headers)
        self.assertEquals(headers['cache-control'], 'no-cache')
        self.assertTrue('content-disposition' in headers)
        self.assertEquals(headers['content-disposition'],
                          'attachment')
        self.assertTrue('content-encoding' in headers)
        self.assertEquals(headers['content-encoding'], 'gzip')

    @s3acl
    def test_object_PUT_error(self):
        code = self._test_method_error('PUT', '/bucket/object',
                                       swob.HTTPUnauthorized)
        self.assertEquals(code, 'SignatureDoesNotMatch')
        code = self._test_method_error('PUT', '/bucket/object',
                                       swob.HTTPForbidden)
        self.assertEquals(code, 'AccessDenied')
        code = self._test_method_error('PUT', '/bucket/object',
                                       swob.HTTPNotFound)
        self.assertEquals(code, 'NoSuchBucket')
        code = self._test_method_error('PUT', '/bucket/object',
                                       swob.HTTPRequestEntityTooLarge)
        self.assertEquals(code, 'EntityTooLarge')
        code = self._test_method_error('PUT', '/bucket/object',
                                       swob.HTTPServerError)
        self.assertEquals(code, 'InternalError')
        code = self._test_method_error('PUT', '/bucket/object',
                                       swob.HTTPUnprocessableEntity)
        self.assertEquals(code, 'BadDigest')
        code = self._test_method_error('PUT', '/bucket/object',
                                       swob.HTTPLengthRequired)
        self.assertEquals(code, 'MissingContentLength')
        code = self._test_method_error('PUT', '/bucket/object',
                                       swob.HTTPPreconditionFailed)
        self.assertEquals(code, 'InternalError')
        code = self._test_method_error('PUT', '/bucket/object',
                                       swob.HTTPServiceUnavailable)
        self.assertEquals(code, 'InternalError')
        code = self._test_method_error('PUT', '/bucket/object',
                                       swob.HTTPCreated,
                                       {'X-Amz-Copy-Source': ''})
        self.assertEquals(code, 'InvalidArgument')
        code = self._test_method_error('PUT', '/bucket/object',
                                       swob.HTTPCreated,
                                       {'X-Amz-Copy-Source': '/'})
        self.assertEquals(code, 'InvalidArgument')
        code = self._test_method_error('PUT', '/bucket/object',
                                       swob.HTTPCreated,
                                       {'X-Amz-Copy-Source': '/bucket'})
        self.assertEquals(code, 'InvalidArgument')
        code = self._test_method_error('PUT', '/bucket/object',
                                       swob.HTTPCreated,
                                       {'X-Amz-Copy-Source': '/bucket/'})
        self.assertEquals(code, 'InvalidArgument')
        code = self._test_method_error('PUT', '/bucket/object',
                                       swob.HTTPRequestTimeout)
        self.assertEquals(code, 'RequestTimeout')

    @s3acl
    def test_object_PUT(self):
        etag = self.response_headers['etag']
        content_md5 = etag.decode('hex').encode('base64').strip()

        req = Request.blank(
            '/bucket/object',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'x-amz-storage-class': 'STANDARD',
                     'Content-MD5': content_md5,
                     'Date': self.get_date_header()},
            body=self.object_body)
        req.date = datetime.now()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')
        # Check that swift3 returns an etag header.
        self.assertEquals(headers['etag'], '"%s"' % etag)

        _, _, headers = self.swift.calls_with_headers[-1]
        # Check that swift3 converts a Content-MD5 header into an etag.
        self.assertEquals(headers['etag'], etag)

    def test_object_PUT_headers(self):
        content_md5 = self.etag.decode('hex').encode('base64').strip()

        self.swift.register('HEAD', '/v1/AUTH_test/some/source',
                            swob.HTTPOk, {'last-modified': self.last_modified},
                            None)
        req = Request.blank(
            '/bucket/object',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'X-Amz-Storage-Class': 'STANDARD',
                     'X-Amz-Meta-Something': 'oh hai',
                     'X-Amz-Copy-Source': '/some/source',
                     'Content-MD5': content_md5,
                     'Date': self.get_date_header()})
        req.date = datetime.now()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        # Check that swift3 does not return an etag header,
        # specified copy source.
        self.assertTrue(headers.get('etag') is None)
        # Check that swift3 does not return custom metadata in response
        self.assertTrue(headers.get('x-amz-meta-something') is None)

        _, _, headers = self.swift.calls_with_headers[-1]
        # Check that swift3 converts a Content-MD5 header into an etag.
        self.assertEquals(headers['ETag'], self.etag)
        self.assertEquals(headers['X-Object-Meta-Something'], 'oh hai')
        self.assertEquals(headers['X-Copy-From'], '/some/source')
        self.assertEquals(headers['Content-Length'], '0')

    def _test_object_PUT_copy(self, head_resp, put_header={}):
        account = 'test:tester'
        grants = [Grant(User(account), 'FULL_CONTROL')]
        head_headers = \
            encode_acl('object',
                       ACL(Owner(account, account), grants))
        head_headers.update({'last-modified': self.last_modified})
        self.swift.register('HEAD', '/v1/AUTH_test/some/source',
                            head_resp, head_headers, None)

        put_headers = {'Authorization': 'AWS test:tester:hmac',
                       'X-Amz-Copy-Source': '/some/source',
                       'Date': self.get_date_header()}
        put_headers.update(put_header)

        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers=put_headers)

        req.date = datetime.now()
        req.content_type = 'text/plain'
        with patch('swift3.utils.time.time', return_value=1396353600.000000):
            return self.call_swift3(req)

    @s3acl
    def test_object_PUT_copy(self):
        last_modified = '2014-04-01T12:00:00.000Z'
        status, headers, body = \
            self._test_object_PUT_copy(swob.HTTPOk)
        self.assertEquals(status.split()[0], '200')
        self.assertEquals(headers['Content-Type'], 'application/xml')
        self.assertTrue(headers.get('etag') is None)
        self.assertTrue(headers.get('x-amz-meta-something') is None)
        elem = fromstring(body, 'CopyObjectResult')
        self.assertEquals(elem.find('LastModified').text, last_modified)
        self.assertEquals(elem.find('ETag').text, '"%s"' % self.etag)

        _, _, headers = self.swift.calls_with_headers[-1]
        self.assertEquals(headers['X-Copy-From'], '/some/source')
        self.assertEquals(headers['Content-Length'], '0')

    @s3acl
    def test_object_PUT_copy_headers_error(self):
        etag = '7dfa07a8e59ddbcd1dc84d4c4f82aea1'
        last_modified_since = 'Fri, 01 Apr 2014 12:00:00 GMT'

        header = {'X-Amz-Copy-Source-If-Match': etag,
                  'Date': self.get_date_header()}
        status, header, body = \
            self._test_object_PUT_copy(swob.HTTPPreconditionFailed,
                                       header)
        self.assertEquals(self._get_error_code(body), 'PreconditionFailed')

        header = {'X-Amz-Copy-Source-If-None-Match': etag}
        status, header, body = \
            self._test_object_PUT_copy(swob.HTTPNotModified,
                                       header)
        self.assertEquals(self._get_error_code(body), 'PreconditionFailed')

        header = {'X-Amz-Copy-Source-If-Modified-Since': last_modified_since}
        status, header, body = \
            self._test_object_PUT_copy(swob.HTTPNotModified,
                                       header)
        self.assertEquals(self._get_error_code(body), 'PreconditionFailed')

        header = \
            {'X-Amz-Copy-Source-If-Unmodified-Since': last_modified_since}
        status, header, body = \
            self._test_object_PUT_copy(swob.HTTPPreconditionFailed,
                                       header)
        self.assertEquals(self._get_error_code(body), 'PreconditionFailed')

    def test_object_PUT_copy_headers_with_match(self):
        etag = '7dfa07a8e59ddbcd1dc84d4c4f82aea1'
        last_modified_since = 'Fri, 01 Apr 2014 11:00:00 GMT'

        header = {'X-Amz-Copy-Source-If-Match': etag,
                  'X-Amz-Copy-Source-If-Modified-Since': last_modified_since,
                  'Date': self.get_date_header()}
        status, header, body = \
            self._test_object_PUT_copy(swob.HTTPOk, header)
        self.assertEquals(status.split()[0], '200')
        self.assertEquals(len(self.swift.calls_with_headers), 2)
        _, _, headers = self.swift.calls_with_headers[-1]
        self.assertTrue(headers.get('If-Match') is None)
        self.assertTrue(headers.get('If-Modified-Since') is None)
        _, _, headers = self.swift.calls_with_headers[0]
        self.assertEquals(headers['If-Match'], etag)
        self.assertEquals(headers['If-Modified-Since'], last_modified_since)

    @s3acl(s3acl_only=True)
    def test_object_PUT_copy_headers_with_match_and_s3acl(self):
        etag = '7dfa07a8e59ddbcd1dc84d4c4f82aea1'
        last_modified_since = 'Fri, 01 Apr 2014 11:00:00 GMT'

        header = {'X-Amz-Copy-Source-If-Match': etag,
                  'X-Amz-Copy-Source-If-Modified-Since': last_modified_since,
                  'Date': self.get_date_header()}
        status, header, body = \
            self._test_object_PUT_copy(swob.HTTPOk, header)

        self.assertEquals(status.split()[0], '200')
        self.assertEquals(len(self.swift.calls_with_headers), 3)
        # After the check of the copy source in the case of s3acl is valid,
        # Swift3 check the bucket write permissions of the destination.
        _, _, headers = self.swift.calls_with_headers[-2]
        self.assertTrue(headers.get('If-Match') is None)
        self.assertTrue(headers.get('If-Modified-Since') is None)
        _, _, headers = self.swift.calls_with_headers[-1]
        self.assertTrue(headers.get('If-Match') is None)
        self.assertTrue(headers.get('If-Modified-Since') is None)
        _, _, headers = self.swift.calls_with_headers[0]
        self.assertEquals(headers['If-Match'], etag)
        self.assertEquals(headers['If-Modified-Since'], last_modified_since)

    def test_object_PUT_copy_headers_with_not_match(self):
        etag = '7dfa07a8e59ddbcd1dc84d4c4f82aea1'
        last_modified_since = 'Fri, 01 Apr 2014 12:00:00 GMT'

        header = {'X-Amz-Copy-Source-If-None-Match': etag,
                  'X-Amz-Copy-Source-If-Unmodified-Since': last_modified_since,
                  'Date': self.get_date_header()}
        status, header, body = \
            self._test_object_PUT_copy(swob.HTTPOk, header)

        self.assertEquals(status.split()[0], '200')
        self.assertEquals(len(self.swift.calls_with_headers), 2)
        _, _, headers = self.swift.calls_with_headers[-1]
        self.assertTrue(headers.get('If-None-Match') is None)
        self.assertTrue(headers.get('If-Unmodified-Since') is None)
        _, _, headers = self.swift.calls_with_headers[0]
        self.assertEquals(headers['If-None-Match'], etag)
        self.assertEquals(headers['If-Unmodified-Since'], last_modified_since)

    @s3acl(s3acl_only=True)
    def test_object_PUT_copy_headers_with_not_match_and_s3acl(self):
        etag = '7dfa07a8e59ddbcd1dc84d4c4f82aea1'
        last_modified_since = 'Fri, 01 Apr 2014 12:00:00 GMT'

        header = {'X-Amz-Copy-Source-If-None-Match': etag,
                  'X-Amz-Copy-Source-If-Unmodified-Since': last_modified_since,
                  'Date': self.get_date_header()}
        status, header, body = \
            self._test_object_PUT_copy(swob.HTTPOk, header)
        self.assertEquals(status.split()[0], '200')
        # After the check of the copy source in the case of s3acl is valid,
        # Swift3 check the bucket write permissions of the destination.
        self.assertEquals(len(self.swift.calls_with_headers), 3)
        _, _, headers = self.swift.calls_with_headers[-1]
        self.assertTrue(headers.get('If-None-Match') is None)
        self.assertTrue(headers.get('If-Unmodified-Since') is None)
        _, _, headers = self.swift.calls_with_headers[0]
        self.assertEquals(headers['If-None-Match'], etag)
        self.assertEquals(headers['If-Unmodified-Since'], last_modified_since)

    @s3acl
    def test_object_POST_error(self):
        code = self._test_method_error('POST', '/bucket/object', None)
        self.assertEquals(code, 'NotImplemented')

    @s3acl
    def test_object_DELETE_error(self):
        code = self._test_method_error('DELETE', '/bucket/object',
                                       swob.HTTPUnauthorized)
        self.assertEquals(code, 'SignatureDoesNotMatch')
        code = self._test_method_error('DELETE', '/bucket/object',
                                       swob.HTTPForbidden)
        self.assertEquals(code, 'AccessDenied')
        code = self._test_method_error('DELETE', '/bucket/object',
                                       swob.HTTPServerError)
        self.assertEquals(code, 'InternalError')
        code = self._test_method_error('DELETE', '/bucket/object',
                                       swob.HTTPServiceUnavailable)
        self.assertEquals(code, 'InternalError')

        with patch('swift3.request.get_container_info',
                   return_value={'status': 204}):
            code = self._test_method_error('DELETE', '/bucket/object',
                                           swob.HTTPNotFound)
            self.assertEquals(code, 'NoSuchKey')

        with patch('swift3.request.get_container_info',
                   return_value={'status': 404}):
            code = self._test_method_error('DELETE', '/bucket/object',
                                           swob.HTTPNotFound)
            self.assertEquals(code, 'NoSuchBucket')

    @s3acl
    @patch('swift3.cfg.CONF.allow_multipart_uploads', False)
    def test_object_DELETE_no_multipart(self):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '204')

        self.assertNotIn(('HEAD', '/v1/AUTH_test/bucket/object'),
                         self.swift.calls)
        self.assertIn(('DELETE', '/v1/AUTH_test/bucket/object'),
                      self.swift.calls)
        _, path = self.swift.calls[-1]
        self.assertEquals(path.count('?'), 0)

    @s3acl
    def test_object_DELETE_multipart(self):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '204')

        self.assertIn(('HEAD', '/v1/AUTH_test/bucket/object'),
                      self.swift.calls)
        self.assertIn(('DELETE', '/v1/AUTH_test/bucket/object'),
                      self.swift.calls)
        _, path = self.swift.calls[-1]
        self.assertEquals(path.count('?'), 0)

    @s3acl
    def test_slo_object_DELETE(self):
        self.swift.register('HEAD', '/v1/AUTH_test/bucket/object',
                            swob.HTTPOk,
                            {'x-static-large-object': 'True'},
                            None)
        self.swift.register('DELETE', '/v1/AUTH_test/bucket/object',
                            swob.HTTPOk, {}, '<SLO delete results>')
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'Content-Type': 'foo/bar'})
        status, headers, body = self.call_swift3(req)
        self.assertEqual(status.split()[0], '204')
        self.assertEqual(body, '')

        self.assertIn(('HEAD', '/v1/AUTH_test/bucket/object'),
                      self.swift.calls)
        self.assertIn(('DELETE', '/v1/AUTH_test/bucket/object'
                                 '?multipart-manifest=delete'),
                      self.swift.calls)
        _, path, headers = self.swift.calls_with_headers[-1]
        path, query_string = path.split('?', 1)
        query = {}
        for q in query_string.split('&'):
            key, arg = q.split('=')
            query[key] = arg
        self.assertEquals(query['multipart-manifest'], 'delete')
        self.assertNotIn('Content-Type', headers)

    def _test_object_for_s3acl(self, method, account):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': method},
                            headers={'Authorization': 'AWS %s:hmac' % account,
                                     'Date': self.get_date_header()})
        return self.call_swift3(req)

    def _test_set_container_permission(self, account, permission):
        grants = [Grant(User(account), permission)]
        headers = \
            encode_acl('container',
                       ACL(Owner('test:tester', 'test:tester'), grants))
        self.swift.register('HEAD', '/v1/AUTH_test/bucket',
                            swob.HTTPNoContent, headers, None)

    @s3acl(s3acl_only=True)
    def test_object_GET_without_permission(self):
        status, headers, body = self._test_object_for_s3acl('GET',
                                                            'test:other')
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    @s3acl(s3acl_only=True)
    def test_object_GET_with_read_permission(self):
        status, headers, body = self._test_object_for_s3acl('GET',
                                                            'test:read')
        self.assertEquals(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_object_GET_with_fullcontrol_permission(self):
        status, headers, body = \
            self._test_object_for_s3acl('GET', 'test:full_control')
        self.assertEquals(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_object_PUT_without_permission(self):
        status, headers, body = self._test_object_for_s3acl('PUT',
                                                            'test:other')
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    @s3acl(s3acl_only=True)
    def test_object_PUT_with_owner_permission(self):
        status, headers, body = self._test_object_for_s3acl('PUT',
                                                            'test:tester')
        self.assertEquals(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_object_PUT_with_write_permission(self):
        account = 'test:other'
        self._test_set_container_permission(account, 'WRITE')
        status, headers, body = self._test_object_for_s3acl('PUT', account)
        self.assertEquals(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_object_PUT_with_fullcontrol_permission(self):
        account = 'test:other'
        self._test_set_container_permission(account, 'FULL_CONTROL')
        status, headers, body = \
            self._test_object_for_s3acl('PUT', account)
        self.assertEquals(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_object_DELETE_without_permission(self):
        account = 'test:other'
        status, headers, body = self._test_object_for_s3acl('DELETE',
                                                            account)
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    @s3acl(s3acl_only=True)
    def test_object_DELETE_with_owner_permission(self):
        status, headers, body = self._test_object_for_s3acl('DELETE',
                                                            'test:tester')
        self.assertEquals(status.split()[0], '204')

    @s3acl(s3acl_only=True)
    def test_object_DELETE_with_write_permission(self):
        account = 'test:other'
        self._test_set_container_permission(account, 'WRITE')
        status, headers, body = self._test_object_for_s3acl('DELETE',
                                                            account)
        self.assertEquals(status.split()[0], '204')

    @s3acl(s3acl_only=True)
    def test_object_DELETE_with_fullcontrol_permission(self):
        account = 'test:other'
        self._test_set_container_permission(account, 'FULL_CONTROL')
        status, headers, body = self._test_object_for_s3acl('DELETE', account)
        self.assertEquals(status.split()[0], '204')

    def _test_object_copy_for_s3acl(self, account, src_permission=None,
                                    src_path='/src_bucket/src_obj'):
        owner = 'test:tester'
        grants = [Grant(User(account), src_permission)] \
            if src_permission else [Grant(User(owner), 'FULL_CONTROL')]
        src_o_headers = \
            encode_acl('object', ACL(Owner(owner, owner), grants))
        src_o_headers.update({'last-modified': self.last_modified})
        self.swift.register(
            'HEAD', join('/v1/AUTH_test', src_path.lstrip('/')),
            swob.HTTPOk, src_o_headers, None)

        req = Request.blank(
            '/bucket/object',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'Authorization': 'AWS %s:hmac' % account,
                     'X-Amz-Copy-Source': src_path,
                     'Date': self.get_date_header()})

        return self.call_swift3(req)

    @s3acl(s3acl_only=True)
    def test_object_PUT_copy_with_owner_permission(self):
        status, headers, body = \
            self._test_object_copy_for_s3acl('test:tester')
        self.assertEquals(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_object_PUT_copy_with_fullcontrol_permission(self):
        status, headers, body = \
            self._test_object_copy_for_s3acl('test:full_control',
                                             'FULL_CONTROL')
        self.assertEquals(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_object_PUT_copy_with_grantee_permission(self):
        status, headers, body = \
            self._test_object_copy_for_s3acl('test:write', 'READ')
        self.assertEquals(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_object_PUT_copy_without_src_obj_permission(self):
        status, headers, body = \
            self._test_object_copy_for_s3acl('test:write')
        self.assertEquals(status.split()[0], '403')

    @s3acl(s3acl_only=True)
    def test_object_PUT_copy_without_dst_container_permission(self):
        status, headers, body = \
            self._test_object_copy_for_s3acl('test:other', 'READ')
        self.assertEquals(status.split()[0], '403')

    @s3acl(s3acl_only=True)
    def test_object_PUT_copy_empty_src_path(self):
        self.swift.register('PUT', '/v1/AUTH_test/bucket/object',
                            swob.HTTPPreconditionFailed, {}, None)
        status, headers, body = self._test_object_copy_for_s3acl(
            'test:write', 'READ', src_path='')
        self.assertEquals(status.split()[0], '400')

if __name__ == '__main__':
    unittest.main()
