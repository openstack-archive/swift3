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

from swift.common import swob
from swift.common.swob import Request

from swift3.test.unit import Swift3TestCase


class TestSwift3Obj(Swift3TestCase):

    def setUp(self):
        super(TestSwift3Obj, self).setUp()

        self.object_body = 'hello'
        etag = hashlib.md5(self.object_body).hexdigest()

        self.response_headers = {'Content-Type': 'text/html',
                                 'Content-Length': len(self.object_body),
                                 'x-object-meta-test': 'swift',
                                 'etag': etag,
                                 'last-modified': '2011-01-05T02:19:14.275290'}

        self.swift.register('GET', '/v1/AUTH_test/bucket/object',
                            swob.HTTPOk, self.response_headers,
                            self.object_body)

    def _test_object_GETorHEAD(self, method):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': method},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

        for key, val in self.response_headers.iteritems():
            if key in ('content-length', 'content-type', 'content-encoding',
                       'last-modified'):
                self.assertTrue(key in headers)
                self.assertEquals(headers[key], val)

            elif key.startswith('x-object-meta-'):
                self.assertTrue('x-amz-meta-' + key[14:] in headers)
                self.assertEquals(headers['x-amz-meta-' + key[14:]], val)

        self.assertEquals(headers['etag'],
                          '"%s"' % self.response_headers['etag'])

        if method == 'GET':
            self.assertEquals(body, self.object_body)

    def test_object_HEAD_error(self):
        # HEAD does not return the body even an error resonse in the
        # specifications of the REST API.
        # So, check the response code for error test of HEAD.
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'HEAD'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        self.swift.register('HEAD', '/v1/AUTH_test/bucket/object',
                            swob.HTTPUnauthorized, {}, None)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '403')
        self.swift.register('HEAD', '/v1/AUTH_test/bucket/object',
                            swob.HTTPForbidden, {}, None)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '403')
        self.swift.register('HEAD', '/v1/AUTH_test/bucket/object',
                            swob.HTTPNotFound, {}, None)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '404')
        self.swift.register('HEAD', '/v1/AUTH_test/bucket/object',
                            swob.HTTPPreconditionFailed, {}, None)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '412')
        self.swift.register('HEAD', '/v1/AUTH_test/bucket/object',
                            swob.HTTPServerError, {}, None)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '500')
        self.swift.register('HEAD', '/v1/AUTH_test/bucket/object',
                            swob.HTTPServiceUnavailable, {}, None)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '500')

    def test_object_HEAD(self):
        self._test_object_GETorHEAD('HEAD')

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

    def test_object_GET(self):
        self._test_object_GETorHEAD('GET')

    def test_object_GET_Range(self):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Range': 'bytes=0-3'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '206')

        self.assertTrue('content-range' in headers)
        self.assertTrue(headers['content-range'].startswith('bytes 0-3'))

    def test_object_GET_Range_error(self):
        code = self._test_method_error('GET', '/bucket/object',
                                       swob.HTTPRequestedRangeNotSatisfiable)
        self.assertEquals(code, 'InvalidRange')

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
                            headers={'Authorization': 'AWS test:tester:hmac'})
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
        self.assertEquals(code, 'InvalidDigest')
        code = self._test_method_error('PUT', '/bucket/object',
                                       swob.HTTPLengthRequired)
        self.assertEquals(code, 'MissingContentLength')
        code = self._test_method_error('PUT', '/bucket/object',
                                       swob.HTTPServiceUnavailable)
        self.assertEquals(code, 'InternalError')

    def test_object_PUT(self):
        etag = self.response_headers['etag']
        content_md5 = etag.decode('hex').encode('base64').strip()

        req = Request.blank(
            '/bucket/object',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'x-amz-storage-class': 'STANDARD',
                     'Content-MD5': content_md5},
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
        etag = '7dfa07a8e59ddbcd1dc84d4c4f82aea1'
        content_md5 = etag.decode('hex').encode('base64').strip()

        self.swift.register('PUT', '/v1/AUTH_test/bucket/object',
                            swob.HTTPCreated,
                            {'etag': etag},
                            None)
        req = Request.blank(
            '/bucket/object',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'X-Amz-Storage-Class': 'STANDARD',
                     'X-Amz-Meta-Something': 'oh hai',
                     'X-Amz-Copy-Source': '/some/source',
                     'Content-MD5': content_md5})
        req.date = datetime.now()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        # Check that swift3 returns an etag header.
        self.assertEquals(headers['etag'], '"%s"' % etag)

        _, _, headers = self.swift.calls_with_headers[-1]
        # Check that swift3 converts a Content-MD5 header into an etag.
        self.assertEquals(headers['ETag'], etag)
        self.assertEquals(headers['X-Object-Meta-Something'], 'oh hai')
        self.assertEquals(headers['X-Copy-From'], '/some/source')
        self.assertEquals(headers['Content-Length'], '0')

    def test_object_DELETE_error(self):
        code = self._test_method_error('DELETE', '/bucket/object',
                                       swob.HTTPUnauthorized)
        self.assertEquals(code, 'SignatureDoesNotMatch')
        code = self._test_method_error('DELETE', '/bucket/object',
                                       swob.HTTPForbidden)
        self.assertEquals(code, 'AccessDenied')
        code = self._test_method_error('DELETE', '/bucket/object',
                                       swob.HTTPNotFound)
        self.assertEquals(code, 'NoSuchKey')
        code = self._test_method_error('DELETE', '/bucket/object',
                                       swob.HTTPServerError)
        self.assertEquals(code, 'InternalError')
        code = self._test_method_error('DELETE', '/bucket/object',
                                       swob.HTTPServiceUnavailable)
        self.assertEquals(code, 'InternalError')

    def test_object_DELETE(self):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '204')

if __name__ == '__main__':
    unittest.main()
