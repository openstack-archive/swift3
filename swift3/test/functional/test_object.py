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

from swift3.test.functional.s3_test_client import Connection
from swift3.test.functional.utils import get_error_code,\
    assert_common_response_headers
from swift3.test.functional import Swift3FunctionalTestCase
from swift3.etree import fromstring


class TestSwift3Object(Swift3FunctionalTestCase):
    def setUp(self):
        super(TestSwift3Object, self).setUp()
        self.bucket = 'bucket'
        self.conn.make_request('PUT', self.bucket)

    def test_object(self):
        obj = 'object'
        contents = 'abc123'

        # PUT Object
        status, headers, body = \
            self.conn.make_request('PUT', self.bucket, obj, body=contents)
        self.assertEquals(status, 200)

        assert_common_response_headers(self, headers)
        self.assertTrue(headers['etag'] is not None)
        self.assertEquals(headers['content-length'], '0')

        # PUT Object Copy
        self.conn.make_request('PUT', 'dst_bucket')
        headers = {'x-amz-copy-source': '/%s/%s' % (self.bucket, obj)}
        status, headers, body = \
            self.conn.make_request('PUT', 'dst_bucket', 'dst_obj',
                                   headers=headers)
        self.assertEquals(status, 200)

        assert_common_response_headers(self, headers)
        self.assertEquals(headers['content-length'], str(len(body)))

        elem = fromstring(body, 'CopyObjectResult')
        self.assertTrue(elem.find('LastModified').text is not None)
        self.assertTrue(elem.find('ETag').text is not None)

        # GET Object
        status, headers, body = \
            self.conn.make_request('GET', self.bucket, obj)
        self.assertEquals(status, 200)

        assert_common_response_headers(self, headers)
        self.assertTrue(headers['last-modified'] is not None)
        self.assertTrue(headers['etag'] is not None)
        self.assertTrue(headers['content-type'] is not None)
        self.assertEquals(headers['content-length'], str(len(contents)))

        # HEAD Object
        status, headers, body = \
            self.conn.make_request('HEAD', self.bucket, obj)
        self.assertEquals(status, 200)

        assert_common_response_headers(self, headers)
        self.assertTrue(headers['last-modified'] is not None)
        self.assertTrue(headers['etag'] is not None)
        self.assertTrue(headers['content-type'] is not None)
        self.assertEquals(headers['content-length'], str(len(contents)))

        # DELETE Object
        status, headers, body = \
            self.conn.make_request('DELETE', self.bucket, obj)
        self.assertEquals(status, 204)

        assert_common_response_headers(self, headers)

    def test_put_object_error(self):
        auth_error_conn = Connection(aws_secret_key='invalid')
        status, headers, body = \
            auth_error_conn.make_request('PUT', self.bucket, 'object')
        self.assertEquals(get_error_code(body), 'SignatureDoesNotMatch')

        status, headers, body = \
            self.conn.make_request('PUT', 'bucket2', 'object')
        self.assertEquals(get_error_code(body), 'NoSuchBucket')

    def test_put_object_copy_error(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)
        dst_bucket = 'dst_bucket'
        self.conn.make_request('PUT', dst_bucket)
        dst_obj = 'dst_object'

        headers = {'x-amz-copy-source': '/%s/%s' % (self.bucket, obj)}
        auth_error_conn = Connection(aws_secret_key='invalid')
        status, headers, body = \
            auth_error_conn.make_request('PUT', dst_bucket, dst_obj, headers)
        self.assertEquals(get_error_code(body), 'SignatureDoesNotMatch')

        # /src/nothing -> /dst/dst
        headers = {'X-Amz-Copy-Source': '/%s/%s' % (self.bucket, 'nothing')}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers)
        self.assertEquals(get_error_code(body), 'NoSuchKey')

        # /nothing/src -> /dst/dst
        headers = {'X-Amz-Copy-Source': '/%s/%s' % ('nothing', obj)}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers)
        # TODO: source bucket is not check.
        # self.assertEquals(get_error_code(body), 'NoSuchBucket')

        # /src/src -> /nothing/dst
        headers = {'X-Amz-Copy-Source': '/%s/%s' % (self.bucket, obj)}
        status, headers, body = \
            self.conn.make_request('PUT', 'nothing', dst_obj, headers)
        self.assertEquals(get_error_code(body), 'NoSuchBucket')

    def test_get_object_error(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)

        auth_error_conn = Connection(aws_secret_key='invalid')
        status, headers, body = \
            auth_error_conn.make_request('GET', self.bucket, obj)
        self.assertEquals(get_error_code(body), 'SignatureDoesNotMatch')

        status, headers, body = \
            self.conn.make_request('GET', self.bucket, 'invalid')
        self.assertEquals(get_error_code(body), 'NoSuchKey')

        status, headers, body = self.conn.make_request('GET', 'invalid', obj)
        # TODO; requires consideration
        # self.assertEquals(get_error_code(body), 'NoSuchBucket')
        self.assertEquals(get_error_code(body), 'NoSuchKey')

    def test_head_object_error(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)

        auth_error_conn = Connection(aws_secret_key='invalid')
        status, headers, body = \
            auth_error_conn.make_request('HEAD', self.bucket, obj)
        self.assertEquals(status, 403)

        status, headers, body = \
            self.conn.make_request('HEAD', self.bucket, 'invalid')
        self.assertEquals(status, 404)

        status, headers, body = \
            self.conn.make_request('HEAD', 'invalid', obj)
        self.assertEquals(status, 404)

    def test_delete_object_error(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)

        auth_error_conn = Connection(aws_secret_key='invalid')
        status, headers, body = \
            auth_error_conn.make_request('DELETE', self.bucket, obj)
        self.assertEquals(get_error_code(body), 'SignatureDoesNotMatch')

        status, headers, body = \
            self.conn.make_request('DELETE', self.bucket, 'invalid')
        self.assertEquals(get_error_code(body), 'NoSuchKey')

        status, headers, body = \
            self.conn.make_request('DELETE', 'invalid', obj)
        self.assertEquals(get_error_code(body), 'NoSuchBucket')

if __name__ == '__main__':
    unittest.main()
