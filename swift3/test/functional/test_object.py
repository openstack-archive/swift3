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

from swift3.test.functional.s3_test_client import Connection
from swift3.test.functional.utils import cleanup, get_error_code,\
    check_common_response_headers


class TestSwift3Object(unittest.TestCase):
    def setUp(self):
        self.conn = Connection()
        self.conn.set_tester1()
        cleanup(self.conn)

    def tearDown(self):
        self.conn.set_tester1()
        cleanup(self.conn)

    def test_object(self):
        bucket = 'bucket'
        obj = 'object'
        contents = 'abc123'
        self.conn.make_request('PUT', bucket)

        # PUT Object
        status, headers, body = \
            self.conn.make_request('PUT', bucket, obj, body=contents)
        self.assertEquals(status, 200)

        check_common_response_headers(self, headers)
        self.assertTrue(headers['etag'] is not None)
        self.assertEquals(headers['content-length'], '0')

        # GET Object
        status, headers, body = \
            self.conn.make_request('GET', bucket, obj)
        self.assertEquals(status, 200)

        check_common_response_headers(self, headers)
        self.assertTrue(headers['last-modified'] is not None)
        self.assertTrue(headers['etag'] is not None)
        self.assertTrue(headers['content-type'] is not None)
        self.assertEquals(headers['content-length'], str(len(contents)))

        # HEAD Object
        status, headers, body = \
            self.conn.make_request('HEAD', bucket, obj)
        self.assertEquals(status, 200)

        check_common_response_headers(self, headers)
        self.assertTrue(headers['last-modified'] is not None)
        self.assertTrue(headers['etag'] is not None)
        self.assertTrue(headers['content-type'] is not None)
        self.assertEquals(headers['content-length'], str(len(contents)))

        # DELETE Object
        status, headers, body = self.conn.make_request('DELETE', bucket, obj)
        self.assertEquals(status, 204)

        check_common_response_headers(self, headers)

        self.conn.make_request('DELETE', bucket)

    def test_put_object_error(self):
        bucket = 'bucket'
        self.conn.make_request('PUT', bucket)

        self.conn.aws_secret_key = 'invalid'
        status, headers, body = self.conn.make_request('PUT', bucket, 'object')
        self.assertEquals(get_error_code(body), 'SignatureDoesNotMatch')
        self.conn.set_tester1()

        status, headers, body = \
            self.conn.make_request('PUT', 'bucket2', 'object')
        self.assertEquals(get_error_code(body), 'NoSuchBucket')

        self.conn.make_request('DELETE', bucket)

    def test_get_object_error(self):
        bucket = 'bucket'
        obj = 'object'
        self.conn.make_request('PUT', bucket)
        self.conn.make_request('PUT', bucket, obj)

        self.conn.aws_secret_key = 'invalid'
        status, headers, body = self.conn.make_request('GET', bucket, obj)
        self.assertEquals(get_error_code(body), 'SignatureDoesNotMatch')
        self.conn.set_tester1()

        status, headers, body = \
            self.conn.make_request('GET', bucket, 'invalid')
        self.assertEquals(get_error_code(body), 'NoSuchKey')

        status, headers, body = self.conn.make_request('GET', 'invalid', obj)
        # TODO; requires consideration
        # self.assertEquals(get_error_code(body), 'NoSuchBucket')
        self.assertEquals(get_error_code(body), 'NoSuchKey')

        self.conn.make_request('DELETE', bucket, obj)
        self.conn.make_request('DELETE', bucket)

    def test_head_object_error(self):
        bucket = 'bucket'
        obj = 'object'
        self.conn.make_request('PUT', bucket)
        self.conn.make_request('PUT', bucket, obj)

        self.conn.aws_secret_key = 'invalid'
        status, headers, body = self.conn.make_request('HEAD', bucket, obj)
        self.assertEquals(status, 403)
        self.conn.set_tester1()

        status, headers, body = \
            self.conn.make_request('HEAD', bucket, 'invalid')
        self.assertEquals(status, 404)

        status, headers, body = \
            self.conn.make_request('HEAD', 'invalid', obj)
        self.assertEquals(status, 404)

        self.conn.make_request('DELETE', bucket, obj)
        self.conn.make_request('DELETE', bucket)

    def test_delete_object_error(self):
        bucket = 'bucket'
        obj = 'object'
        self.conn.make_request('PUT', bucket)
        self.conn.make_request('PUT', bucket, obj)

        self.conn.aws_secret_key = 'invalid'
        status, headers, body = self.conn.make_request('DELETE', bucket, obj)
        self.assertEquals(get_error_code(body), 'SignatureDoesNotMatch')
        self.conn.set_tester1()

        status, headers, body = \
            self.conn.make_request('DELETE', bucket, 'invalid')
        self.assertEquals(get_error_code(body), 'NoSuchKey')

        status, headers, body = \
            self.conn.make_request('DELETE', 'invalid', obj)
        # TODO; requires consideration
        # self.assertEquals(get_error_code(body), 'NoSuchBucket')
        self.assertEquals(get_error_code(body), 'NoSuchKey')

        self.conn.make_request('DELETE', bucket, obj)
        self.conn.make_request('DELETE', bucket)

if __name__ == '__main__':
    unittest.main()
