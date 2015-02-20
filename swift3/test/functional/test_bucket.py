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
from swift3.etree import fromstring
from swift3.cfg import CONF


class TestSwift3Bucket(unittest.TestCase):
    def setUp(self):
        self.conn = Connection()
        self.conn.set_tester1()
        cleanup(self.conn)

    def tearDown(self):
        self.conn.set_tester1()
        cleanup(self.conn)

    def test_bucket(self):
        bucket = 'bucket'

        # PUT Bucket
        status, headers, body = self.conn.make_request('PUT', bucket)
        self.assertEquals(status, 200)

        check_common_response_headers(self, headers)
        self.assertEquals(headers['location'], '/' + bucket)
        self.assertEquals(headers['content-length'], '0')

        # GET Bucket(Without Object)
        status, headers, body = self.conn.make_request('GET', bucket)
        self.assertEquals(status, 200)

        check_common_response_headers(self, headers)
        self.assertTrue(headers['content-type'] is not None)
        self.assertEquals(headers['content-length'], str(len(body)))
        # TODO; requires consideration
        # self.assertEquasl(headers['transfer-encoding'], 'chunked')

        elem = fromstring(body, 'ListBucketResult')
        self.assertEquals(elem.find('Name').text, bucket)
        self.assertEquals(elem.find('Prefix').text, None)
        self.assertEquals(elem.find('Marker').text, None)
        self.assertEquals(elem.find('MaxKeys').text,
                          str(CONF.max_bucket_listing))
        self.assertEquals(elem.find('IsTruncated').text, 'false')
        objects = elem.findall('./Contents')
        self.assertEquals(list(objects), [])

        # GET Bucket(With Object)
        req_objects = ('object', 'object2')
        for obj in req_objects:
            self.conn.make_request('PUT', bucket, obj)
        status, headers, body = self.conn.make_request('GET', bucket)
        self.assertEquals(status, 200)

        elem = fromstring(body, 'ListBucketResult')
        self.assertEquals(elem.find('Name').text, bucket)
        self.assertEquals(elem.find('Prefix').text, None)
        self.assertEquals(elem.find('Marker').text, None)
        self.assertEquals(elem.find('MaxKeys').text,
                          str(CONF.max_bucket_listing))
        self.assertEquals(elem.find('IsTruncated').text, 'false')
        resp_objects = elem.findall('./Contents')
        self.assertEquals(len(list(resp_objects)), 2)
        for o in resp_objects:
            self.assertTrue(o.find('Key').text in req_objects)
            self.assertTrue(o.find('LastModified').text is not None)
            self.assertTrue(o.find('ETag').text is not None)
            self.assertTrue(o.find('Size').text is not None)
            self.assertTrue(o.find('StorageClass').text is not None)
            self.assertTrue(o.find('Owner/ID').text, self.conn.user_id)
            self.assertTrue(o.find('Owner/DisplayName').text,
                            self.conn.user_id)

        # HEAD Bucket
        status, headers, body = self.conn.make_request('HEAD', bucket)
        self.assertEquals(status, 200)

        check_common_response_headers(self, headers)
        self.assertTrue(headers['content-type'] is not None)
        self.assertEquals(headers['content-length'], str(len(body)))
        # TODO; requires consideration
        # self.assertEquasl(headers['transfer-encoding'], 'chunked')

        # DELETE Bucket
        for obj in req_objects:
            self.conn.make_request('DELETE', bucket, obj)
        status, headers, body = self.conn.make_request('DELETE', bucket)
        self.assertEquals(status, 204)

        check_common_response_headers(self, headers)

    def test_put_bucket_error(self):
        status, headers, body = \
            self.conn.make_request('PUT', 'bucket+invalid')
        self.assertEquals(get_error_code(body), 'InvalidBucketName')

        self.conn.aws_secret_key = 'invalid'
        status, headers, body = self.conn.make_request('PUT', 'bucket')
        self.assertEquals(get_error_code(body), 'SignatureDoesNotMatch')
        self.conn.set_tester1()

        self.conn.make_request('PUT', 'bucket')
        status, headers, body = self.conn.make_request('PUT', 'bucket')
        self.assertEquals(get_error_code(body), 'BucketAlreadyExists')
        self.conn.make_request('DELETE', 'bucket')

    def test_get_bucket_error(self):
        self.conn.make_request('PUT', 'bucket')

        status, headers, body = \
            self.conn.make_request('GET', 'bucket+invalid')
        self.assertEquals(get_error_code(body), 'InvalidBucketName')

        self.conn.aws_secret_key = 'invalid'
        status, headers, body = self.conn.make_request('GET', 'bucket')
        self.assertEquals(get_error_code(body), 'SignatureDoesNotMatch')
        self.conn.set_tester1()

        status, headers, body = self.conn.make_request('GET', 'nothing')
        self.assertEquals(get_error_code(body), 'NoSuchBucket')

        self.conn.make_request('DELETE', 'bucket')

    def test_head_bucket_error(self):
        self.conn.make_request('PUT', 'bucket')

        status, headers, body = \
            self.conn.make_request('HEAD', 'bucket+invalid')
        self.assertEquals(status, 400)

        self.conn.aws_secret_key = 'invalid'
        status, headers, body = self.conn.make_request('HEAD', 'bucket')
        self.assertEquals(status, 403)
        self.conn.set_tester1()

        status, headers, body = self.conn.make_request('HEAD', 'nothing')
        self.assertEquals(status, 404)

        self.conn.make_request('DELETE', 'bucket')

    def test_delete_bucket_error(self):
        status, headers, body = \
            self.conn.make_request('DELETE', 'bucket+invalid')
        self.assertEquals(get_error_code(body), 'InvalidBucketName')

        self.conn.aws_secret_key = 'invalid'
        status, headers, body = self.conn.make_request('DELETE', 'bucket')
        self.assertEquals(get_error_code(body), 'SignatureDoesNotMatch')
        self.conn.set_tester1()

        status, headers, body = self.conn.make_request('DELETE', 'bucket')
        self.assertEquals(get_error_code(body), 'NoSuchBucket')

if __name__ == '__main__':
    unittest.main()
