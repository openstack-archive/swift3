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
from swift3.test.functional.s3_test_client import Connection
from swift3.test.functional.utils import assert_common_response_headers, \
    get_error_code
from swift3.etree import fromstring


class TestSwift3Acl(Swift3FunctionalTestCase):
    def setUp(self):
        super(TestSwift3Acl, self).setUp()
        self.bucket = 'bucket'
        self.conn.make_request('PUT', self.bucket)

    def test_acl(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)
        query = 'acl'

        # PUT Bucket ACL
        headers = {'x-amz-acl': 'public-read'}
        status, headers, body = \
            self.conn.make_request('PUT', self.bucket, headers=headers,
                                   query=query)
        self.assertEquals(status, 200)
        assert_common_response_headers(self, headers)
        self.assertEquals(headers['content-length'], '0')

        # GET Bucket ACL
        status, headers, body = \
            self.conn.make_request('GET', self.bucket, query=query)
        self.assertEquals(status, 200)
        assert_common_response_headers(self, headers)
        # TODO: Fix the response that last-modified must be in the response.
        # self.assertTrue(headers['last-modified'] is not None)
        self.assertEquals(headers['content-length'], str(len(body)))
        self.assertTrue(headers['content-type'] is not None)
        elem = fromstring(body, 'AccessControlPolicy')
        owner = elem.find('Owner')
        self.assertEquals(owner.find('ID').text, self.conn.user_id)
        self.assertEquals(owner.find('DisplayName').text, self.conn.user_id)
        acl = elem.find('AccessControlList')
        self.assertTrue(acl.find('Grant') is not None)

        # GET Object ACL
        status, headers, body = \
            self.conn.make_request('GET', self.bucket, obj, query=query)
        self.assertEquals(status, 200)
        assert_common_response_headers(self, headers)
        # TODO: Fix the response that last-modified must be in the response.
        # self.assertTrue(headers['last-modified'] is not None)
        self.assertEquals(headers['content-length'], str(len(body)))
        self.assertTrue(headers['content-type'] is not None)
        elem = fromstring(body, 'AccessControlPolicy')
        owner = elem.find('Owner')
        self.assertEquals(owner.find('ID').text, self.conn.user_id)
        self.assertEquals(owner.find('DisplayName').text, self.conn.user_id)
        acl = elem.find('AccessControlList')
        self.assertTrue(acl.find('Grant') is not None)

    def test_put_bucket_acl_error(self):
        req_headers = {'x-amz-acl': 'public-read'}
        aws_error_conn = Connection(aws_secret_key='invalid')
        status, headers, body = \
            aws_error_conn.make_request('PUT', self.bucket,
                                        headers=req_headers, query='acl')
        self.assertEquals(get_error_code(body), 'SignatureDoesNotMatch')

        status, headers, body = \
            self.conn.make_request('PUT', 'nothing',
                                   headers=req_headers, query='acl')
        self.assertEquals(get_error_code(body), 'NoSuchBucket')

    def test_get_bucket_acl_error(self):
        aws_error_conn = Connection(aws_secret_key='invalid')
        status, headers, body = \
            aws_error_conn.make_request('GET', self.bucket, query='acl')
        self.assertEquals(get_error_code(body), 'SignatureDoesNotMatch')

        status, headers, body = \
            self.conn.make_request('GET', 'nothing', query='acl')
        self.assertEquals(get_error_code(body), 'NoSuchBucket')

    def test_get_object_acl_error(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)

        aws_error_conn = Connection(aws_secret_key='invalid')
        status, headers, body = \
            aws_error_conn.make_request('GET', self.bucket, obj, query='acl')
        self.assertEquals(get_error_code(body), 'SignatureDoesNotMatch')

        status, headers, body = \
            self.conn.make_request('GET', self.bucket, 'nothing', query='acl')
        self.assertEquals(get_error_code(body), 'NoSuchKey')

if __name__ == '__main__':
    unittest.main()
