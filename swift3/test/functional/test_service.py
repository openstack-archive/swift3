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
from swift3.test.functional.utils import get_error_code
from swift3.etree import fromstring
from swift3.test.functional import Swift3FunctionalTestCase


class TestSwift3Service(Swift3FunctionalTestCase):
    def setUp(self):
        super(TestSwift3Service, self).setUp()

    def test_service(self):
        # GET Service(without bucket)
        status, headers, body = self.conn.make_request('GET')
        self.assertEquals(status, 200)

        self.assertCommonResponseHeaders(headers)
        self.assertTrue(headers['content-type'] is not None)
        # TODO; requires consideration
        # self.assertEquasl(headers['transfer-encoding'], 'chunked')

        elem = fromstring(body, 'ListAllMyBucketsResult')
        buckets = elem.findall('./Buckets/Bucket')
        self.assertEquals(list(buckets), [])
        owner = elem.find('Owner')
        self.assertEquals(self.conn.user_id, owner.find('ID').text)
        self.assertEquals(self.conn.user_id, owner.find('DisplayName').text)

        # GET Service(with Bucket)
        req_buckets = ('bucket', 'bucket2')
        for bucket in req_buckets:
            self.conn.make_request('PUT', bucket)
        status, headers, body = self.conn.make_request('GET')
        self.assertEquals(status, 200)

        elem = fromstring(body, 'ListAllMyBucketsResult')
        resp_buckets = elem.findall('./Buckets/Bucket')
        self.assertEquals(len(list(resp_buckets)), 2)
        for b in resp_buckets:
            self.assertTrue(b.find('Name').text in req_buckets)
            self.assertTrue(b.find('CreationDate') is not None)

    def test_service_error(self):
        auth_error_conn = Connection(aws_secret_key='invalid')
        status, headers, body = auth_error_conn.make_request('GET')
        self.assertEquals(get_error_code(body), 'SignatureDoesNotMatch')
        self.assertEquals(headers['content-type'], 'application/xml')

if __name__ == '__main__':
    unittest.main()
