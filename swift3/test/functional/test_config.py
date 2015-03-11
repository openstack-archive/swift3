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

from swift3.test.functional.s3_test_client import get_tester_connection, \
    get_tester2_connection
from swift3.test.functional.utils import reload_proxy_server_conf
from swift3.etree import fromstring


class TestSwift3Config(unittest.TestCase):
    @classmethod
    def setUpClass(self):
        params = {
            's3_acl': 'true',
            'check_bucket_owner': 'true'
        }
        reload_proxy_server_conf(params)

    @classmethod
    def tearDownClass(self):
        reload_proxy_server_conf()

    def setUp(self):
        self.conn_tester = get_tester_connection()
        self.conn_tester2 = get_tester2_connection()
        self.conn_tester.reset()
        self.conn_tester2.reset()

    def test_check_bucket_owner(self):
        bucket1 = 'bucket1'
        bucket2 = 'bucket2'
        self.conn_tester.make_request('PUT', bucket1)
        self.conn_tester2.make_request('PUT', bucket2)

        status, headers, body = self.conn_tester.make_request('GET')
        self.assertEquals(status, 200)
        elem = fromstring(body, 'ListAllMyBucketsResult')
        resp_buckets = elem.findall('./Buckets/Bucket')
        self.assertEquals(len(list(resp_buckets)), 1)
        for b in resp_buckets:
            self.assertEquals(b.find('Name').text, bucket1)
            self.assertTrue(b.find('CreationDate') is not None)

        status, headers, body = self.conn_tester2.make_request('GET')
        self.assertEquals(status, 200)
        elem = fromstring(body, 'ListAllMyBucketsResult')
        resp_buckets = elem.findall('./Buckets/Bucket')
        self.assertEquals(len(list(resp_buckets)), 1)
        for b in resp_buckets:
            self.assertEquals(b.find('Name').text, bucket2)
            self.assertTrue(b.find('CreationDate') is not None)
