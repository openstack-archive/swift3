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
from swift3.test.functional.utils import assert_common_response_headers
from swift3.etree import fromstring


class TestSwift3Acl(Swift3FunctionalTestCase):
    def setUp(self):
        super(TestSwift3Acl, self).setUp()

    def test_acl(self):
        bucket = 'bucket'
        obj = 'object'
        self.conn.make_request('PUT', bucket)
        self.conn.make_request('PUT', bucket, obj)
        query = 'acl'

        # PUT Bucket ACL
        headers = {'x-amz-acl': 'public-read'}
        status, headers, body = \
            self.conn.make_request('PUT', bucket, headers=headers,
                                   query=query)
        self.assertEquals(status, 200)
        assert_common_response_headers(self, headers)
        self.assertEquals(headers['content-length'], '0')

        # GET Bucket ACL
        status, headers, body = \
            self.conn.make_request('GET', bucket, query=query)
        self.assertEquals(status, 200)
        assert_common_response_headers(self, headers)
        # TODO: last-modified is not return.
        # self.assertTrue(headers['last-modified'] is not None)
        self.assertEquals(headers['content-length'], str(len(body)))
        self.assertTrue(headers['content-type'] is not None)
        elem = fromstring(body, 'AccessControlPolicy')
        owner = elem.find('Owner')
        self.assertEquals(owner.find('ID').text, self.conn.user_id)
        self.assertEquals(owner.find('DisplayName').text, self.conn.user_id)
        acl = elem.find('AccessControlList')
        self.assertTrue(acl.find('Grant') is not None)

        # PUT Object ACL
        # TODO: PUT Object ACL is not supported

        # GET Object ACL
        status, headers, body = \
            self.conn.make_request('GET', bucket, obj, query=query)
        self.assertEquals(status, 200)
        assert_common_response_headers(self, headers)
        # TODO: last-modified is not return.
        # self.assertTrue(headers['last-modified'] is not None)
        self.assertEquals(headers['content-length'], str(len(body)))
        self.assertTrue(headers['content-type'] is not None)
        elem = fromstring(body, 'AccessControlPolicy')
        owner = elem.find('Owner')
        self.assertEquals(owner.find('ID').text, self.conn.user_id)
        self.assertEquals(owner.find('DisplayName').text, self.conn.user_id)
        acl = elem.find('AccessControlList')
        self.assertTrue(acl.find('Grant') is not None)

if __name__ == '__main__':
    unittest.main()
