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
import simplejson

from swift.common import swob
from swift.common.swob import Request

from swift3.test.unit import Swift3TestCase
from swift3.test.unit.test_s3_acl import s3acl
from swift3.etree import fromstring
from swift3.subresource import ACL, Owner, encode_acl


class TestSwift3Service(Swift3TestCase):
    def setup_buckets(self):
        self.buckets = (('apple', 1, 200), ('orange', 3, 430))

        json_pattern = ['"name":%s', '"count":%s', '"bytes":%s']
        json_pattern = '{' + ','.join(json_pattern) + '}'
        json_out = []
        for b in self.buckets:
            name = simplejson.dumps(b[0])
            json_out.append(json_pattern %
                            (name, b[1], b[2]))
        bucket_list = '[' + ','.join(json_out) + ']'

        self.swift.register('GET', '/v1/AUTH_test', swob.HTTPOk, {},
                            bucket_list)

    def setUp(self):
        super(TestSwift3Service, self).setUp()

        self.setup_buckets()

    @s3acl
    def test_service_GET_error(self):
        code = self._test_method_error('GET', '', swob.HTTPUnauthorized)
        self.assertEquals(code, 'SignatureDoesNotMatch')
        code = self._test_method_error('GET', '', swob.HTTPForbidden)
        self.assertEquals(code, 'AccessDenied')
        code = self._test_method_error('GET', '', swob.HTTPServerError)
        self.assertEquals(code, 'InternalError')

    def test_service_GET(self):
        req = Request.blank('/',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

        elem = fromstring(body, 'ListAllMyBucketsResult')

        all_buckets = elem.find('./Buckets')
        buckets = all_buckets.iterchildren('Bucket')
        listing = list(list(buckets)[0])
        self.assertEquals(len(listing), 2)

        names = []
        for b in all_buckets.iterchildren('Bucket'):
            names.append(b.find('./Name').text)

        self.assertEquals(len(names), len(self.buckets))
        for i in self.buckets:
            self.assertTrue(i[0] in names)

    def test_service_GET_subresource(self):
        req = Request.blank('/?acl',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

        elem = fromstring(body, 'ListAllMyBucketsResult')

        all_buckets = elem.find('./Buckets')
        buckets = all_buckets.iterchildren('Bucket')
        listing = list(list(buckets)[0])
        self.assertEquals(len(listing), 2)

        names = []
        for b in all_buckets.iterchildren('Bucket'):
            names.append(b.find('./Name').text)

        self.assertEquals(len(names), len(self.buckets))
        for i in self.buckets:
            self.assertTrue(i[0] in names)

    def _test_service_GET_for_s3acl(self, buckets):
        json_pattern = ['"name":%s', '"count":%s', '"bytes":%s']
        json_pattern = '{' + ','.join(json_pattern) + '}'
        json_out = []

        for b in buckets:
            name = simplejson.dumps(b[0])
            json_out.append(json_pattern %
                            (name, b[1], b[2]))

        bucket_list = '[' + ','.join(json_out) + ']'
        self.swift.register('GET', '/v1/AUTH_test', swob.HTTPOk, {},
                            bucket_list)

        req = Request.blank('/',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        return self.call_swift3(req)

    @s3acl(s3acl_only=True)
    def test_service_GET_without_bucket(self):
        bucket_list = []
        for var in range(0, 10):
            bucket = 'bucket%s' % var
            self.swift.register('HEAD', '/v1/AUTH_test/%s' % bucket,
                                swob.HTTPNotFound, {}, None)
            bucket_list.append((bucket, var, 300 + var))

        status, headers, body = self._test_service_GET_for_s3acl(bucket_list)
        self.assertEquals(status.split()[0], '200')

        elem = fromstring(body, 'ListAllMyBucketsResult')

        resp_buckets = elem.find('./Buckets')
        buckets = resp_buckets.iterchildren('Bucket')
        self.assertEquals(len(list(buckets)), 0)

    @s3acl(s3acl_only=True)
    def test_service_GET_without_owner_bucket(self):
        bucket_list = []
        for var in range(0, 10):
            user_id = 'test:other'
            bucket = 'bucket%s' % var
            owner = Owner(user_id, user_id)
            headers = encode_acl('container', ACL(owner, []))
            self.swift.register('HEAD', '/v1/AUTH_test/%s' % bucket,
                                swob.HTTPNoContent, headers, None)
            bucket_list.append((bucket, var, 300 + var))

        status, headers, body = self._test_service_GET_for_s3acl(bucket_list)
        self.assertEquals(status.split()[0], '200')

        elem = fromstring(body, 'ListAllMyBucketsResult')

        resp_buckets = elem.find('./Buckets')
        buckets = resp_buckets.iterchildren('Bucket')
        self.assertEquals(len(list(buckets)), 0)

    @s3acl(s3acl_only=True)
    def test_service_GET_bucekt_list(self):
        bucket_list = []
        for var in range(0, 10):
            if var % 3 == 0:
                user_id = 'test:tester'
            else:
                user_id = 'test:other'
            bucket = 'bucket%s' % var
            owner = Owner(user_id, user_id)
            headers = encode_acl('container', ACL(owner, []))
            # set register to get owner of buckets
            if var % 3 == 2:
                self.swift.register('HEAD', '/v1/AUTH_test/%s' % bucket,
                                    swob.HTTPNotFound, {}, None)
            else:
                self.swift.register('HEAD', '/v1/AUTH_test/%s' % bucket,
                                    swob.HTTPNoContent, headers, None)
            bucket_list.append((bucket, var, 300 + var))

        status, headers, body = self._test_service_GET_for_s3acl(bucket_list)
        self.assertEquals(status.split()[0], '200')

        elem = fromstring(body, 'ListAllMyBucketsResult')
        resp_buckets = elem.find('./Buckets')
        buckets = resp_buckets.iterchildren('Bucket')
        listing = list(list(buckets)[0])
        self.assertEquals(len(listing), 2)

        names = []
        for b in resp_buckets.iterchildren('Bucket'):
            names.append(b.find('./Name').text)

        # Check whether getting bucket only locate in multiples of 3 in
        # bucket_list which mean requested user is owner.
        expected_buckets = [b for i, b in enumerate(bucket_list)
                            if i % 3 == 0]
        self.assertEquals(len(names), len(expected_buckets))
        for i in expected_buckets:
            self.assertTrue(i[0] in names)

if __name__ == '__main__':
    unittest.main()
