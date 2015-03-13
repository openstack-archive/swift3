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
from nose.plugins.attrib import attr

from swift3.test.functional import Swift3FunctionalTestCase
from swift3.test.functional.s3_test_client import Connection
from swift3.test.functional.utils import get_error_code,\
    assert_common_response_headers
from swift3.etree import fromstring

ALL_USERS = 'http://acs.amazonaws.com/groups/global/AllUsers'
AUTHENTICATED_USERS = \
    'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
LOG_DELIVERY = 'http://acs.amazonaws.com/groups/s3/LogDelivery'
XMLNS_XSI = 'http://www.w3.org/2001/XMLSchema-instance'
MIN_SEGMENTS_SIZE = 5242880


@attr(s3acl=True)
class TestSwift3S3Acl(Swift3FunctionalTestCase):
    def setUp(self):
        super(TestSwift3S3Acl, self).setUp()
        self.bucket = 'bucket'
        self.conn.make_request('PUT', self.bucket)

    def _check_canned_acl(self, permission, bucket='bucket', obj='',
                          resp_body=None):
        check_grants = []
        if permission == 'private':
            check_grants = [('FULL_CONTROL', self.conn.user_id)]
        elif permission == 'public-read':
            check_grants = [('FULL_CONTROL', self.conn.user_id),
                            ('READ', ALL_USERS)]
        elif permission == 'public-read-write':
            check_grants = [('FULL_CONTROL', self.conn.user_id),
                            ('READ', ALL_USERS),
                            ('WRITE', ALL_USERS)]
        elif permission == 'authenticated-read':
            check_grants = [('FULL_CONTROL', self.conn.user_id),
                            ('READ', AUTHENTICATED_USERS)]
        elif permission == 'bucket-owner-read':
            status, headers, body = \
                self.conn.make_request('GET', bucket, query='acl')
            elem = fromstring(body, 'AccessControlPolicy')
            bucket_owner = elem.find('Owner/ID').text
            check_grants = [('FULL_CONTROL', self.conn.user_id),
                            ('READ', bucket_owner)]
        elif permission == 'bucket-owner-full-control':
            status, headers, body = \
                self.conn.make_request('GET', bucket, query='acl')
            elem = fromstring(body, 'AccessControlPolicy')
            bucket_owner = elem.find('Owner/ID').text
            check_grants = [('FULL_CONTROL', self.conn.user_id),
                            ('FULL_CONTROL', bucket_owner)]

        if not resp_body:
            status, headers, resp_body = \
                self.conn.make_request('GET', bucket, obj, query='acl')
            self.assertEquals(status, 200)

        elem = fromstring(resp_body, 'AccessControlPolicy')
        owner = elem.find('Owner')
        self.assertEquals(owner.find('ID').text, self.conn.user_id)
        self.assertEquals(owner.find('DisplayName').text, self.conn.user_id)
        acl = elem.find('AccessControlList')

        grants = acl.findall('Grant')
        self.assertEquals(len(grants), len(check_grants))

        for grant in grants:
            permission = grant.find('Permission').text
            grantee = grant.find('Grantee')
            grantee_type = grantee.get('{%s}type' % XMLNS_XSI)
            if grantee_type == 'Group':
                grantee_value = grantee.find('URI').text
            elif grantee_type == 'CanonicalUser':
                grantee_value = grantee.find('ID').text
            else:
                grantee_value = None
            self.assertTrue((permission, grantee_value) in check_grants)

    def test_s3acl(self):
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
        # TODO: last-modified is not return.
        # self.assertTrue(headers['last-modified'] is not None)
        self.assertEquals(headers['content-length'], str(len(body)))
        self.assertTrue(headers['content-type'] is not None)

        self._check_canned_acl('public-read', self.bucket, resp_body=body)

        # PUT Object ACL
        headers = {'x-amz-acl': 'public-read'}
        status, headers, body = \
            self.conn.make_request('PUT', self.bucket, obj, headers=headers,
                                   query=query)
        self.assertEquals(status, 200)
        assert_common_response_headers(self, headers)
        # TODO: last-modified is not return.
        # self.assertTrue(headers['last-modified'] is not None)
        self.assertEquals(headers['content-length'], '0')

        # GET Object ACL
        status, headers, body = \
            self.conn.make_request('GET', self.bucket, obj, query=query)
        self.assertEquals(status, 200)
        assert_common_response_headers(self, headers)
        # TODO: last-modified is not return.
        # self.assertTrue(headers['last-modified'] is not None)
        self.assertEquals(headers['content-length'], str(len(body)))
        self.assertTrue(headers['content-type'] is not None)

        self._check_canned_acl('public-read', self.bucket, obj, resp_body=body)

    def test_put_bucket_acl_error(self):
        headers = {'x-amz-acl': 'public-read'}
        status, headers, body = \
            self.conn.make_request('PUT', 'nothing', headers=headers,
                                   query='acl')
        self.assertEquals(get_error_code(body), 'NoSuchBucket')

        aws_error_conn = Connection(aws_secret_key='invalid')
        status, headers, body = \
            aws_error_conn.make_request('PUT', self.bucket, headers=headers,
                                        query='acl')
        self.assertEquals(get_error_code(body), 'SignatureDoesNotMatch')

    def test_get_bucket_acl_error(self):
        headers = {'x-amz-acl': 'public-read'}
        status, headers, body = \
            self.conn.make_request('GET', 'nothing', headers=headers,
                                   query='acl')
        self.assertEquals(get_error_code(body), 'NoSuchBucket')

        aws_error_conn = Connection(aws_secret_key='invalid')
        status, headers, body = \
            aws_error_conn.make_request('GET', self.bucket, headers=headers,
                                        query='acl')
        self.assertEquals(get_error_code(body), 'SignatureDoesNotMatch')

    def test_put_object_acl_error(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)

        headers = {'x-amz-acl': 'public-read'}
        status, headers, body = \
            self.conn.make_request('PUT', self.bucket, 'nothing',
                                   headers=headers, query='acl')
        self.assertEquals(get_error_code(body), 'NoSuchKey')

        aws_error_conn = Connection(aws_secret_key='invalid')
        status, headers, body = \
            aws_error_conn.make_request('PUT', self.bucket, obj,
                                        headers=headers, query='acl')
        self.assertEquals(get_error_code(body), 'SignatureDoesNotMatch')

    def test_get_object_acl_error(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)

        headers = {'x-amz-acl': 'public-read'}
        status, headers, body = \
            self.conn.make_request('GET', self.bucket, 'nothing',
                                   headers=headers, query='acl')
        self.assertEquals(get_error_code(body), 'NoSuchKey')

        aws_error_conn = Connection(aws_secret_key='invalid')
        status, headers, body = \
            aws_error_conn.make_request('GET', self.bucket, obj,
                                        headers=headers, query='acl')
        self.assertEquals(get_error_code(body), 'SignatureDoesNotMatch')

if __name__ == '__main__':
    unittest.main()
