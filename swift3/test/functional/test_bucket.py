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
from swift3.etree import fromstring, tostring, Element, SubElement
from swift3.cfg import CONF
from swift3.test.functional import Swift3FunctionalTestCase


class TestSwift3Bucket(Swift3FunctionalTestCase):
    def setUp(self):
        super(TestSwift3Bucket, self).setUp()

    def _gen_location_xml(self, location):
        elem = Element('CreateBucketConfiguration')
        SubElement(elem, 'LocationConstraint').text = location
        return tostring(elem)

    def test_bucket(self):
        bucket = 'bucket'

        # PUT Bucket
        status, headers, body = self.conn.make_request('PUT', bucket)
        self.assertEqual(status, 200)

        self.assertCommonResponseHeaders(headers)
        self.assertEqual(headers['location'], '/' + bucket)
        self.assertEqual(headers['content-length'], '0')

        # GET Bucket(Without Object)
        status, headers, body = self.conn.make_request('GET', bucket)
        self.assertEqual(status, 200)

        self.assertCommonResponseHeaders(headers)
        self.assertTrue(headers['content-type'] is not None)
        self.assertEqual(headers['content-length'], str(len(body)))
        # TODO; requires consideration
        # self.assertEquasl(headers['transfer-encoding'], 'chunked')

        elem = fromstring(body, 'ListBucketResult')
        self.assertEqual(elem.find('Name').text, bucket)
        self.assertEqual(elem.find('Prefix').text, None)
        self.assertEqual(elem.find('Marker').text, None)
        self.assertEqual(elem.find('MaxKeys').text,
                         str(CONF.max_bucket_listing))
        self.assertEqual(elem.find('IsTruncated').text, 'false')
        objects = elem.findall('./Contents')
        self.assertEqual(list(objects), [])

        # GET Bucket(With Object)
        req_objects = ('object', 'object2')
        for obj in req_objects:
            self.conn.make_request('PUT', bucket, obj)
        status, headers, body = self.conn.make_request('GET', bucket)
        self.assertEqual(status, 200)

        elem = fromstring(body, 'ListBucketResult')
        self.assertEqual(elem.find('Name').text, bucket)
        self.assertEqual(elem.find('Prefix').text, None)
        self.assertEqual(elem.find('Marker').text, None)
        self.assertEqual(elem.find('MaxKeys').text,
                         str(CONF.max_bucket_listing))
        self.assertEqual(elem.find('IsTruncated').text, 'false')
        resp_objects = elem.findall('./Contents')
        self.assertEqual(len(list(resp_objects)), 2)
        for o in resp_objects:
            self.assertTrue(o.find('Key').text in req_objects)
            self.assertTrue(o.find('LastModified').text is not None)
            self.assertRegexpMatches(
                o.find('LastModified').text,
                r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$')
            self.assertTrue(o.find('ETag').text is not None)
            self.assertTrue(o.find('Size').text is not None)
            self.assertTrue(o.find('StorageClass').text is not None)
            self.assertTrue(o.find('Owner/ID').text, self.conn.user_id)
            self.assertTrue(o.find('Owner/DisplayName').text,
                            self.conn.user_id)

        # HEAD Bucket
        status, headers, body = self.conn.make_request('HEAD', bucket)
        self.assertEqual(status, 200)

        self.assertCommonResponseHeaders(headers)
        self.assertTrue(headers['content-type'] is not None)
        self.assertEqual(headers['content-length'], str(len(body)))
        # TODO; requires consideration
        # self.assertEquasl(headers['transfer-encoding'], 'chunked')

        # DELETE Bucket
        for obj in req_objects:
            self.conn.make_request('DELETE', bucket, obj)
        status, headers, body = self.conn.make_request('DELETE', bucket)
        self.assertEqual(status, 204)

        self.assertCommonResponseHeaders(headers)

    def test_put_bucket_error(self):
        status, headers, body = \
            self.conn.make_request('PUT', 'bucket+invalid')
        self.assertEqual(get_error_code(body), 'InvalidBucketName')

        auth_error_conn = Connection(aws_secret_key='invalid')
        status, headers, body = auth_error_conn.make_request('PUT', 'bucket')
        self.assertEqual(get_error_code(body), 'SignatureDoesNotMatch')

        self.conn.make_request('PUT', 'bucket')
        status, headers, body = self.conn.make_request('PUT', 'bucket')
        self.assertEqual(get_error_code(body), 'BucketAlreadyExists')

    def test_put_bucket_with_LocationConstraint(self):
        bucket = 'bucket'
        xml = self._gen_location_xml('US')
        status, headers, body = \
            self.conn.make_request('PUT', bucket, body=xml)
        self.assertEqual(status, 200)

    def test_get_bucket_error(self):
        self.conn.make_request('PUT', 'bucket')

        status, headers, body = \
            self.conn.make_request('GET', 'bucket+invalid')
        self.assertEqual(get_error_code(body), 'InvalidBucketName')

        auth_error_conn = Connection(aws_secret_key='invalid')
        status, headers, body = auth_error_conn.make_request('GET', 'bucket')
        self.assertEqual(get_error_code(body), 'SignatureDoesNotMatch')

        status, headers, body = self.conn.make_request('GET', 'nothing')
        self.assertEqual(get_error_code(body), 'NoSuchBucket')

    def _prepare_test_get_bucket(self, bucket, objects):
        self.conn.make_request('PUT', bucket)
        for obj in objects:
            self.conn.make_request('PUT', bucket, obj)

    def test_get_bucket_with_delimiter(self):
        bucket = 'bucket'
        put_objects = ('object', 'object2', 'subdir/object', 'subdir2/object',
                       'dir/subdir/object')
        self._prepare_test_get_bucket(bucket, put_objects)

        delimiter = '/'
        query = 'delimiter=%s' % delimiter
        expect_objects = ('object', 'object2')
        expect_prefixes = ('dir/', 'subdir/', 'subdir2/')
        status, headers, body = \
            self.conn.make_request('GET', bucket, query=query)
        self.assertEqual(status, 200)
        elem = fromstring(body, 'ListBucketResult')
        self.assertEqual(elem.find('Delimiter').text, delimiter)
        resp_objects = elem.findall('./Contents')
        self.assertEqual(len(list(resp_objects)), len(expect_objects))
        for i, o in enumerate(resp_objects):
            self.assertEqual(o.find('Key').text, expect_objects[i])
            self.assertTrue(o.find('LastModified').text is not None)
            self.assertRegexpMatches(
                o.find('LastModified').text,
                r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$')
            self.assertTrue(o.find('ETag').text is not None)
            self.assertTrue(o.find('Size').text is not None)
            self.assertEqual(o.find('StorageClass').text, 'STANDARD')
            self.assertTrue(o.find('Owner/ID').text, self.conn.user_id)
            self.assertTrue(o.find('Owner/DisplayName').text,
                            self.conn.user_id)
        resp_prefixes = elem.findall('CommonPrefixes')
        self.assertEqual(len(resp_prefixes), len(expect_prefixes))
        for i, p in enumerate(resp_prefixes):
            self.assertEqual(p.find('./Prefix').text, expect_prefixes[i])

    def test_get_bucket_with_encoding_type(self):
        bucket = 'bucket'
        put_objects = ('object', 'object2')
        self._prepare_test_get_bucket(bucket, put_objects)

        encoding_type = 'url'
        query = 'encoding-type=%s' % encoding_type
        status, headers, body = \
            self.conn.make_request('GET', bucket, query=query)
        self.assertEqual(status, 200)
        elem = fromstring(body, 'ListBucketResult')
        self.assertEqual(elem.find('EncodingType').text, encoding_type)

    def test_get_bucket_with_marker(self):
        bucket = 'bucket'
        put_objects = ('object', 'object2', 'subdir/object', 'subdir2/object',
                       'dir/subdir/object')
        self._prepare_test_get_bucket(bucket, put_objects)

        marker = 'object'
        query = 'marker=%s' % marker
        expect_objects = ('object2', 'subdir/object', 'subdir2/object')
        status, headers, body = \
            self.conn.make_request('GET', bucket, query=query)
        self.assertEqual(status, 200)
        elem = fromstring(body, 'ListBucketResult')
        self.assertEqual(elem.find('Marker').text, marker)
        resp_objects = elem.findall('./Contents')
        self.assertEqual(len(list(resp_objects)), len(expect_objects))
        for i, o in enumerate(resp_objects):
            self.assertEqual(o.find('Key').text, expect_objects[i])
            self.assertTrue(o.find('LastModified').text is not None)
            self.assertRegexpMatches(
                o.find('LastModified').text,
                r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$')
            self.assertTrue(o.find('ETag').text is not None)
            self.assertTrue(o.find('Size').text is not None)
            self.assertEqual(o.find('StorageClass').text, 'STANDARD')
            self.assertTrue(o.find('Owner/ID').text, self.conn.user_id)
            self.assertTrue(o.find('Owner/DisplayName').text,
                            self.conn.user_id)

    def test_get_bucket_with_max_keys(self):
        bucket = 'bucket'
        put_objects = ('object', 'object2', 'subdir/object', 'subdir2/object',
                       'dir/subdir/object')
        self._prepare_test_get_bucket(bucket, put_objects)

        max_keys = '2'
        query = 'max-keys=%s' % max_keys
        expect_objects = ('dir/subdir/object', 'object')
        status, headers, body = \
            self.conn.make_request('GET', bucket, query=query)
        self.assertEqual(status, 200)
        elem = fromstring(body, 'ListBucketResult')
        self.assertEqual(elem.find('MaxKeys').text, max_keys)
        resp_objects = elem.findall('./Contents')
        self.assertEqual(len(list(resp_objects)), len(expect_objects))
        for i, o in enumerate(resp_objects):
            self.assertEqual(o.find('Key').text, expect_objects[i])
            self.assertTrue(o.find('LastModified').text is not None)
            self.assertRegexpMatches(
                o.find('LastModified').text,
                r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$')
            self.assertTrue(o.find('ETag').text is not None)
            self.assertTrue(o.find('Size').text is not None)
            self.assertEqual(o.find('StorageClass').text, 'STANDARD')
            self.assertTrue(o.find('Owner/ID').text, self.conn.user_id)
            self.assertTrue(o.find('Owner/DisplayName').text,
                            self.conn.user_id)

    def test_get_bucket_with_prefix(self):
        bucket = 'bucket'
        req_objects = ('object', 'object2', 'subdir/object', 'subdir2/object',
                       'dir/subdir/object')
        self._prepare_test_get_bucket(bucket, req_objects)

        prefix = 'object'
        query = 'prefix=%s' % prefix
        expect_objects = ('object', 'object2')
        status, headers, body = \
            self.conn.make_request('GET', bucket, query=query)
        self.assertEqual(status, 200)
        elem = fromstring(body, 'ListBucketResult')
        self.assertEqual(elem.find('Prefix').text, prefix)
        resp_objects = elem.findall('./Contents')
        self.assertEqual(len(list(resp_objects)), len(expect_objects))
        for i, o in enumerate(resp_objects):
            self.assertEqual(o.find('Key').text, expect_objects[i])
            self.assertTrue(o.find('LastModified').text is not None)
            self.assertRegexpMatches(
                o.find('LastModified').text,
                r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$')
            self.assertTrue(o.find('ETag').text is not None)
            self.assertTrue(o.find('Size').text is not None)
            self.assertEqual(o.find('StorageClass').text, 'STANDARD')
            self.assertTrue(o.find('Owner/ID').text, self.conn.user_id)
            self.assertTrue(o.find('Owner/DisplayName').text,
                            self.conn.user_id)

    def test_head_bucket_error(self):
        self.conn.make_request('PUT', 'bucket')

        status, headers, body = \
            self.conn.make_request('HEAD', 'bucket+invalid')
        self.assertEqual(status, 400)
        self.assertEqual(body, '')  # sanifty

        auth_error_conn = Connection(aws_secret_key='invalid')
        status, headers, body = \
            auth_error_conn.make_request('HEAD', 'bucket')
        self.assertEqual(status, 403)
        self.assertEqual(body, '')  # sanifty

        status, headers, body = self.conn.make_request('HEAD', 'nothing')
        self.assertEqual(status, 404)
        self.assertEqual(body, '')  # sanifty

    def test_delete_bucket_error(self):
        status, headers, body = \
            self.conn.make_request('DELETE', 'bucket+invalid')
        self.assertEqual(get_error_code(body), 'InvalidBucketName')

        auth_error_conn = Connection(aws_secret_key='invalid')
        status, headers, body = \
            auth_error_conn.make_request('DELETE', 'bucket')
        self.assertEqual(get_error_code(body), 'SignatureDoesNotMatch')

        status, headers, body = self.conn.make_request('DELETE', 'bucket')
        self.assertEqual(get_error_code(body), 'NoSuchBucket')

if __name__ == '__main__':
    unittest.main()
