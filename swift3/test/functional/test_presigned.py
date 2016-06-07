# Copyright (c) 2016 SwiftStack, Inc.
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

import requests

from swift3.test.functional.utils import get_error_code
from swift3.etree import fromstring
from swift3.cfg import CONF
from swift3.test.functional import Swift3FunctionalTestCase


class TestSwift3PresignedUrls(Swift3FunctionalTestCase):
    def test_bucket(self):
        bucket = 'test-bucket'
        req_objects = ('object', 'object2')

        # GET Bucket (Without Object)
        status, _junk, _junk = self.conn.make_request('PUT', bucket)
        self.assertEquals(status, 200)

        url = self.conn.generate_url('GET', bucket)
        resp = requests.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertCommonResponseHeaders(resp.headers)
        self.assertIsNotNone(resp.headers['content-type'])
        self.assertEqual(resp.headers['content-length'],
                         str(len(resp.content)))

        elem = fromstring(resp.content, 'ListBucketResult')
        self.assertEquals(elem.find('Name').text, bucket)
        self.assertEquals(elem.find('Prefix').text, None)
        self.assertEquals(elem.find('Marker').text, None)
        self.assertEquals(elem.find('MaxKeys').text,
                          str(CONF.max_bucket_listing))
        self.assertEquals(elem.find('IsTruncated').text, 'false')
        objects = elem.findall('./Contents')
        self.assertEquals(list(objects), [])

        # GET Bucket (With Object)
        for obj in req_objects:
            status, _junk, _junk = self.conn.make_request('PUT', bucket, obj)
            self.assertEqual(
                status, 200,
                'Got %d response while creating %s' % (status, obj))

        resp = requests.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertCommonResponseHeaders(resp.headers)
        self.assertIsNotNone(resp.headers['content-type'])
        self.assertEqual(resp.headers['content-length'],
                         str(len(resp.content)))

        elem = fromstring(resp.content, 'ListBucketResult')
        self.assertEquals(elem.find('Name').text, bucket)
        self.assertEquals(elem.find('Prefix').text, None)
        self.assertEquals(elem.find('Marker').text, None)
        self.assertEquals(elem.find('MaxKeys').text,
                          str(CONF.max_bucket_listing))
        self.assertEquals(elem.find('IsTruncated').text, 'false')
        resp_objects = elem.findall('./Contents')
        self.assertEquals(len(list(resp_objects)), 2)
        for o in resp_objects:
            self.assertIn(o.find('Key').text, req_objects)
            self.assertIsNotNone(o.find('LastModified').text)
            self.assertRegexpMatches(
                o.find('LastModified').text,
                r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$')
            self.assertIsNotNone(o.find('ETag').text)
            self.assertEqual(o.find('Size').text, '0')
            self.assertIsNotNone(o.find('StorageClass').text is not None)
            self.assertEqual(o.find('Owner/ID').text, self.conn.user_id)
            self.assertEqual(o.find('Owner/DisplayName').text,
                             self.conn.user_id)
        # DELETE Bucket
        for obj in req_objects:
            self.conn.make_request('DELETE', bucket, obj)
        url = self.conn.generate_url('DELETE', bucket)
        resp = requests.delete(url)
        self.assertEqual(resp.status_code, 204)

    def test_object(self):
        bucket = 'test-bucket'
        obj = 'object'

        status, _junk, _junk = self.conn.make_request('PUT', bucket)
        self.assertEquals(status, 200)

        # HEAD/missing object
        head_url = self.conn.generate_url('HEAD', bucket, obj)
        resp = requests.head(head_url)
        self.assertEqual(resp.status_code, 404)

        # Wrong verb
        resp = requests.get(head_url)
        self.assertEqual(resp.status_code, 403)
        self.assertEquals(get_error_code(resp.content),
                          'SignatureDoesNotMatch')

        # PUT empty object
        put_url = self.conn.generate_url('PUT', bucket, obj)
        resp = requests.put(put_url, data='')
        self.assertEqual(resp.status_code, 200)

        # GET empty object
        get_url = self.conn.generate_url('GET', bucket, obj)
        resp = requests.get(get_url)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content, '')

        # PUT over object
        resp = requests.put(put_url, data='foobar')
        self.assertEqual(resp.status_code, 200)

        # GET non-empty object
        resp = requests.get(get_url)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content, 'foobar')

        # DELETE Object
        delete_url = self.conn.generate_url('DELETE', bucket, obj)
        resp = requests.delete(delete_url)
        self.assertEqual(resp.status_code, 204)

        # Final cleanup
        status, _junk, _junk = self.conn.make_request('DELETE', bucket)
        self.assertEquals(status, 204)
