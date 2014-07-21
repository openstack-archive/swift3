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
import simplejson as json
from mock import patch

from swift.common import swob
from swift.common.swob import Request

from swift3.test.unit import Swift3TestCase
from swift3.etree import fromstring

class TestSwift3MultiUpload(Swift3TestCase):

    def setUp(self):
        super(TestSwift3MultiUpload, self).setUp()

        self.swift.register('PUT',
                            '/v1/AUTH_test/bucket+segments',
                            swob.HTTPAccepted, {}, None)
        self.swift.register('GET',
                            '/v1/AUTH_test/bucket+segments',
                            swob.HTTPOk, {},
                            json.dumps([{'name': 'object/X/1',
                                         'last_modified':
                                             '2014-05-07T19:47:54.592270',
                                         'hash': 'HASH',
                                         'bytes': 100},
                                        {'name': 'object/X/2',
                                         'last_modified':
                                             '2014-05-07T19:47:54.592270',
                                         'hash': 'HASH',
                                         'bytes': 100},
                                        ]))
        self.swift.register('HEAD', '/v1/AUTH_test/bucket+segments/object/X',
                            swob.HTTPOk, {}, None)
        self.swift.register('PUT', '/v1/AUTH_test/bucket+segments/object/X',
                            swob.HTTPCreated, {}, None)
        self.swift.register('DELETE', '/v1/AUTH_test/bucket+segments/object/X',
                            swob.HTTPNoContent, {}, None)
        self.swift.register('GET', '/v1/AUTH_test/bucket+segments/object/invalid',
                            swob.HTTPNotFound, {}, None)
        self.swift.register('PUT', '/v1/AUTH_test/bucket+segments/object/X/1',
                            swob.HTTPCreated, {}, None)
        self.swift.register('DELETE', '/v1/AUTH_test/bucket+segments/object/X/1',
                            swob.HTTPNoContent, {}, None)
        self.swift.register('DELETE', '/v1/AUTH_test/bucket+segments/object/X/2',
                            swob.HTTPNoContent, {}, None)

    def test_bucket_upload_part(self):
        req = Request.blank('/bucket?partNumber=1&uploadId=x',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidRequest')

    def test_object_multipart_uploads_list(self):
        req = Request.blank('/bucket/object?uploads',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidRequest')

    def test_bucket_multipart_uploads_initiate(self):
        req = Request.blank('/bucket?uploads',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidRequest')

    def test_bucket_list_parts(self):
        req = Request.blank('/bucket?uploadId=x',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidRequest')

    def test_bucket_multipart_uploads_abort(self):
        req = Request.blank('/bucket?uploadId=x',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidRequest')

    def test_bucket_multipart_uploads_complete(self):
        req = Request.blank('/bucket?uploadId=x',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidRequest')

    def test_bucket_multipart_uploads_GET(self):
        req = Request.blank('/bucket/?uploads',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'ListMultipartUploadsResult')
        self.assertEquals(status.split()[0], '200')

    @patch('swift3.controllers.multi_upload.unique_id', lambda: 'X')
    def test_object_multipart_upload_initiate(self):
        req = Request.blank('/bucket/object?uploads',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization':
                                     'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'InitiateMultipartUploadResult')
        self.assertEquals(status.split()[0], '200')

    def test_object_multipart_upload_complete_error(self):
        xml = 'malformed_XML'
        req = Request.blank('/bucket/object?uploadId=X',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=xml)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'MalformedXML')

    def test_object_multipart_upload_complete(self):
        xml = '<CompleteMultipartUpload>' \
            '<Part>' \
            '<PartNumber>1</PartNumber>' \
            '<ETag>HASH</ETag>' \
            '</Part>' \
            '<Part>' \
            '<PartNumber>2</PartNumber>' \
            '<ETag>"HASH"</ETag>' \
            '</Part>' \
            '</CompleteMultipartUpload>'
        req = Request.blank('/bucket/object?uploadId=X',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=xml)
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'CompleteMultipartUploadResult')
        self.assertEquals(status.split()[0], '200')

    def test_object_multipart_upload_abort_error(self):
        req = Request.blank('/bucket/object?uploadId=invalid',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'NoSuchUpload')

    def test_object_multipart_upload_abort(self):
        req = Request.blank('/bucket/object?uploadId=X',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '204')

    def test_object_upload_part_error(self):
        req = Request.blank('/bucket/object?partNumber=1',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body='part object')
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    def test_object_upload_part(self):
        req = Request.blank('/bucket/object?partNumber=1&uploadId=X',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body='part object')
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_object_list_parts_error(self):
        req = Request.blank('/bucket/object?uploadId=invalid',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'NoSuchUpload')

    def test_object_list_parts(self):
        req = Request.blank('/bucket/object?uploadId=X',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'ListPartsResult')
        self.assertEquals(status.split()[0], '200')

if __name__ == '__main__':
    unittest.main()
