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
from mock import patch

from swift.common import swob
from swift.common.swob import Request

from swift3.test.unit import Swift3TestCase
from swift3.etree import fromstring
from swift3.subresource import Owner, Grant, User, ACL, encode_acl
from swift3.test.unit.test_s3_acl import s3acl

xml = '<CompleteMultipartUpload>' \
    '<Part>' \
    '<PartNumber>1</PartNumber>' \
    '<ETag>HASH1</ETag>' \
    '</Part>' \
    '<Part>' \
    '<PartNumber>2</PartNumber>' \
    '<ETag>"HASH2"</ETag>' \
    '</Part>' \
    '</CompleteMultipartUpload>'


class TestSwift3MultiUpload(Swift3TestCase):

    def setUp(self):
        super(TestSwift3MultiUpload, self).setUp()

        segment_bucket = '/v1/AUTH_test/bucket+segments'

        self.objects = \
            (('object/X/1', '2014-05-06T19:47:51.592270', 'HASH1', 10),
             ('object/X/2', '2014-05-06T19:47:52.592270', 'HASH2', 20))

        json_pattern = ['"name":"%s"', '"last_modified":"%s"', '"hash":"%s"',
                        '"bytes":%s']
        json_pattern = '{' + ','.join(json_pattern) + '}'
        json_out = []
        for o in self.objects:
            json_out.append(json_pattern %
                            (o[0], o[1], o[2], o[3]))
        object_list = '[' + ','.join(json_out) + ']'

        self.swift.register('PUT',
                            '/v1/AUTH_test/bucket+segments',
                            swob.HTTPAccepted, {}, None)
        self.swift.register('GET', segment_bucket, swob.HTTPOk, {},
                            object_list)
        self.swift.register('HEAD', segment_bucket + '/object/X',
                            swob.HTTPOk, {}, None)
        self.swift.register('PUT', segment_bucket + '/object/X',
                            swob.HTTPCreated, {}, None)
        self.swift.register('DELETE', segment_bucket + '/object/X',
                            swob.HTTPNoContent, {}, None)
        self.swift.register('GET', segment_bucket + '/object/invalid',
                            swob.HTTPNotFound, {}, None)
        self.swift.register('PUT', segment_bucket + '/object/X/1',
                            swob.HTTPCreated, {}, None)
        self.swift.register('DELETE', segment_bucket + '/object/X/1',
                            swob.HTTPNoContent, {}, None)
        self.swift.register('DELETE', segment_bucket + '/object/X/2',
                            swob.HTTPNoContent, {}, None)

        self.swift.register('HEAD', segment_bucket + '/object/Y',
                            swob.HTTPOk, {}, None)
        self.swift.register('PUT', segment_bucket + '/object/Y',
                            swob.HTTPCreated, {}, None)
        self.swift.register('DELETE', segment_bucket + '/object/Y',
                            swob.HTTPNoContent, {}, None)
        self.swift.register('PUT', segment_bucket + '/object/Y/1',
                            swob.HTTPCreated, {}, None)
        self.swift.register('DELETE', segment_bucket + '/object/Y/1',
                            swob.HTTPNoContent, {}, None)
        self.swift.register('DELETE', segment_bucket + '/object/Y/2',
                            swob.HTTPNoContent, {}, None)

        self.swift.register('HEAD', segment_bucket + '/object2/Z',
                            swob.HTTPOk, {}, None)
        self.swift.register('PUT', segment_bucket + '/object2/Z',
                            swob.HTTPCreated, {}, None)
        self.swift.register('DELETE', segment_bucket + '/object2/Z',
                            swob.HTTPNoContent, {}, None)
        self.swift.register('PUT', segment_bucket + '/object2/Z/1',
                            swob.HTTPCreated, {}, None)
        self.swift.register('DELETE', segment_bucket + '/object2/Z/1',
                            swob.HTTPNoContent, {}, None)
        self.swift.register('DELETE', segment_bucket + '/object2/Z/2',
                            swob.HTTPNoContent, {}, None)

    @s3acl
    def test_bucket_upload_part(self):
        req = Request.blank('/bucket?partNumber=1&uploadId=x',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidRequest')

    @s3acl
    def test_object_multipart_uploads_list(self):
        req = Request.blank('/bucket/object?uploads',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidRequest')

    @s3acl
    def test_bucket_multipart_uploads_initiate(self):
        req = Request.blank('/bucket?uploads',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidRequest')

    @s3acl
    def test_bucket_list_parts(self):
        req = Request.blank('/bucket?uploadId=x',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidRequest')

    @s3acl
    def test_bucket_multipart_uploads_abort(self):
        req = Request.blank('/bucket?uploadId=x',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidRequest')

    @s3acl
    def test_bucket_multipart_uploads_complete(self):
        req = Request.blank('/bucket?uploadId=x',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidRequest')

    def _test_bucket_multipart_uploads_GET(self, query='?uploads',
                                           multiparts=None):
        segment_bucket = '/v1/AUTH_test/bucket+segments'

        self.multi_objects = multiparts if multiparts else \
            (('object/X', '2014-05-06T19:47:50.592270', 'HASHX', 1),
             ('object/X/1', '2014-05-06T19:47:51.592270', 'HASHX1', 10),
             ('object/X/2', '2014-05-06T19:47:52.592270', 'HASHX2', 20),
             ('object/Y', '2014-05-06T19:47:53.592270', 'HASHY', 2),
             ('object/Y/1', '2014-05-06T19:47:54.592270', 'HASHY1', 12),
             ('object/Y/2', '2014-05-06T19:47:55.592270', 'HASHY2', 22),
             ('object2/Z', '2014-05-06T19:47:56.592270', 'HASHZ', 3),
             ('object2/Z/1', '2014-05-06T19:47:57.592270', 'HASHZ1', 13),
             ('object2/Z/2', '2014-05-06T19:47:58.592270', 'HASHZ2', 23))
        json_pattern = ['"name":"%s"', '"last_modified":"%s"', '"hash":"%s"',
                        '"bytes":%s']
        json_pattern = '{' + ','.join(json_pattern) + '}'
        json_out = []
        for o in self.multi_objects:
            json_out.append(json_pattern %
                            (o[0], o[1], o[2], o[3]))
        object_list = '[' + ','.join(json_out) + ']'

        self.swift.register('GET', segment_bucket, swob.HTTPOk, {},
                            object_list)

        req = Request.blank('/bucket/%s' % query,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        return self.call_swift3(req)

    @s3acl
    def test_bucket_multipart_uploads_GET(self):
        status, headers, body = self._test_bucket_multipart_uploads_GET()
        elem = fromstring(body, 'ListMultipartUploadsResult')
        self.assertEquals(elem.find('Bucket').text, 'bucket')
        self.assertEquals(elem.find('KeyMarker').text, None)
        self.assertEquals(elem.find('UploadIdMarker').text, None)
        self.assertEquals(elem.find('NextUploadIdMarker').text, 'Z')
        self.assertEquals(elem.find('MaxUploads').text, '1000')
        self.assertEquals(elem.find('IsTruncated').text, 'false')
        self.assertEquals(len(elem.findall('Upload')), 3)
        objects = [(o[0], o[1][:-3] + 'Z') for o in self.multi_objects]
        for u in elem.findall('Upload'):
            name = u.find('Key').text + '/' + u.find('UploadId').text
            initiated = u.find('Initiated').text
            self.assertTrue((name, initiated) in objects)
            self.assertEquals(u.find('Initiator/ID').text, 'test:tester')
            self.assertEquals(u.find('Initiator/DisplayName').text,
                              'test:tester')
            self.assertEquals(u.find('Owner/ID').text, 'test:tester')
            self.assertEquals(u.find('Owner/DisplayName').text, 'test:tester')
            self.assertEquals(u.find('StorageClass').text, 'STANDARD')
        self.assertEquals(status.split()[0], '200')

    @s3acl
    def test_bucket_multipart_uploads_GET_encoding_type_error(self):
        query = '?uploads&encoding-type=xml'
        status, headers, body = \
            self._test_bucket_multipart_uploads_GET(query)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    @s3acl
    def test_bucket_multipart_uploads_GET_maxuploads(self):
        query = '?uploads&max-uploads=2'
        status, headers, body = \
            self._test_bucket_multipart_uploads_GET(query)
        elem = fromstring(body, 'ListMultipartUploadsResult')
        self.assertEquals(len(elem.findall('Upload/UploadId')), 2)
        self.assertEquals(elem.find('NextKeyMarker').text, 'object')
        self.assertEquals(elem.find('NextUploadIdMarker').text, 'Y')
        self.assertEquals(elem.find('MaxUploads').text, '2')
        self.assertEquals(elem.find('IsTruncated').text, 'true')
        self.assertEquals(status.split()[0], '200')

    @s3acl
    def test_bucket_multipart_uploads_GET_str_maxuploads(self):
        query = '?uploads&max-uploads=invalid'
        status, headers, body = \
            self._test_bucket_multipart_uploads_GET(query)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    @s3acl
    def test_bucket_multipart_uploads_GET_negative_maxuploads(self):
        query = '?uploads&max-uploads=-1'
        status, headers, body = \
            self._test_bucket_multipart_uploads_GET(query)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    @s3acl
    def test_bucket_multipart_uploads_GET_maxuploads_over_default(self):
        query = '?uploads&max-uploads=1001'
        status, headers, body = \
            self._test_bucket_multipart_uploads_GET(query)
        elem = fromstring(body, 'ListMultipartUploadsResult')
        self.assertEquals(len(elem.findall('Upload')), 3)
        self.assertEquals(elem.find('MaxUploads').text, '1000')
        self.assertEquals(status.split()[0], '200')

    @s3acl
    def test_bucket_multipart_uploads_GET_maxuploads_over_maxint(self):
        query = '?uploads&max-uploads=2147483648'
        status, headers, body = \
            self._test_bucket_multipart_uploads_GET(query)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    @s3acl
    def test_bucket_multipart_uploads_GET_with_id_and_key_marker(self):
        query = '?uploads&upload-id-marker=Y&key-marker=object'
        multiparts = \
            (('object/Y', '2014-05-06T19:47:53.592270', 'HASHY', 2),
             ('object/Y/1', '2014-05-06T19:47:54.592270', 'HASHY1', 12),
             ('object/Y/2', '2014-05-06T19:47:55.592270', 'HASHY2', 22))
        status, headers, body = \
            self._test_bucket_multipart_uploads_GET(query, multiparts)
        elem = fromstring(body, 'ListMultipartUploadsResult')
        self.assertEquals(elem.find('KeyMarker').text, 'object')
        self.assertEquals(elem.find('UploadIdMarker').text, 'Y')
        self.assertEquals(len(elem.findall('Upload')), 1)
        objects = [(o[0], o[1][:-3] + 'Z') for o in self.multi_objects]
        for u in elem.findall('Upload'):
            name = u.find('Key').text + '/' + u.find('UploadId').text
            initiated = u.find('Initiated').text
            self.assertTrue((name, initiated) in objects)
        self.assertEquals(status.split()[0], '200')

    @s3acl
    def test_bucket_multipart_uploads_GET_with_key_marker(self):
        query = '?uploads&key-marker=object'
        multiparts = \
            (('object/X', '2014-05-06T19:47:50.592270', 'HASHX', 1),
             ('object/X/1', '2014-05-06T19:47:51.592270', 'HASHX1', 10),
             ('object/X/2', '2014-05-06T19:47:52.592270', 'HASHX2', 20),
             ('object/Y', '2014-05-06T19:47:53.592270', 'HASHY', 2),
             ('object/Y/1', '2014-05-06T19:47:54.592270', 'HASHY1', 12),
             ('object/Y/2', '2014-05-06T19:47:55.592270', 'HASHY2', 22))
        status, headers, body = \
            self._test_bucket_multipart_uploads_GET(query, multiparts)
        elem = fromstring(body, 'ListMultipartUploadsResult')
        self.assertEquals(elem.find('KeyMarker').text, 'object')
        self.assertEquals(elem.find('NextKeyMarker').text, 'object')
        self.assertEquals(elem.find('NextUploadIdMarker').text, 'Y')
        self.assertEquals(len(elem.findall('Upload')), 2)
        objects = [(o[0], o[1][:-3] + 'Z') for o in self.multi_objects]
        for u in elem.findall('Upload'):
            name = u.find('Key').text + '/' + u.find('UploadId').text
            initiated = u.find('Initiated').text
            self.assertTrue((name, initiated) in objects)
        self.assertEquals(status.split()[0], '200')

    @s3acl
    def test_bucket_multipart_uploads_GET_with_prefix(self):
        query = '?uploads&prefix=X'
        multiparts = \
            (('object/X', '2014-05-06T19:47:50.592270', 'HASHX', 1),
             ('object/X/1', '2014-05-06T19:47:51.592270', 'HASHX1', 10),
             ('object/X/2', '2014-05-06T19:47:52.592270', 'HASHX2', 20))
        status, headers, body = \
            self._test_bucket_multipart_uploads_GET(query, multiparts)
        elem = fromstring(body, 'ListMultipartUploadsResult')
        self.assertEquals(len(elem.findall('Upload')), 1)
        objects = [(o[0], o[1][:-3] + 'Z') for o in self.multi_objects]
        for u in elem.findall('Upload'):
            name = u.find('Key').text + '/' + u.find('UploadId').text
            initiated = u.find('Initiated').text
            self.assertTrue((name, initiated) in objects)
        self.assertEquals(status.split()[0], '200')

    @s3acl
    @patch('swift3.controllers.multi_upload.unique_id', lambda: 'X')
    def test_object_multipart_upload_initiate(self):
        req = Request.blank('/bucket/object?uploads',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization':
                                     'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'InitiateMultipartUploadResult')
        self.assertEquals(status.split()[0], '200')

    @s3acl
    def test_object_multipart_upload_complete_error(self):
        xml = 'malformed_XML'
        req = Request.blank('/bucket/object?uploadId=X',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=xml)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'MalformedXML')

    @s3acl
    def test_object_multipart_upload_complete(self):
        req = Request.blank('/bucket/object?uploadId=X',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=xml)
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'CompleteMultipartUploadResult')
        self.assertEquals(status.split()[0], '200')

    @s3acl
    def test_object_multipart_upload_abort_error(self):
        req = Request.blank('/bucket/object?uploadId=invalid',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'NoSuchUpload')

    @s3acl
    def test_object_multipart_upload_abort(self):
        req = Request.blank('/bucket/object?uploadId=X',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '204')

    @s3acl
    def test_object_upload_part_error(self):
        req = Request.blank('/bucket/object?partNumber=1',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body='part object')
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    @s3acl
    def test_object_upload_part(self):
        req = Request.blank('/bucket/object?partNumber=1&uploadId=X',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body='part object')
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    @s3acl
    def test_object_list_parts_error(self):
        req = Request.blank('/bucket/object?uploadId=invalid',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'NoSuchUpload')

    @s3acl
    def test_object_list_parts(self):
        req = Request.blank('/bucket/object?uploadId=X',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'ListPartsResult')
        self.assertEquals(status.split()[0], '200')

    def _test_for_s3acl(self, method, query, account, hasObj=True, body=None):
        path = '/bucket%s' % ('/object' + query if hasObj else query)
        req = Request.blank(path,
                            environ={'REQUEST_METHOD': method},
                            headers={'Authorization': 'AWS %s:hmac' % account},
                            body=body)
        return self.call_swift3(req)

    @s3acl(s3acl_only=True)
    def test_upload_part_acl_without_permission(self):
        status, headers, body = \
            self._test_for_s3acl('PUT', '?partNumber=1&uploadId=X',
                                 'test:other')
        self.assertEquals(status.split()[0], '403')

    @s3acl(s3acl_only=True)
    def test_upload_part_acl_with_write_permission(self):
        status, headers, body = \
            self._test_for_s3acl('PUT', '?partNumber=1&uploadId=X',
                                 'test:write')
        self.assertEquals(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_upload_part_acl_with_fullcontrol_permission(self):
        status, headers, body = \
            self._test_for_s3acl('PUT', '?partNumber=1&uploadId=X',
                                 'test:full_control')
        self.assertEquals(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_list_multipart_uploads_acl_without_permission(self):
        status, headers, body = \
            self._test_for_s3acl('GET', '?uploads', 'test:other',
                                 hasObj=False)
        self.assertEquals(status.split()[0], '403')

    @s3acl(s3acl_only=True)
    def test_list_multipart_uploads_acl_with_read_permission(self):
        status, headers, body = \
            self._test_for_s3acl('GET', '?uploads', 'test:read',
                                 hasObj=False)
        self.assertEquals(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_list_multipart_uploads_acl_with_fullcontrol_permission(self):
        status, headers, body = \
            self._test_for_s3acl('GET', '?uploads', 'test:full_control',
                                 hasObj=False)
        self.assertEquals(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    @patch('swift3.controllers.multi_upload.unique_id', lambda: 'X')
    def test_initiate_multipart_upload_acl_without_permission(self):
        status, headers, body = \
            self._test_for_s3acl('POST', '?uploads', 'test:other')
        self.assertEquals(status.split()[0], '403')

    @s3acl(s3acl_only=True)
    @patch('swift3.controllers.multi_upload.unique_id', lambda: 'X')
    def test_initiate_multipart_upload_acl_with_write_permission(self):
        status, headers, body = \
            self._test_for_s3acl('POST', '?uploads', 'test:write')
        self.assertEquals(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    @patch('swift3.controllers.multi_upload.unique_id', lambda: 'X')
    def test_initiate_multipart_upload_acl_with_fullcontrol_permission(self):
        status, headers, body = \
            self._test_for_s3acl('POST', '?uploads', 'test:full_control')
        self.assertEquals(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_list_parts_acl_without_permission(self):
        status, headers, body = \
            self._test_for_s3acl('GET', '?uploadId=X', 'test:other')
        self.assertEquals(status.split()[0], '403')

    @s3acl(s3acl_only=True)
    def test_list_parts_acl_with_read_permission(self):
        status, headers, body = \
            self._test_for_s3acl('GET', '?uploadId=X', 'test:read')
        self.assertEquals(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_list_parts_acl_with_fullcontrol_permission(self):
        status, headers, body = \
            self._test_for_s3acl('GET', '?uploadId=X', 'test:full_control')
        self.assertEquals(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_abort_multipart_upload_acl_without_permission(self):
        status, headers, body = \
            self._test_for_s3acl('DELETE', '?uploadId=X', 'test:other')
        self.assertEquals(status.split()[0], '403')

    @s3acl(s3acl_only=True)
    def test_abort_multipart_upload_acl_with_write_permission(self):
        status, headers, body = \
            self._test_for_s3acl('DELETE', '?uploadId=X', 'test:write')
        self.assertEquals(status.split()[0], '204')

    @s3acl(s3acl_only=True)
    def test_abort_multipart_upload_acl_with_fullcontrol_permission(self):
        status, headers, body = \
            self._test_for_s3acl('DELETE', '?uploadId=X', 'test:full_control')
        self.assertEquals(status.split()[0], '204')

    @s3acl(s3acl_only=True)
    def test_complete_multipart_upload_acl_without_permission(self):
        status, headers, body = \
            self._test_for_s3acl('POST', '?uploadId=X', 'test:other',
                                 body=xml)
        self.assertEquals(status.split()[0], '403')

    @s3acl(s3acl_only=True)
    def test_complete_multipart_upload_acl_with_write_permission(self):
        status, headers, body = \
            self._test_for_s3acl('POST', '?uploadId=X', 'test:write',
                                 body=xml)
        self.assertEquals(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_complete_multipart_upload_acl_with_fullcontrol_permission(self):
        status, headers, body = \
            self._test_for_s3acl('POST', '?uploadId=X', 'test:full_control',
                                 body=xml)
        self.assertEquals(status.split()[0], '200')

    def _test_copy_for_s3acl(self, account, src_permission=None,
                             src_path='/src_bucket/src_obj'):
        owner = 'test:tester'
        grants = [Grant(User(account), src_permission)] \
            if src_permission else [Grant(User(owner), 'FULL_CONTROL')]
        src_o_headers = encode_acl('object', ACL(Owner(owner, owner), grants))
        self.swift.register('HEAD', '/v1/AUTH_test/src_bucket/src_obj',
                            swob.HTTPOk, src_o_headers, None)

        req = Request.blank(
            '/bucket/object?partNumber=1&uploadId=X',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'Authorization': 'AWS %s:hmac' % account,
                     'X-Amz-Copy-Source': src_path})
        return self.call_swift3(req)

    @s3acl(s3acl_only=True)
    def test_upload_part_copy_acl_with_owner_permission(self):
        status, headers, body = \
            self._test_copy_for_s3acl('test:tester')
        self.assertEquals(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_upload_part_copy_acl_without_permission(self):
        status, headers, body = \
            self._test_copy_for_s3acl('test:other', 'READ')
        self.assertEquals(status.split()[0], '403')

    @s3acl(s3acl_only=True)
    def test_upload_part_copy_acl_with_write_permission(self):
        status, headers, body = \
            self._test_copy_for_s3acl('test:write', 'READ')
        self.assertEquals(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_upload_part_copy_acl_with_fullcontrol_permission(self):
        status, headers, body = \
            self._test_copy_for_s3acl('test:full_control', 'READ')
        self.assertEquals(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_upload_part_copy_acl_without_src_permission(self):
        status, headers, body = \
            self._test_copy_for_s3acl('test:write', 'WRITE')
        self.assertEquals(status.split()[0], '403')

    @s3acl(s3acl_only=True)
    def test_upload_part_copy_acl_invalid_source(self):
        status, headers, body = \
            self._test_copy_for_s3acl('test:write', 'WRITE', '')
        self.assertEquals(status.split()[0], '400')

        status, headers, body = \
            self._test_copy_for_s3acl('test:write', 'WRITE', '/')
        self.assertEquals(status.split()[0], '400')

        status, headers, body = \
            self._test_copy_for_s3acl('test:write', 'WRITE', '/bucket')
        self.assertEquals(status.split()[0], '400')

        status, headers, body = \
            self._test_copy_for_s3acl('test:write', 'WRITE', '/bucket/')
        self.assertEquals(status.split()[0], '400')

if __name__ == '__main__':
    unittest.main()
