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
from hashlib import md5
from itertools import izip
from email.utils import parsedate
from time import mktime

from swift3.etree import fromstring, tostring, Element, SubElement
from swift3.test.functional import Swift3FunctionalTestCase

MIN_SEGMENT_SIZE = 5242880


class TestSwift3MultiUpload(Swift3FunctionalTestCase):
    def setUp(self):
        super(TestSwift3MultiUpload, self).setUp()

    def _gen_comp_xml(self, etags):
        elem = Element('CompleteMultipartUpload')
        for i, etag in enumerate(etags):
            elem_part = SubElement(elem, 'Part')
            SubElement(elem_part, 'PartNumber').text = str(i + 1)
            SubElement(elem_part, 'ETag').text = etag
        return tostring(elem)

    def _initiate_multi_uploads_result_generator(self, bucket, keys,
                                                 trials=1):
        self.conn.make_request('PUT', bucket)
        query = 'uploads'
        for key in keys:
            for i in xrange(trials):
                status, resp_headers, body = \
                    self.conn.make_request('POST', bucket, key, query=query)
                yield status, resp_headers, body

    def _upload_part(self, bucket, key, upload_id, content=None, part_num=1):
        query = 'partNumber=%s&uploadId=%s' % (part_num, upload_id)
        content = content if content else 'a' * MIN_SEGMENT_SIZE
        status, headers, body = \
            self.conn.make_request('PUT', bucket, key, body=content,
                                   query=query)
        return status, headers, body

    def _upload_part_copy(self, src_bucket, src_obj, dst_bucket, dst_key,
                          upload_id, part_num=1):

        src_path = '%s/%s' % (src_bucket, src_obj)
        query = 'partNumber=%s&uploadId=%s' % (part_num, upload_id)
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_key,
                                   headers={'X-Amz-Copy-Source': src_path},
                                   query=query)
        elem = fromstring(body, 'CopyPartResult')
        etag = elem.find('ETag').text.strip('"')
        return status, headers, body, etag

    def _complete_multi_upload(self, bucket, key, upload_id, xml):
        query = 'uploadId=%s' % upload_id
        status, headers, body = \
            self.conn.make_request('POST', bucket, key, body=xml,
                                   query=query)
        return status, headers, body

    def test_object_multi_upload(self):
        bucket = 'bucket'
        keys = ['obj1', 'obj2']
        uploads = []

        results_generator = self._initiate_multi_uploads_result_generator(
            bucket, keys)

        # Initiate Multipart Upload
        for expected_key, (status, headers, body) in \
                izip(keys, results_generator):
            self.assertEquals(status, 200)
            self.assertCommonResponseHeaders(headers)
            self.assertTrue('content-type' in headers)
            self.assertEquals(headers['content-type'], 'application/xml')
            self.assertTrue('content-length' in headers)
            self.assertEquals(headers['content-length'], str(len(body)))
            elem = fromstring(body, 'InitiateMultipartUploadResult')
            self.assertEquals(elem.find('Bucket').text, bucket)
            key = elem.find('Key').text
            self.assertEquals(expected_key, key)
            upload_id = elem.find('UploadId').text
            self.assertTrue(upload_id is not None)
            self.assertTrue((key, upload_id) not in uploads)
            uploads.append((key, upload_id))

        self.assertEquals(len(uploads), len(keys))  # sanity

        # List Multipart Uploads
        query = 'uploads'
        status, headers, body = \
            self.conn.make_request('GET', bucket, query=query)
        self.assertEquals(status, 200)
        self.assertCommonResponseHeaders(headers)
        self.assertTrue('content-type' in headers)
        self.assertEquals(headers['content-type'], 'application/xml')
        self.assertTrue('content-length' in headers)
        self.assertEquals(headers['content-length'], str(len(body)))
        elem = fromstring(body, 'ListMultipartUploadsResult')
        self.assertEquals(elem.find('Bucket').text, bucket)
        self.assertEquals(elem.find('KeyMarker').text, None)
        self.assertEquals(elem.find('NextKeyMarker').text, uploads[-1][0])
        self.assertEquals(elem.find('UploadIdMarker').text, None)
        self.assertEquals(elem.find('NextUploadIdMarker').text, uploads[-1][1])
        self.assertEquals(elem.find('MaxUploads').text, '1000')
        self.assertTrue(elem.find('EncodingType') is None)
        self.assertEquals(elem.find('IsTruncated').text, 'false')
        self.assertEquals(len(elem.findall('Upload')), 2)
        for (expected_key, expected_upload_id), u in \
                izip(uploads, elem.findall('Upload')):
            key = u.find('Key').text
            upload_id = u.find('UploadId').text
            self.assertEquals(expected_key, key)
            self.assertEquals(expected_upload_id, upload_id)
            self.assertEquals(u.find('Initiator/ID').text,
                              self.conn.user_id)
            self.assertEquals(u.find('Initiator/DisplayName').text,
                              self.conn.user_id)
            self.assertEquals(u.find('Owner/ID').text, self.conn.user_id)
            self.assertEquals(u.find('Owner/DisplayName').text,
                              self.conn.user_id)
            self.assertEquals(u.find('StorageClass').text, 'STANDARD')
            self.assertTrue(u.find('Initiated').text is not None)

        # Upload Part
        key, upload_id = uploads[0]
        content = 'a' * MIN_SEGMENT_SIZE
        etag = md5(content).hexdigest()
        status, headers, body = \
            self._upload_part(bucket, key, upload_id, content)
        self.assertEquals(status, 200)
        self.assertCommonResponseHeaders(headers, etag)
        self.assertTrue('content-type' in headers)
        self.assertEquals(headers['content-type'], 'text/html; charset=UTF-8')
        self.assertTrue('content-length' in headers)
        self.assertEquals(headers['content-length'], '0')
        # TODO: make a function like as mktime in swift3.test.function.utils
        expected_parts_list = [(headers['etag'],
                                mktime(parsedate(headers['date'])))]

        # Upload Part Copy
        key, upload_id = uploads[1]
        src_bucket = 'bucket2'
        src_obj = 'obj3'
        src_content = 'b' * MIN_SEGMENT_SIZE
        etag = md5(src_content).hexdigest()

        # prepare src obj
        self.conn.make_request('PUT', src_bucket)
        _, headers, _ = self.conn.make_request(
            'PUT', src_bucket, src_obj, body=src_content)
        self.assertCommonResponseHeaders(headers)
        # TODO: this need by the assertion below
        # last_modified_date_from_header = mktime(parsedate(headers['date']))

        status, headers, body, resp_etag = \
            self._upload_part_copy(src_bucket, src_obj, bucket,
                                   key, upload_id)
        self.assertEquals(status, 200)
        self.assertCommonResponseHeaders(headers)
        self.assertTrue('content-type' in headers)
        self.assertEquals(headers['content-type'], 'application/xml')
        self.assertTrue('content-length' in headers)
        self.assertEquals(headers['content-length'], str(len(body)))
        self.assertTrue('etag' not in headers)
        elem = fromstring(body, 'CopyPartResult')

        last_modified = elem.find('LastModified').text
        self.assertTrue(last_modified is not None)
        # last_modified_from_xml = mktime(
        #     strptime(last_modified, '%Y-%m-%dT%H:%M:%S'))
        # self.assertEquals(last_modified_date_from_header,
        #                   last_modified_from_xml)

        self.assertEquals(resp_etag, etag)

        # List Parts
        key, upload_id = uploads[0]
        query = 'uploadId=%s' % upload_id
        status, headers, body = \
            self.conn.make_request('GET', bucket, key, query=query)
        self.assertEquals(status, 200)
        self.assertCommonResponseHeaders(headers)
        self.assertTrue('content-type' in headers)
        self.assertEquals(headers['content-type'], 'application/xml')
        self.assertTrue('content-length' in headers)
        self.assertEquals(headers['content-length'], str(len(body)))
        elem = fromstring(body, 'ListPartsResult')
        self.assertEquals(elem.find('Bucket').text, bucket)
        self.assertEquals(elem.find('Key').text, key)
        self.assertEquals(elem.find('UploadId').text, upload_id)
        self.assertEquals(u.find('Initiator/ID').text, self.conn.user_id)
        self.assertEquals(u.find('Initiator/DisplayName').text,
                          self.conn.user_id)
        self.assertEquals(u.find('Owner/ID').text, self.conn.user_id)
        self.assertEquals(u.find('Owner/DisplayName').text, self.conn.user_id)
        self.assertEquals(elem.find('StorageClass').text, 'STANDARD')
        self.assertEquals(elem.find('PartNumberMarker').text, '0')
        self.assertEquals(elem.find('NextPartNumberMarker').text, '1')
        self.assertEquals(elem.find('MaxParts').text, '1000')
        self.assertEquals(elem.find('IsTruncated').text, 'false')
        self.assertEquals(len(elem.findall('Part')), 1)
        # etags will be used to generate xml for Complete Multipart Upload
        etags = []
        for (expected_etag, expected_date), p in \
                izip(expected_parts_list, elem.findall('Part')):
            last_modified = p.find('LastModified').text
            self.assertTrue(last_modified is not None)
            # TODO: fix the LastModified is formatted as %Y-%m-%dT%H:%M:%S
            #       and time.strptime is needed for the fix.
            # last_modified_from_xml = mktime(
            #     strptime(last_modified, '%Y-%m-%dT%H:%M:%S'))
            # self.assertEquals(expected_date,
            #                   last_modified_from_xml)
            self.assertEquals(expected_etag, p.find('ETag').text)
            self.assertEquals(MIN_SEGMENT_SIZE, int(p.find('Size').text))
            etags.append(p.find('ETag').text)

        # Abort Multipart Upload
        key, upload_id = uploads[1]
        query = 'uploadId=%s' % upload_id
        status, headers, body = \
            self.conn.make_request('DELETE', bucket, key, query=query)
        self.assertEquals(status, 204)
        self.assertCommonResponseHeaders(headers)
        self.assertTrue('content-type' in headers)
        self.assertEquals(headers['content-type'], 'text/html; charset=UTF-8')
        self.assertTrue('content-length' in headers)
        self.assertEquals(headers['content-length'], '0')

        # Complete Multipart Upload
        key, upload_id = uploads[0]
        xml = self._gen_comp_xml(etags)
        status, headers, body = \
            self._complete_multi_upload(bucket, key, upload_id, xml)
        self.assertEquals(status, 200)
        self.assertCommonResponseHeaders(headers)
        self.assertTrue('content-type' in headers)
        self.assertEquals(headers['content-type'], 'application/xml')
        self.assertTrue('content-length' in headers)
        self.assertEquals(headers['content-length'], str(len(body)))
        elem = fromstring(body, 'CompleteMultipartUploadResult')
        self.assertEquals('http://localhost:8080/bucket/obj1',
                          elem.find('Location').text)
        self.assertEquals(elem.find('Bucket').text, bucket)
        self.assertEquals(elem.find('Key').text, key)
        # TODO: confirm completed etag value
        self.assertTrue(elem.find('ETag').text is not None)

if __name__ == '__main__':
    unittest.main()
