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
from string import replace
from hashlib import md5

from swift3.test.functional.utils import assert_common_response_headers, \
    get_error_code
from swift3.etree import fromstring, tostring, Element, SubElement
from swift3.test.functional import Swift3FunctionalTestCase
from swift3.test.functional.s3_test_client import Connection

MIN_SEGMENTS_SIZE = 5242880


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

    def _gen_invalid_comp_xml(self):
        elem = Element('CompleteMultipartUpload')
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

    def _upload_part(self, bucket, key, upload_id, contents=None, part_num=1):
        query = 'partNumber=%s&uploadId=%s' % (part_num, upload_id)
        contents = contents if contents else 'a' * MIN_SEGMENTS_SIZE
        status, headers, body = \
            self.conn.make_request('PUT', bucket, key, body=contents,
                                   query=query)
        etag = replace(headers.get('etag'), '"', '')
        return status, headers, body, etag

    def _upload_part_copy(self, src_bucket, src_obj, dst_bucket, dst_key,
                          upload_id, src_contents=None, part_num=1):
        # prepare src obj
        self.conn.make_request('PUT', src_bucket)
        contents = src_contents if src_contents else 'b' * MIN_SEGMENTS_SIZE
        self.conn.make_request('PUT', src_bucket, src_obj, body=contents)

        src_path = '%s/%s' % (src_bucket, src_obj)
        query = 'partNumber=%s&uploadId=%s' % (part_num, upload_id)
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_key,
                                   headers={'X-Amz-Copy-Source': src_path},
                                   query=query)
        elem = fromstring(body, 'CopyPartResult')
        etag = elem.find('ETag').text
        return status, headers, body, replace(etag, '"', '')

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

        # Initiate Multipart Upload
        for status, headers, body in \
                self._initiate_multi_uploads_result_generator(bucket, keys):
            self.assertEquals(status, 200)
            assert_common_response_headers(self, headers)
            self.assertEquals(headers['content-type'], 'application/xml')
            self.assertEquals(headers['content-length'], str(len(body)))
            elem = fromstring(body, 'InitiateMultipartUploadResult')
            self.assertEquals(elem.find('Bucket').text, bucket)
            key = elem.find('Key').text
            self.assertTrue(key is not None)
            upload_id = elem.find('UploadId').text
            self.assertTrue(upload_id is not None)
            self.assertTrue((key, upload_id) not in uploads)
            uploads.append((key, upload_id))

        # List Multipart Uploads
        query = 'uploads'
        status, headers, body = \
            self.conn.make_request('GET', bucket, query=query)
        self.assertEquals(status, 200)
        assert_common_response_headers(self, headers)
        self.assertEquals(headers['content-type'], 'application/xml')
        self.assertEquals(headers['content-length'], str(len(body)))
        elem = fromstring(body, 'ListMultipartUploadsResult')
        self.assertEquals(elem.find('Bucket').text, bucket)
        self.assertEquals(elem.find('KeyMarker').text, None)
        self.assertTrue(elem.find('NextKeyMarker').text is not None)
        self.assertEquals(elem.find('UploadIdMarker').text, None)
        self.assertTrue(elem.find('NextUploadIdMarker').text is not None)
        self.assertEquals(elem.find('MaxUploads').text, '1000')
        self.assertTrue(elem.find('EncodingType') is None)
        self.assertEquals(elem.find('IsTruncated').text, 'false')
        self.assertEquals(len(elem.findall('Upload')), 2)
        for u in elem.findall('Upload'):
            key = u.find('Key').text
            upload_id = u.find('UploadId').text
            self.assertTrue((key, upload_id) in uploads)
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
        contents = 'a' * MIN_SEGMENTS_SIZE
        etag = md5(contents).hexdigest()
        status, headers, body, resp_etag = \
            self._upload_part(bucket, key, upload_id, contents)
        self.assertEquals(status, 200)
        assert_common_response_headers(self, headers)
        self.assertEquals(headers['content-type'], 'text/html; charset=UTF-8')
        self.assertEquals(headers['content-length'], '0')
        self.assertEquals(resp_etag, etag)

        # Upload Part Copy
        key, upload_id = uploads[1]
        src_bucket = 'bucket2'
        src_obj = 'obj3'
        src_contents = 'b' * MIN_SEGMENTS_SIZE
        etag = md5(src_contents).hexdigest()
        status, headers, body, resp_etag = \
            self._upload_part_copy(src_bucket, src_obj, bucket, key,
                                   upload_id, src_contents)
        self.assertEquals(status, 200)
        assert_common_response_headers(self, headers)
        self.assertEquals(headers['content-type'], 'application/xml')
        self.assertEquals(headers['content-length'], str(len(body)))
        self.assertEquals(headers.get('etag'), None)
        elem = fromstring(body, 'CopyPartResult')
        self.assertTrue(elem.find('LastModified').text is not None)
        self.assertEquals(resp_etag, etag)

        # List Parts
        key, upload_id = uploads[0]
        query = 'uploadId=%s' % upload_id
        status, headers, body = \
            self.conn.make_request('GET', bucket, key, query=query)
        self.assertEquals(status, 200)
        assert_common_response_headers(self, headers)
        self.assertEquals(headers['content-type'], 'application/xml')
        self.assertTrue(headers['content-type'] is not None)
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
        for p in elem.findall('Part'):
            self.assertTrue(p.find('LastModified').text is not None)
            self.assertTrue(p.find('ETag').text is not None)
            etags.append(p.find('ETag').text)
            self.assertTrue(p.find('Size').text is not None)

        # Abort Multipart Upload
        key, upload_id = uploads[1]
        query = 'uploadId=%s' % upload_id
        status, headers, body = \
            self.conn.make_request('DELETE', bucket, key, query=query)
        self.assertEquals(status, 204)
        assert_common_response_headers(self, headers)
        self.assertEquals(headers['content-type'], 'text/html; charset=UTF-8')
        self.assertEquals(headers['content-length'], '0')

        # Complete Multipart Upload
        key, upload_id = uploads[0]
        xml = self._gen_comp_xml(etags)
        status, headers, body = \
            self._complete_multi_upload(bucket, key, upload_id, xml)
        self.assertEquals(status, 200)
        assert_common_response_headers(self, headers)
        self.assertEquals(headers['content-type'], 'application/xml')
        self.assertEquals(headers['content-length'], str(len(body)))
        elem = fromstring(body, 'CompleteMultipartUploadResult')
        self.assertTrue(elem.find('Location').text is not None)
        self.assertEquals(elem.find('Bucket').text, bucket)
        self.assertEquals(elem.find('Key').text, key)
        self.assertTrue(elem.find('ETag').text is not None)

    def test_initiate_multi_upload_error(self):
        bucket = 'bucket'
        key = 'obj'
        self.conn.make_request('PUT', bucket)
        query = 'uploads'

        auth_error_conn = Connection(aws_secret_key='invalid')
        status, headers, body = \
            auth_error_conn.make_request('POST', bucket, key, query=query)
        self.assertEquals(get_error_code(body), 'SignatureDoesNotMatch')

        # TODO: Without the bucket exists, Initiate Multipart Upload is
        #       success.
        #       bug: 1434476
        # status, resp_headers, body = \
        #    self.conn.make_request('POST', 'nothing', obj, query=query)
        # self.assertEquals(get_error_code(body), 'NoSuchBucket')

    def test_list_multi_uploads_error(self):
        bucket = 'bucket'
        self.conn.make_request('PUT', bucket)
        query = 'uploads'

        auth_error_conn = Connection(aws_secret_key='invalid')
        status, headers, body = \
            auth_error_conn.make_request('GET', bucket, query=query)
        self.assertEquals(get_error_code(body), 'SignatureDoesNotMatch')

        status, headers, body = \
            self.conn.make_request('GET', 'nothing', query=query)
        self.assertEquals(get_error_code(body), 'NoSuchBucket')

    def test_upload_part_error(self):
        bucket = 'bucket'
        keys = ['obj']
        status, headers, body = \
            self._initiate_multi_uploads_result_generator(bucket, keys).next()
        elem = fromstring(body, 'InitiateMultipartUploadResult')
        key = elem.find('Key').text
        upload_id = elem.find('UploadId').text

        query = 'partNumber=%s&uploadId=%s' % (1, upload_id)
        auth_error_conn = Connection(aws_secret_key='invalid')
        status, headers, body = \
            auth_error_conn.make_request('PUT', bucket, key, query=query)
        self.assertEquals(get_error_code(body), 'SignatureDoesNotMatch')

        query = 'partNumber=%s&uploadId=%s' % (1, 'nothing')
        status, headers, body = \
            self.conn.make_request('PUT', bucket, key, query=query)
        self.assertEquals(get_error_code(body), 'NoSuchUpload')

        query = 'partNumber=%s&uploadId=%s' % (0, upload_id)
        status, headers, body = \
            self.conn.make_request('PUT', bucket, key, query=query)
        self.assertEquals(get_error_code(body), 'InvalidArgument')

    def test_upload_part_copy_error(self):
        src_bucket = 'src'
        src_obj = 'src'
        self.conn.make_request('PUT', src_bucket)
        self.conn.make_request('PUT', src_bucket, src_obj)
        src_path = '%s/%s' % (src_bucket, src_obj)

        bucket = 'bucket'
        keys = ['obj']
        status, headers, body = \
            self._initiate_multi_uploads_result_generator(bucket, keys).next()
        elem = fromstring(body, 'InitiateMultipartUploadResult')
        key = elem.find('Key').text
        upload_id = elem.find('UploadId').text

        query = 'partNumber=%s&uploadId=%s' % (1, upload_id)
        auth_error_conn = Connection(aws_secret_key='invalid')
        status, headers, body = \
            auth_error_conn.make_request('PUT', bucket, key,
                                         headers={
                                             'X-Amz-Copy-Source': src_path
                                         },
                                         query=query)
        self.assertEquals(get_error_code(body), 'SignatureDoesNotMatch')

        query = 'partNumber=%s&uploadId=%s' % (1, 'nothing')
        status, headers, body = \
            self.conn.make_request('PUT', bucket, key,
                                   headers={'X-Amz-Copy-Source': src_path},
                                   query=query)
        self.assertEquals(get_error_code(body), 'NoSuchUpload')

        src_path = '%s/%s' % (src_bucket, 'nothing')
        query = 'partNumber=%s&uploadId=%s' % (1, upload_id)
        status, headers, body = \
            self.conn.make_request('PUT', bucket, key,
                                   headers={'X-Amz-Copy-Source': src_path},
                                   query=query)
        self.assertEquals(get_error_code(body), 'NoSuchKey')

    def test_list_parts_error(self):
        bucket = 'bucket'
        keys = ['obj']
        status, headers, body = \
            self._initiate_multi_uploads_result_generator(bucket, keys).next()
        elem = fromstring(body, 'InitiateMultipartUploadResult')
        key = elem.find('Key').text
        upload_id = elem.find('UploadId').text

        query = 'uploadId=%s' % upload_id
        auth_error_conn = Connection(aws_secret_key='invalid')
        status, headers, body = \
            auth_error_conn.make_request('GET', bucket, key, query=query)
        self.assertEquals(get_error_code(body), 'SignatureDoesNotMatch')

        query = 'uploadId=%s' % 'nothing'
        status, headers, body = \
            self.conn.make_request('GET', bucket, key, query=query)
        self.assertEquals(get_error_code(body), 'NoSuchUpload')

    def test_abort_multi_upload_error(self):
        bucket = 'bucket'
        keys = ['obj']
        status, headers, body = \
            self._initiate_multi_uploads_result_generator(bucket, keys).next()
        elem = fromstring(body, 'InitiateMultipartUploadResult')
        key = elem.find('Key').text
        upload_id = elem.find('UploadId').text
        self._upload_part(bucket, key, upload_id)

        query = 'uploadId=%s' % upload_id
        auth_error_conn = Connection(aws_secret_key='invalid')
        status, headers, body = \
            auth_error_conn.make_request('DELETE', bucket, key, query=query)
        self.assertEquals(get_error_code(body), 'SignatureDoesNotMatch')

        query = 'uploadId=%s' % 'nothing'
        status, headers, body = \
            self.conn.make_request('DELETE', bucket, key, query=query)
        self.assertEquals(get_error_code(body), 'NoSuchUpload')

    def test_complete_multi_upload_error(self):
        bucket = 'bucket'
        keys = ['obj', 'obj2']
        gen_multi_upload = \
            self._initiate_multi_uploads_result_generator(bucket, keys)

        status, headers, body = \
            gen_multi_upload.next()
        elem = fromstring(body, 'InitiateMultipartUploadResult')
        key = elem.find('Key').text
        upload_id = elem.find('UploadId').text
        status, headers, body, etag = \
            self._upload_part(bucket, key, upload_id)
        xml = self._gen_comp_xml([etag])

        query = 'uploadId=%s' % upload_id
        auth_error_conn = Connection(aws_secret_key='invalid')
        status, headers, body = \
            auth_error_conn.make_request('POST', bucket, key, body=xml,
                                         query=query)
        self.assertEquals(get_error_code(body), 'SignatureDoesNotMatch')

        query = 'uploadId=%s' % 'nothing'
        status, headers, body = \
            self.conn.make_request('POST', bucket, key, body=xml,
                                   query=query)
        self.assertEquals(get_error_code(body), 'NoSuchUpload')

        # without Part tag in xml
        query = 'uploadId=%s' % upload_id
        xml = self._gen_invalid_comp_xml()
        status, headers, body = \
            self.conn.make_request('POST', bucket, key, body=xml,
                                   query=query)
        self.assertEquals(get_error_code(body), 'MalformedXML')

        # without part in Swift
        status, headers, body = \
            gen_multi_upload.next()
        elem = fromstring(body, 'InitiateMultipartUploadResult')
        key = elem.find('Key').text
        upload_id = elem.find('UploadId').text
        query = 'uploadId=%s' % upload_id
        xml = self._gen_comp_xml([etag])
        status, headers, body = \
            self.conn.make_request('POST', bucket, key, body=xml,
                                   query=query)
        self.assertEquals(get_error_code(body), 'InvalidPart')

if __name__ == '__main__':
    unittest.main()
