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
import datetime

from swift3.test.functional.s3_test_client import get_tester_connection,\
    Connection
from swift3.test.functional.utils import get_error_code,\
    assert_common_response_headers, calculate_md5, calculate_datetime
from swift3.etree import fromstring


class TestSwift3Object(unittest.TestCase):
    def setUp(self):
        self.conn = get_tester_connection()
        self.conn.reset()

    def _prepare_bucket_object(self, bucket='bucket', obj='object',
                               contents='abcdefghij', headers=None):
        self.conn.make_request('PUT', bucket)
        self.conn.make_request('PUT', bucket, obj, body=contents,
                               headers=headers)

    def test_object(self):
        bucket = 'bucket'
        obj = 'object'
        contents = 'abc123'
        self._prepare_bucket_object(bucket)

        # PUT Object
        status, headers, body = \
            self.conn.make_request('PUT', bucket, obj, body=contents)
        self.assertEquals(status, 200)

        assert_common_response_headers(self, headers)
        self.assertTrue(headers['etag'] is not None)
        self.assertEquals(headers['content-length'], '0')

        # PUT Object Copy
        self.conn.make_request('PUT', 'dst_bucket')
        headers = {'x-amz-copy-source': '/%s/%s' % (bucket, obj)}
        status, headers, body = \
            self.conn.make_request('PUT', 'dst_bucket', 'dst_obj', headers,
                                   body=contents)
        self.assertEquals(status, 200)

        assert_common_response_headers(self, headers)
        self.assertEquals(headers['content-length'], str(len(body)))

        elem = fromstring(body, 'CopyObjectResult')
        self.assertTrue(elem.find('LastModified').text is not None)
        self.assertTrue(elem.find('ETag').text is not None)

        # GET Object
        status, headers, body = \
            self.conn.make_request('GET', bucket, obj)
        self.assertEquals(status, 200)

        assert_common_response_headers(self, headers)
        self.assertTrue(headers['last-modified'] is not None)
        self.assertTrue(headers['etag'] is not None)
        self.assertTrue(headers['content-type'] is not None)
        self.assertEquals(headers['content-length'], str(len(contents)))

        # HEAD Object
        status, headers, body = \
            self.conn.make_request('HEAD', bucket, obj)
        self.assertEquals(status, 200)

        assert_common_response_headers(self, headers)
        self.assertTrue(headers['last-modified'] is not None)
        self.assertTrue(headers['etag'] is not None)
        self.assertTrue(headers['content-type'] is not None)
        self.assertEquals(headers['content-length'], str(len(contents)))

        # DELETE Object
        status, headers, body = \
            self.conn.make_request('DELETE', bucket, obj)
        self.assertEquals(status, 204)

        assert_common_response_headers(self, headers)

    def test_put_object_error(self):
        bucket = 'bucket'
        obj = 'object'
        self._prepare_bucket_object(bucket)

        auth_error_conn = Connection(aws_secret_key='invalid')
        status, headers, body = \
            auth_error_conn.make_request('PUT', bucket, obj)
        self.assertEquals(get_error_code(body), 'SignatureDoesNotMatch')

        status, headers, body = \
            self.conn.make_request('PUT', 'nothing', obj)
        self.assertEquals(get_error_code(body), 'NoSuchBucket')

    def test_put_object_copy_error(self):
        src_bucket = 'src_bucket'
        src_obj = 'src_object'
        self._prepare_bucket_object(src_bucket, src_obj)
        dst_bucket = 'dst_bucket'
        dst_obj = 'dst_object'
        self._prepare_bucket_object(dst_bucket)

        headers = {'x-amz-copy-source': '/%s/%s' % (src_bucket, src_obj)}
        auth_error_conn = Connection(aws_secret_key='invalid')
        status, headers, body = \
            auth_error_conn.make_request('PUT', dst_bucket, dst_obj, headers)
        self.assertEquals(get_error_code(body), 'SignatureDoesNotMatch')

        # /src/nothing -> /dst/dst
        headers = {'X-Amz-Copy-Source': '/%s/%s' % (src_bucket, 'nothing')}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers)
        self.assertEquals(get_error_code(body), 'NoSuchKey')

        # /nothing/src -> /dst/dst
        headers = {'X-Amz-Copy-Source': '/%s/%s' % ('nothing', src_obj)}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers)
        # TODO: source bucket is not check.
        # self.assertEquals(get_error_code(body), 'NoSuchBucket')
        self.assertEquals(get_error_code(body), 'NoSuchKey')

        # /src/src -> /nothing/dst
        headers = {'X-Amz-Copy-Source': '/%s/%s' % (src_bucket, src_obj)}
        status, headers, body = \
            self.conn.make_request('PUT', 'nothing', dst_obj, headers)
        self.assertEquals(get_error_code(body), 'NoSuchBucket')

    def test_get_object_error(self):
        bucket = 'bucket'
        obj = 'object'
        self._prepare_bucket_object(bucket, obj)

        auth_error_conn = Connection(aws_secret_key='invalid')
        status, headers, body = \
            auth_error_conn.make_request('GET', bucket, obj)
        self.assertEquals(get_error_code(body), 'SignatureDoesNotMatch')

        status, headers, body = \
            self.conn.make_request('GET', bucket, 'invalid')
        self.assertEquals(get_error_code(body), 'NoSuchKey')

        status, headers, body = self.conn.make_request('GET', 'invalid', obj)
        # TODO; requires consideration
        # self.assertEquals(get_error_code(body), 'NoSuchBucket')
        self.assertEquals(get_error_code(body), 'NoSuchKey')

    def test_head_object_error(self):
        bucket = 'bucket'
        obj = 'object'
        self._prepare_bucket_object(bucket, obj)

        auth_error_conn = Connection(aws_secret_key='invalid')
        status, headers, body = \
            auth_error_conn.make_request('HEAD', bucket, obj)
        self.assertEquals(status, 403)

        status, headers, body = \
            self.conn.make_request('HEAD', bucket, 'nothing')
        self.assertEquals(status, 404)

        status, headers, body = \
            self.conn.make_request('HEAD', 'nothing', obj)
        self.assertEquals(status, 404)

    def test_delete_object_error(self):
        bucket = 'bucket'
        obj = 'object'
        self._prepare_bucket_object(bucket, obj)

        auth_error_conn = Connection(aws_secret_key='invalid')
        status, headers, body = \
            auth_error_conn.make_request('DELETE', bucket, obj)
        self.assertEquals(get_error_code(body), 'SignatureDoesNotMatch')

        status, headers, body = \
            self.conn.make_request('DELETE', bucket, 'nothing')
        self.assertEquals(get_error_code(body), 'NoSuchKey')

        status, headers, body = \
            self.conn.make_request('DELETE', 'nothing', obj)
        # TODO; If s3_acl is False, Swift3 returns NoSuchKey.
        #       If s3_acl is True, Swift3 returns NoSuchBucket.
        self.assertTrue(get_error_code(body) in ('NoSuchBucket', 'NoSuchKey'))

    def test_put_object_cache_control(self):
        bucket = 'bucket'
        obj = 'object'
        self._prepare_bucket_object(bucket)

        headers = {'Cache-Control': 'public'}
        self.conn.make_request('PUT', bucket, obj, headers)

        status, headers, body = \
            self.conn.make_request('HEAD', bucket, obj)
        # TODO: Cache-Control is not supported.
        # self.assertEquals(headers['cache-control'], 'public')

    def test_put_object_content_disposition(self):
        bucket = 'bucket'
        obj = 'object'
        self._prepare_bucket_object(bucket)

        headers = {'Content-Disposition': 'inline'}
        self.conn.make_request('PUT', bucket, obj, headers)

        status, headers, body = \
            self.conn.make_request('HEAD', bucket, obj)
        # TODO: Content-Disposition is not supported.
        # self.assertEquals(headers['content-disposition'], 'inline')

    def test_put_object_content_encoding(self):
        bucket = 'bucket'
        obj = 'object'
        self._prepare_bucket_object(bucket)

        headers = {'Content-Encoding': 'gzip'}
        self.conn.make_request('PUT', bucket, obj, headers)

        status, headers, body = \
            self.conn.make_request('HEAD', bucket, obj)
        self.assertEquals(headers['content-encoding'], 'gzip')

    def test_put_object_content_length(self):
        bucket = 'bucket'
        obj = 'object'
        contents = 'abcdefghij'
        self._prepare_bucket_object(bucket)

        # Content-Length with over body size
        # This tests wait to raise request timeout.
        # It takes time, so comment out.
        """
        headers = {'Content-Length': str(len(contents) + 1)}
        status, headers, body = \
            self.conn.make_request('PUT', bucket, obj, headers, contents)
        self.assertEquals(get_error_code(body), 'RequestTimeout')
        """

        # Content-Length with under body size
        headers = {'Content-Length': str(len(contents) - 1)}
        status, headers, body = \
            self.conn.make_request('PUT', bucket, obj, headers, contents)
        self.assertEquals(status, 200)
        # connection reset for put data remains
        self.conn = get_tester_connection()
        status, headers, body = \
            self.conn.make_request('HEAD', bucket, obj, body='')
        self.assertEquals(status, 200)
        self.assertEquals(headers['content-length'], str(len(contents) - 1))

        # Content-Length with invalid value
        headers = {'Content-Length': 'invalid'}
        self.conn.make_request('PUT', bucket, obj, headers, contents)
        status, headers, body = \
            self.conn.make_request('PUT', bucket, obj, headers, contents)
        # TODO: S3 returns XML, but Swift3 returns nothing.
        # <Error>
        #   <Code>BadRequest</Code>
        #   <Message>An error occurred when parsing the HTTP request.</Message>
        #   <RequestId>[request_id]</RequestId>
        #   <HostId>[host_id]</HostId>
        # </Error>
        # self.assertEquals(get_error_code(body), 'BadRequest')
        self.assertEquals(status, 400)

    def test_put_object_content_md5(self):
        bucket = 'bucket'
        obj = 'object'
        contents = 'abcdefghij'
        self._prepare_bucket_object(bucket)

        headers = {'Content-MD5': calculate_md5(contents)}
        status, headers, body = \
            self.conn.make_request('PUT', bucket, obj, headers, contents)
        self.assertEquals(status, 200)

        headers = {'Content-MD5': 'invalid'}
        status, headers, body = \
            self.conn.make_request('PUT', bucket, obj, headers, contents)
        self.assertEquals(get_error_code(body), 'InvalidDigest')

    def test_put_object_content_type(self):
        bucket = 'bucket'
        obj = 'object'
        contents = 'abcdefghij'
        self._prepare_bucket_object(bucket)

        headers = {'Content-Type': 'text/plain'}
        status, headers, body = \
            self.conn.make_request('PUT', bucket, obj, headers, contents)
        self.assertEquals(status, 200)
        status, headers, body = \
            self.conn.make_request('HEAD', bucket, obj)
        self.assertEquals(headers['content-type'], 'text/plain')

    def test_put_object_expect(self):
        bucket = 'bucket'
        obj = 'object'
        contents = 'abcdefghij'
        self._prepare_bucket_object(bucket)

        headers = {'Expect': '100-continue'}
        status, headers, body = \
            self.conn.make_request('PUT', bucket, obj, headers, contents)
        self.assertEquals(status, 200)

    def test_put_object_expires(self):
        bucket = 'bucket'
        obj = 'object'
        contents = 'abcdefghij'
        date = datetime.datetime.now()
        self._prepare_bucket_object(bucket)

        headers = {'Expires': date}
        self.conn.make_request('PUT', bucket, obj, headers, contents)
        status, headers, body = \
            self.conn.make_request('HEAD', bucket, obj)
        # TODO: Expires is not supported.
        # self.assertEquals(headers['expires'], date)

    def test_put_object_metadata(self):
        bucket = 'bucket'
        obj = 'object'
        contents = 'abcdefghij'
        self._prepare_bucket_object(bucket)

        headers = {'X-Amz-Meta-Bar': 'foo', 'X-Amz-Meta-Bar2': 'foo2'}
        status, headers, body = \
            self.conn.make_request('PUT', bucket, obj, headers, contents)
        self.assertEquals(status, 200)
        status, headers, body = \
            self.conn.make_request('HEAD', bucket, obj)
        self.assertEquals(headers['x-amz-meta-bar'], 'foo')
        self.assertEquals(headers['x-amz-meta-bar2'], 'foo2')

    def test_put_object_storage_class(self):
        bucket = 'bucket'
        obj = 'object'
        contents = 'abcdefghij'
        self._prepare_bucket_object(bucket)

        headers = {'X-Amz-Storage-Class': 'STANDARD'}
        status, headers, body = \
            self.conn.make_request('PUT', bucket, obj, headers, contents)
        self.assertEquals(status, 200)

        headers = {'X-Amz-Storage-Class': 'REDUCED_REDUNDANCY'}
        status, headers, body = \
            self.conn.make_request('PUT', bucket, obj, headers, contents)
        # TODO: REDUCED_REDUNDANCY is not supported.
        # self.assertEquals(status, 200)
        self.assertEquals(get_error_code(body), 'InvalidStorageClass')

        headers = {'X-Amz-Storage-Class': 'invalid'}
        status, headers, body = \
            self.conn.make_request('PUT', bucket, obj, headers, contents)
        self.assertEquals(get_error_code(body), 'InvalidStorageClass')

    def test_put_object_website_redirect_location(self):
        bucket = 'bucket'
        obj = 'object'
        contents = 'abcdefghij'
        self._prepare_bucket_object(bucket)

        headers = {'X-Amz-Website-Redirect-Location':
                   'http://www.example.com/'}
        status, headers, body = \
            self.conn.make_request('PUT', bucket, obj, headers, contents)
        self.assertEquals(get_error_code(body), 'NotImplemented')

    def test_put_object_server_side_encryption(self):
        bucket = 'bucket'
        obj = 'object'
        contents = 'abcdefghij'
        self._prepare_bucket_object(bucket)

        headers = {'X-Amz-Server-Side-Encryption':
                   'aws:kms'}
        status, headers, body = \
            self.conn.make_request('PUT', bucket, obj, headers, contents)
        self.assertEquals(get_error_code(body), 'NotImplemented')

    def test_put_object_copy(self):
        src_bucket = 'src_bucket'
        src_obj = 'src_object'
        dst_bucket = 'dst_bucket'
        dst_obj = 'dst_object'
        self._prepare_bucket_object(src_bucket, src_obj)
        self._prepare_bucket_object(dst_bucket)

        # /src/src -> /dst/dst
        headers = {'X-Amz-Copy-Source': '/%s/%s' % (src_bucket, src_obj)}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers)
        self.assertEquals(status, 200)
        self.conn.make_request('DELETE', dst_bucket, dst_obj)

        # /src/src -> /src/dst
        headers = {'X-Amz-Copy-Source': '/%s/%s' % (src_bucket, src_obj)}
        status, headers, body = \
            self.conn.make_request('PUT', src_bucket, dst_obj, headers)
        self.assertEquals(status, 200)
        self.conn.make_request('DELETE', src_bucket, dst_obj)

        # /src/src -> /src/src
        headers = {'X-Amz-Copy-Source': '/%s/%s' % (src_bucket, src_obj)}
        status, headers, body = \
            self.conn.make_request('PUT', src_bucket, src_obj, headers)
        self.assertEquals(status, 200)

        headers = {'X-Amz-Copy-Source': '/%s/' % src_bucket}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers)
        self.assertEquals(get_error_code(body), 'InvalidArgument')

        headers = {'X-Amz-Copy-Source': '/%s' % src_bucket}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers)
        self.assertEquals(get_error_code(body), 'InvalidArgument')

        headers = {'X-Amz-Copy-Source': '/'}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers)
        self.assertEquals(get_error_code(body), 'InvalidArgument')

        headers = {'X-Amz-Copy-Source': '//'}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers)
        self.assertEquals(get_error_code(body), 'InvalidArgument')

    def test_put_object_copy_metadata_directive(self):
        src_bucket = 'src_bucket'
        src_obj = 'src_object'
        src_headers = {'X-Amz-Meta-Test': 'src'}
        dst_bucket = 'dst_bucket'
        dst_obj = 'dst_object'
        self._prepare_bucket_object(src_bucket, src_obj, headers=src_headers)
        self._prepare_bucket_object(dst_bucket)

        headers = {'X-Amz-Copy-Source': '/%s/%s' % (src_bucket, src_obj),
                   'X-Amz-Metadata-Directive': 'COPY',
                   'X-Amz-Meta-Test': 'dst'}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers)
        self.assertEquals(status, 200)
        status, headers, body = \
            self.conn.make_request('HEAD', dst_bucket, dst_obj)
        # TODO: COPY is not supported.
        # self.assertEquals(headers['x-amz-meta-test'], 'src')
        self.assertEquals(headers['x-amz-meta-test'], 'dst')
        self.conn.make_request('DELETE', dst_bucket, dst_obj)

        headers = {'X-Amz-Copy-Source': '/%s/%s' % (src_bucket, src_obj),
                   'X-Amz-Metadata-Directive': 'REPLACE',
                   'X-Amz-Meta-Test': 'dst'}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers)
        self.assertEquals(status, 200)
        status, headers, body = \
            self.conn.make_request('HEAD', dst_bucket, dst_obj)
        self.assertEquals(headers['x-amz-meta-test'], 'dst')
        self.conn.make_request('DELETE', dst_bucket, dst_obj)

        headers = {'X-Amz-Copy-Source': '/%s/%s' % (src_bucket, src_obj),
                   'X-Amz-Metadata-Directive': 'inavlid',
                   'X-Amz-Meta-Test': 'dst'}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers)
        self.assertEquals(get_error_code(body), 'InvalidArgument')

    def test_put_object_copy_source_if_modified_since(self):
        src_bucket = 'src_bucket'
        src_obj = 'src_object'
        dst_bucket = 'dst_bucket'
        dst_obj = 'dst_object'
        date = datetime.datetime.utcnow()
        self._prepare_bucket_object(src_bucket, src_obj)
        self._prepare_bucket_object(dst_bucket)

        headers = {'X-Amz-Copy-Source': '/%s/%s' % (src_bucket, src_obj),
                   'X-Amz-Copy-Source-If-Modified-Since':
                   calculate_datetime(date, -1)}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers=headers)
        self.assertEquals(status, 200)

        headers = {'X-Amz-Copy-Source': '/%s/%s' % (src_bucket, src_obj),
                   'X-Amz-Copy-Source-If-Modified-Since':
                   calculate_datetime(date, 1)}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers=headers)
        self.assertEquals(status, 412)

        headers = {'X-Amz-Copy-Source': '/%s/%s' % (src_bucket, src_obj),
                   'X-Amz-Copy-Source-If-Modified-Since':
                   'invalid'}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers=headers)
        self.assertEquals(status, 200)

    def test_put_object_copy_source_if_unmodified_since(self):
        src_bucket = 'src_bucket'
        src_obj = 'src_object'
        dst_bucket = 'dst_bucket'
        dst_obj = 'dst_object'
        date = datetime.datetime.utcnow()
        self._prepare_bucket_object(src_bucket, src_obj)
        self._prepare_bucket_object(dst_bucket)

        headers = {'X-Amz-Copy-Source': '/%s/%s' % (src_bucket, src_obj),
                   'X-Amz-Copy-Source-If-Unmodified-Since':
                   calculate_datetime(date, 1)}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers=headers)
        self.assertEquals(status, 200)

        headers = {'X-Amz-Copy-Source': '/%s/%s' % (src_bucket, src_obj),
                   'X-Amz-Copy-Source-If-Unmodified-Since':
                   calculate_datetime(date, -1)}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers=headers)
        self.assertEquals(status, 412)

        headers = {'X-Amz-Copy-Source': '/%s/%s' % (src_bucket, src_obj),
                   'X-Amz-Copy-Source-If-Unmodified-Since':
                   'invalid'}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers=headers)
        self.assertEquals(status, 200)

    def test_put_object_copy_source_if_match(self):
        src_bucket = 'src_bucket'
        src_obj = 'src_object'
        dst_bucket = 'dst_bucket'
        dst_obj = 'dst_object'
        self._prepare_bucket_object(src_bucket, src_obj)
        self._prepare_bucket_object(dst_bucket)

        status, headers, body = \
            self.conn.make_request('HEAD', src_bucket, src_obj)
        etag = headers['etag']

        headers = {'X-Amz-Copy-Source': '/%s/%s' % (src_bucket, src_obj),
                   'X-Amz-Copy-Source-If-Match': etag}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers=headers)
        self.assertEquals(status, 200)

        headers = {'X-Amz-Copy-Source': '/%s/%s' % (src_bucket, src_obj),
                   'X-Amz-Copy-Source-If-Match': 'none-match'}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers=headers)
        self.assertEquals(status, 412)

    def test_put_object_copy_source_if_none_match(self):
        src_bucket = 'src_bucket'
        src_obj = 'src_object'
        dst_bucket = 'dst_bucket'
        dst_obj = 'dst_object'
        self._prepare_bucket_object(src_bucket, src_obj)
        self._prepare_bucket_object(dst_bucket)

        status, headers, body = \
            self.conn.make_request('HEAD', src_bucket, src_obj)
        etag = headers['etag']

        headers = {'X-Amz-Copy-Source': '/%s/%s' % (src_bucket, src_obj),
                   'X-Amz-Copy-Source-If-None-Match': 'none-match'}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers=headers)
        self.assertEquals(status, 200)

        headers = {'X-Amz-Copy-Source': '/%s/%s' % (src_bucket, src_obj),
                   'X-Amz-Copy-Source-If-None-Match': etag}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers=headers)
        self.assertEquals(status, 412)

    def test_get_object_response_content_type(self):
        bucket = 'bucket'
        obj = 'obj'
        self._prepare_bucket_object(bucket, obj)

        query = 'response-content-type=text/plain'
        status, headers, body = \
            self.conn.make_request('GET', bucket, obj, query=query)
        self.assertEquals(status, 200)
        self.assertEquals(headers['content-type'], 'text/plain')

    def test_get_object_response_content_language(self):
        bucket = 'bucket'
        obj = 'object'
        self.conn.make_request('PUT', bucket)
        self.conn.make_request('PUT', bucket, obj)

        query = 'response-content-language=en'
        status, headers, body = \
            self.conn.make_request('GET', bucket, obj, query=query)
        self.assertEquals(status, 200)
        self.assertEquals(headers['content-language'], 'en')

    def test_get_object_response_expires(self):
        # TODO: Expires is not supported.
        pass
        """
        bucket = 'bucket'
        obj = 'object'
        self._prepare_bucket_object(bucket, obj)

        date = datetime.datetime.now()
        query = 'response-expires=%s' % date
        status, headers, body =
            self.conn.make_request('GET', bucket, obj, query=query)
        self.assertEquals(headers['expires'], date)
        """

    def test_get_object_response_cache_control(self):
        bucket = 'bucket'
        obj = 'object'
        self._prepare_bucket_object(bucket, obj)

        query = 'response-cache-control=private'
        status, headers, body = \
            self.conn.make_request('GET', bucket, obj, query=query)
        self.assertEquals(status, 200)
        self.assertEquals(headers['cache-control'], 'private')

    def test_get_object_response_content_disposition(self):
        bucket = 'bucket'
        obj = 'object'
        self._prepare_bucket_object(bucket, obj)

        query = 'response-content-disposition=inline'
        status, headers, body = \
            self.conn.make_request('GET', bucket, obj, query=query)
        self.assertEquals(status, 200)
        self.assertEquals(headers['content-disposition'], 'inline')

    def test_get_object_response_content_encoding(self):
        bucket = 'bucket'
        obj = 'object'
        self._prepare_bucket_object(bucket, obj)

        query = 'response-content-encoding=gzip'
        status, headers, body = \
            self.conn.make_request('GET', bucket, obj, query=query)
        self.assertEquals(status, 200)
        self.assertEquals(headers['content-encoding'], 'gzip')

    def test_get_object_range(self):
        bucket = 'bucket'
        obj = 'object'
        contents = 'abcdefghij'
        self._prepare_bucket_object(bucket, obj, contents)

        headers = {'Range': 'bytes=1-5'}
        status, headers, body = \
            self.conn.make_request('GET', bucket, obj, headers=headers)
        self.assertEquals(status, 206)
        self.assertEquals(headers['content-length'], '5')
        self.assertEquals(len(body), 5)

        headers = {'Range': 'bytes=5-'}
        status, headers, body = \
            self.conn.make_request('GET', bucket, obj, headers=headers)
        self.assertEquals(status, 206)
        self.assertEquals(headers['content-length'], '5')
        self.assertEquals(len(body), 5)

        headers = {'Range': 'bytes=-5'}
        status, headers, body = \
            self.conn.make_request('GET', bucket, obj, headers=headers)
        self.assertEquals(status, 206)
        self.assertEquals(headers['content-length'], '5')
        self.assertEquals(len(body), 5)

        headers = {'Range': 'invalid'}
        status, headers, body = \
            self.conn.make_request('GET', bucket, obj, headers=headers)
        self.assertEquals(status, 200)
        self.assertEquals(headers['content-length'], '10')
        self.assertEquals(len(body), 10)

    def test_get_object_if_modified_since(self):
        bucket = 'bucket'
        obj = 'object'
        date = datetime.datetime.utcnow()
        self._prepare_bucket_object(bucket, obj)

        headers = {'If-Modified-Since': calculate_datetime(date, -1)}
        status, headers, body = \
            self.conn.make_request('GET', bucket, obj, headers=headers)
        self.assertEquals(status, 200)

        headers = {'If-Modified-Since': calculate_datetime(date, 1)}
        status, headers, body = \
            self.conn.make_request('GET', bucket, obj, headers=headers)
        self.assertEquals(status, 304)

        headers = {'If-Modified-Since': 'invalid'}
        status, headers, body = \
            self.conn.make_request('GET', bucket, obj, headers=headers)
        self.assertEquals(status, 200)

    def test_get_object_if_unmodified_since(self):
        bucket = 'bucket'
        obj = 'object'
        date = datetime.datetime.utcnow()
        self._prepare_bucket_object(bucket, obj)

        headers = {'If-Unmodified-Since': calculate_datetime(date, 1)}
        status, headers, body = \
            self.conn.make_request('GET', bucket, obj, headers=headers)
        self.assertEquals(status, 200)

        headers = {'If-Unmodified-Since': calculate_datetime(date, -1)}
        status, headers, body = \
            self.conn.make_request('GET', bucket, obj, headers=headers)
        self.assertEquals(status, 412)

        headers = {'If-Unmodified-Since': 'invalid'}
        status, headers, body = \
            self.conn.make_request('GET', bucket, obj, headers=headers)
        self.assertEquals(status, 200)

    def test_get_object_if_match(self):
        bucket = 'bucket'
        obj = 'object'
        self._prepare_bucket_object(bucket, obj)

        status, headers, body = \
            self.conn.make_request('HEAD', bucket, obj)
        etag = headers['etag']

        headers = {'If-Match': etag}
        status, headers, body = \
            self.conn.make_request('GET', bucket, obj, headers=headers)
        self.assertEquals(status, 200)

        headers = {'If-Match': 'none-match'}
        status, headers, body = \
            self.conn.make_request('GET', bucket, obj, headers=headers)
        self.assertEquals(status, 412)

    def test_get_object_if_none_match(self):
        bucket = 'bucket'
        obj = 'object'
        self._prepare_bucket_object(bucket, obj)

        status, headers, body = \
            self.conn.make_request('HEAD', bucket, obj)
        etag = headers['etag']

        headers = {'If-None-Match': 'none-match'}
        status, headers, body = \
            self.conn.make_request('GET', bucket, obj, headers=headers)
        self.assertEquals(status, 200)

        headers = {'If-None-Match': etag}
        status, headers, body = \
            self.conn.make_request('GET', bucket, obj, headers=headers)
        self.assertEquals(status, 304)

    def test_head_object_range(self):
        bucket = 'bucket'
        obj = 'object'
        contents = 'abcdefghij'
        self._prepare_bucket_object(bucket, obj, contents)

        headers = {'Range': 'bytes=1-5'}
        status, headers, body = \
            self.conn.make_request('HEAD', bucket, obj, headers=headers)
        self.assertEquals(headers['content-length'], '5')

        headers = {'Range': 'bytes=5-'}
        status, headers, body = \
            self.conn.make_request('HEAD', bucket, obj, headers=headers)
        self.assertEquals(headers['content-length'], '5')

        headers = {'Range': 'bytes=-5'}
        status, headers, body = \
            self.conn.make_request('HEAD', bucket, obj, headers=headers)
        self.assertEquals(headers['content-length'], '5')

        headers = {'Range': 'invalid'}
        status, headers, body = \
            self.conn.make_request('HEAD', bucket, obj, headers=headers)
        self.assertEquals(headers['content-length'], '10')

    def test_head_object_if_modified_since(self):
        bucket = 'bucket'
        obj = 'object'
        date = datetime.datetime.utcnow()
        self._prepare_bucket_object(bucket, obj)

        headers = {'If-Modified-Since': calculate_datetime(date, -1)}
        status, headers, body = \
            self.conn.make_request('HEAD', bucket, obj, headers=headers)
        self.assertEquals(status, 200)

        headers = {'If-Modified-Since': calculate_datetime(date, 1)}
        status, headers, body = \
            self.conn.make_request('HEAD', bucket, obj, headers=headers)
        self.assertEquals(status, 304)

        headers = {'If-Modified-Since': 'invalid'}
        status, headers, body = \
            self.conn.make_request('HEAD', bucket, obj, headers=headers)
        self.assertEquals(status, 200)

    def test_head_object_if_unmodified_since(self):
        bucket = 'bucket'
        obj = 'object'
        date = datetime.datetime.utcnow()
        self._prepare_bucket_object(bucket, obj)

        headers = {'If-Unmodified-Since': calculate_datetime(date, 1)}
        status, headers, body = \
            self.conn.make_request('HEAD', bucket, obj, headers=headers)
        self.assertEquals(status, 200)

        headers = {'If-Unmodified-Since': calculate_datetime(date, -1)}
        status, headers, body = \
            self.conn.make_request('HEAD', bucket, obj, headers=headers)
        self.assertEquals(status, 412)

        headers = {'If-Unmodified-Since': 'invalid'}
        status, headers, body = \
            self.conn.make_request('HEAD', bucket, obj, headers=headers)
        self.assertEquals(status, 200)

    def test_head_object_if_match(self):
        bucket = 'bucket'
        obj = 'object'
        self._prepare_bucket_object(bucket, obj)

        status, headers, body = \
            self.conn.make_request('HEAD', bucket, obj)
        etag = headers['etag']

        headers = {'If-Match': etag}
        status, headers, body = \
            self.conn.make_request('HEAD', bucket, obj, headers=headers)
        self.assertEquals(status, 200)

        headers = {'If-Match': 'none-match'}
        status, headers, body = \
            self.conn.make_request('HEAD', bucket, obj, headers=headers)
        self.assertEquals(status, 412)

    def test_head_object_if_none_match(self):
        bucket = 'bucket'
        obj = 'object'
        self._prepare_bucket_object(bucket, obj)

        status, headers, body = \
            self.conn.make_request('HEAD', bucket, obj)
        etag = headers['etag']

        headers = {'If-None-Match': 'none-match'}
        status, headers, body = \
            self.conn.make_request('HEAD', bucket, obj, headers=headers)
        self.assertEquals(status, 200)

        headers = {'If-None-Match': etag}
        status, headers, body = \
            self.conn.make_request('HEAD', bucket, obj, headers=headers)
        self.assertEquals(status, 304)

    def test_delete_object_mfa(self):
        bucket = 'bucket'
        obj = 'object'
        self._prepare_bucket_object(bucket, obj)

        headers = {'X-Amz-Mfa': '20899872 301749'}
        status, headers, body = \
            self.conn.make_request('DELETE', bucket, obj, headers)
        self.assertEquals(get_error_code(body), 'NotImplemented')


if __name__ == '__main__':
    unittest.main()
