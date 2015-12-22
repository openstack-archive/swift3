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

from email.utils import formatdate, parsedate
from time import mktime

from multifile import MultiFile
from cStringIO import StringIO
from hashlib import md5
from urllib import quote

from swift3.test.functional.s3_test_client import Connection
from swift3.test.functional.utils import get_error_code,\
    calculate_md5
from swift3.test.functional import Swift3FunctionalTestCase
from swift3.etree import fromstring

DAY = 86400.0  # 60 * 60 * 24 (sec)


class TestSwift3Object(Swift3FunctionalTestCase):
    def setUp(self):
        super(TestSwift3Object, self).setUp()
        self.bucket = 'bucket'
        self.conn.make_request('PUT', self.bucket)

    def _assertObjectEtag(self, bucket, obj, etag):
        status, headers, _ = self.conn.make_request('HEAD', bucket, obj)
        self.assertEquals(status, 200)  # sanity
        self.assertCommonResponseHeaders(headers, etag)

    def test_object(self):
        obj = 'object name with %-sign'
        content = 'abc123'
        etag = md5(content).hexdigest()

        # PUT Object
        status, headers, body = \
            self.conn.make_request('PUT', self.bucket, obj, body=content)
        self.assertEquals(status, 200)

        self.assertCommonResponseHeaders(headers)
        self.assertTrue('content-length' in headers)  # sanity
        self.assertEquals(headers['content-length'], '0')
        self._assertObjectEtag(self.bucket, obj, etag)

        # PUT Object Copy
        dst_bucket = 'dst-bucket'
        dst_obj = 'dst_obj'
        self.conn.make_request('PUT', dst_bucket)
        headers = {'x-amz-copy-source': '/%s/%s' % (self.bucket, obj)}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj,
                                   headers=headers)
        self.assertEquals(status, 200)

        # PUT Object Copy with URL-encoded Source
        dst_bucket = 'dst-bucket'
        dst_obj = 'dst_obj'
        self.conn.make_request('PUT', dst_bucket)
        headers = {'x-amz-copy-source': quote('/%s/%s' % (self.bucket, obj))}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj,
                                   headers=headers)
        self.assertEquals(status, 200)

        self.assertCommonResponseHeaders(headers)
        self.assertEquals(headers['content-length'], str(len(body)))

        elem = fromstring(body, 'CopyObjectResult')
        self.assertTrue(elem.find('LastModified').text is not None)
        last_modified_xml = elem.find('LastModified').text
        self.assertTrue(elem.find('ETag').text is not None)
        self.assertEquals(etag, elem.find('ETag').text.strip('"'))
        self._assertObjectEtag(dst_bucket, dst_obj, etag)

        # Check timestamp on Copy:
        status, headers, body = \
            self.conn.make_request('GET', dst_bucket)
        self.assertEquals(status, 200)
        elem = fromstring(body, 'ListBucketResult')

        # FIXME: COPY result drops mili/microseconds but GET doesn't
        self.assertEquals(
            elem.find('Contents').find("LastModified").text.rsplit('.', 1)[0],
            last_modified_xml.rsplit('.', 1)[0])

        # GET Object
        status, headers, body = \
            self.conn.make_request('GET', self.bucket, obj)
        self.assertEquals(status, 200)

        self.assertCommonResponseHeaders(headers, etag)
        self.assertTrue(headers['last-modified'] is not None)
        self.assertTrue(headers['content-type'] is not None)
        self.assertEquals(headers['content-length'], str(len(content)))

        # HEAD Object
        status, headers, body = \
            self.conn.make_request('HEAD', self.bucket, obj)
        self.assertEquals(status, 200)

        self.assertCommonResponseHeaders(headers, etag)
        self.assertTrue(headers['last-modified'] is not None)
        self.assertTrue('content-type' in headers)
        self.assertEquals(headers['content-length'], str(len(content)))

        # DELETE Object
        status, headers, body = \
            self.conn.make_request('DELETE', self.bucket, obj)
        self.assertEquals(status, 204)
        self.assertCommonResponseHeaders(headers)

    def test_put_object_error(self):
        auth_error_conn = Connection(aws_secret_key='invalid')
        status, headers, body = \
            auth_error_conn.make_request('PUT', self.bucket, 'object')
        self.assertEquals(get_error_code(body), 'SignatureDoesNotMatch')
        self.assertEquals(headers['content-type'], 'application/xml')

        status, headers, body = \
            self.conn.make_request('PUT', 'bucket2', 'object')
        self.assertEquals(get_error_code(body), 'NoSuchBucket')
        self.assertEquals(headers['content-type'], 'application/xml')

    def test_put_object_copy_error(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)
        dst_bucket = 'dst-bucket'
        self.conn.make_request('PUT', dst_bucket)
        dst_obj = 'dst_object'

        headers = {'x-amz-copy-source': '/%s/%s' % (self.bucket, obj)}
        auth_error_conn = Connection(aws_secret_key='invalid')
        status, headers, body = \
            auth_error_conn.make_request('PUT', dst_bucket, dst_obj, headers)
        self.assertEquals(get_error_code(body), 'SignatureDoesNotMatch')
        self.assertEquals(headers['content-type'], 'application/xml')

        # /src/nothing -> /dst/dst
        headers = {'X-Amz-Copy-Source': '/%s/%s' % (self.bucket, 'nothing')}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers)
        self.assertEquals(get_error_code(body), 'NoSuchKey')
        self.assertEquals(headers['content-type'], 'application/xml')

        # /nothing/src -> /dst/dst
        headers = {'X-Amz-Copy-Source': '/%s/%s' % ('nothing', obj)}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers)
        # TODO: source bucket is not check.
        # self.assertEquals(get_error_code(body), 'NoSuchBucket')

        # /src/src -> /nothing/dst
        headers = {'X-Amz-Copy-Source': '/%s/%s' % (self.bucket, obj)}
        status, headers, body = \
            self.conn.make_request('PUT', 'nothing', dst_obj, headers)
        self.assertEquals(get_error_code(body), 'NoSuchBucket')
        self.assertEquals(headers['content-type'], 'application/xml')

    def test_get_object_error(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)

        auth_error_conn = Connection(aws_secret_key='invalid')
        status, headers, body = \
            auth_error_conn.make_request('GET', self.bucket, obj)
        self.assertEquals(get_error_code(body), 'SignatureDoesNotMatch')
        self.assertEquals(headers['content-type'], 'application/xml')

        status, headers, body = \
            self.conn.make_request('GET', self.bucket, 'invalid')
        self.assertEquals(get_error_code(body), 'NoSuchKey')
        self.assertEquals(headers['content-type'], 'application/xml')

        status, headers, body = self.conn.make_request('GET', 'invalid', obj)
        # TODO; requires consideration
        # self.assertEquals(get_error_code(body), 'NoSuchBucket')
        self.assertEquals(get_error_code(body), 'NoSuchKey')
        self.assertEquals(headers['content-type'], 'application/xml')

    def test_head_object_error(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)

        auth_error_conn = Connection(aws_secret_key='invalid')
        status, headers, body = \
            auth_error_conn.make_request('HEAD', self.bucket, obj)
        self.assertEquals(status, 403)
        self.assertEquals(body, '')  # sanifty
        self.assertEquals(headers['content-type'], 'application/xml')

        status, headers, body = \
            self.conn.make_request('HEAD', self.bucket, 'invalid')
        self.assertEquals(status, 404)
        self.assertEquals(body, '')  # sanifty
        self.assertEquals(headers['content-type'], 'application/xml')

        status, headers, body = \
            self.conn.make_request('HEAD', 'invalid', obj)
        self.assertEquals(status, 404)
        self.assertEquals(body, '')  # sanifty
        self.assertEquals(headers['content-type'], 'application/xml')

    def test_delete_object_error(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)

        auth_error_conn = Connection(aws_secret_key='invalid')
        status, headers, body = \
            auth_error_conn.make_request('DELETE', self.bucket, obj)
        self.assertEquals(get_error_code(body), 'SignatureDoesNotMatch')
        self.assertEquals(headers['content-type'], 'application/xml')

        status, headers, body = \
            self.conn.make_request('DELETE', self.bucket, 'invalid')
        self.assertEquals(get_error_code(body), 'NoSuchKey')
        self.assertEquals(headers['content-type'], 'application/xml')

        status, headers, body = \
            self.conn.make_request('DELETE', 'invalid', obj)
        self.assertEquals(get_error_code(body), 'NoSuchBucket')
        self.assertEquals(headers['content-type'], 'application/xml')

    def test_put_object_content_encoding(self):
        obj = 'object'
        etag = md5().hexdigest()
        headers = {'Content-Encoding': 'gzip'}
        status, headers, body = \
            self.conn.make_request('PUT', self.bucket, obj, headers)
        self.assertEquals(status, 200)
        status, headers, body = \
            self.conn.make_request('HEAD', self.bucket, obj)
        self.assertTrue('content-encoding' in headers)  # sanity
        self.assertEquals(headers['content-encoding'], 'gzip')
        self.assertCommonResponseHeaders(headers)
        self._assertObjectEtag(self.bucket, obj, etag)

    def test_put_object_content_md5(self):
        obj = 'object'
        content = 'abcdefghij'
        etag = md5(content).hexdigest()
        headers = {'Content-MD5': calculate_md5(content)}
        status, headers, body = \
            self.conn.make_request('PUT', self.bucket, obj, headers, content)
        self.assertEquals(status, 200)
        self.assertCommonResponseHeaders(headers)
        self._assertObjectEtag(self.bucket, obj, etag)

    def test_put_object_content_type(self):
        obj = 'object'
        content = 'abcdefghij'
        etag = md5(content).hexdigest()
        headers = {'Content-Type': 'text/plain'}
        status, headers, body = \
            self.conn.make_request('PUT', self.bucket, obj, headers, content)
        self.assertEquals(status, 200)
        status, headers, body = \
            self.conn.make_request('HEAD', self.bucket, obj)
        self.assertEquals(headers['content-type'], 'text/plain')
        self.assertCommonResponseHeaders(headers)
        self._assertObjectEtag(self.bucket, obj, etag)

    def test_put_object_conditional_requests(self):
        obj = 'object'
        content = 'abcdefghij'
        headers = {'If-None-Match': '*'}
        status, headers, body = \
            self.conn.make_request('PUT', self.bucket, obj, headers, content)
        self.assertEquals(status, 501)

        headers = {'If-Match': '*'}
        status, headers, body = \
            self.conn.make_request('PUT', self.bucket, obj, headers, content)
        self.assertEquals(status, 501)

        headers = {'If-Modified-Since': 'Sat, 27 Jun 2015 00:00:00 GMT'}
        status, headers, body = \
            self.conn.make_request('PUT', self.bucket, obj, headers, content)
        self.assertEquals(status, 501)

        headers = {'If-Unmodified-Since': 'Sat, 27 Jun 2015 00:00:00 GMT'}
        status, headers, body = \
            self.conn.make_request('PUT', self.bucket, obj, headers, content)
        self.assertEquals(status, 501)

        # None of the above should actually have created an object
        status, headers, body = \
            self.conn.make_request('HEAD', self.bucket, obj, {}, '')
        self.assertEquals(status, 404)

    def test_put_object_expect(self):
        obj = 'object'
        content = 'abcdefghij'
        etag = md5(content).hexdigest()
        headers = {'Expect': '100-continue'}
        status, headers, body = \
            self.conn.make_request('PUT', self.bucket, obj, headers, content)
        self.assertEquals(status, 200)
        self.assertCommonResponseHeaders(headers)
        self._assertObjectEtag(self.bucket, obj, etag)

    def _test_put_object_headers(self, req_headers):
        obj = 'object'
        content = 'abcdefghij'
        etag = md5(content).hexdigest()
        status, headers, body = \
            self.conn.make_request('PUT', self.bucket, obj,
                                   req_headers, content)
        self.assertEquals(status, 200)
        status, headers, body = \
            self.conn.make_request('HEAD', self.bucket, obj)
        for header, value in req_headers.items():
            self.assertIn(header.lower(), headers)
            self.assertEquals(headers[header.lower()], value)
        self.assertCommonResponseHeaders(headers)
        self._assertObjectEtag(self.bucket, obj, etag)

    def test_put_object_metadata(self):
        self._test_put_object_headers({
            'X-Amz-Meta-Bar': 'foo',
            'X-Amz-Meta-Bar2': 'foo2'})

    def test_put_object_content_headers(self):
        self._test_put_object_headers({
            'Content-Type': 'foo/bar',
            'Content-Encoding': 'baz',
            'Content-Disposition': 'attachment',
            'Content-Language': 'en'})

    def test_put_object_cache_control(self):
        self._test_put_object_headers({
            'Cache-Control': 'private, some-extension'})

    def test_put_object_expires(self):
        self._test_put_object_headers({
            # We don't validate that the Expires header is a valid date
            'Expires': 'a valid HTTP-date timestamp'})

    def test_put_object_robots_tag(self):
        self._test_put_object_headers({
            'X-Robots-Tag': 'googlebot: noarchive'})

    def test_put_object_storage_class(self):
        obj = 'object'
        content = 'abcdefghij'
        etag = md5(content).hexdigest()
        headers = {'X-Amz-Storage-Class': 'STANDARD'}
        status, headers, body = \
            self.conn.make_request('PUT', self.bucket, obj, headers, content)
        self.assertEquals(status, 200)
        self.assertCommonResponseHeaders(headers)
        self._assertObjectEtag(self.bucket, obj, etag)

    def test_put_object_copy_source(self):
        obj = 'object'
        content = 'abcdefghij'
        etag = md5(content).hexdigest()
        self.conn.make_request('PUT', self.bucket, obj, body=content)

        dst_bucket = 'dst-bucket'
        dst_obj = 'dst_object'
        self.conn.make_request('PUT', dst_bucket)

        # /src/src -> /dst/dst
        headers = {'X-Amz-Copy-Source': '/%s/%s' % (self.bucket, obj)}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers)
        self.assertEquals(status, 200)
        self.assertCommonResponseHeaders(headers)
        self._assertObjectEtag(dst_bucket, dst_obj, etag)

        # /src/src -> /src/dst
        headers = {'X-Amz-Copy-Source': '/%s/%s' % (self.bucket, obj)}
        status, headers, body = \
            self.conn.make_request('PUT', self.bucket, dst_obj, headers)
        self.assertEquals(status, 200)
        self.assertCommonResponseHeaders(headers)
        self._assertObjectEtag(self.bucket, dst_obj, etag)

        # /src/src -> /src/src
        # need changes to copy itself (e.g. metadata)
        headers = {'X-Amz-Copy-Source': '/%s/%s' % (self.bucket, obj),
                   'X-Amz-Meta-Foo': 'bar',
                   'X-Amz-Metadata-Directive': 'REPLACE'}
        status, headers, body = \
            self.conn.make_request('PUT', self.bucket, obj, headers)
        self.assertEquals(status, 200)
        self._assertObjectEtag(self.bucket, obj, etag)
        self.assertCommonResponseHeaders(headers)

    def test_put_object_copy_metadata_directive(self):
        obj = 'object'
        src_headers = {'X-Amz-Meta-Test': 'src'}
        dst_bucket = 'dst-bucket'
        dst_obj = 'dst_object'
        self.conn.make_request('PUT', self.bucket, obj, headers=src_headers)
        self.conn.make_request('PUT', dst_bucket)

        headers = {'X-Amz-Copy-Source': '/%s/%s' % (self.bucket, obj),
                   'X-Amz-Metadata-Directive': 'REPLACE',
                   'X-Amz-Meta-Test': 'dst'}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers)
        self.assertEquals(status, 200)
        self.assertCommonResponseHeaders(headers)
        status, headers, body = \
            self.conn.make_request('HEAD', dst_bucket, dst_obj)
        self.assertEquals(headers['x-amz-meta-test'], 'dst')

    def test_put_object_copy_source_if_modified_since(self):
        obj = 'object'
        dst_bucket = 'dst-bucket'
        dst_obj = 'dst_object'
        etag = md5().hexdigest()
        self.conn.make_request('PUT', self.bucket, obj)
        self.conn.make_request('PUT', dst_bucket)

        _, headers, _ = self.conn.make_request('HEAD', self.bucket, obj)
        src_datetime = mktime(parsedate(headers['last-modified']))
        src_datetime = src_datetime - DAY
        headers = {'X-Amz-Copy-Source': '/%s/%s' % (self.bucket, obj),
                   'X-Amz-Copy-Source-If-Modified-Since':
                   formatdate(src_datetime)}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers=headers)
        self.assertEquals(status, 200)
        self.assertCommonResponseHeaders(headers)
        self._assertObjectEtag(self.bucket, obj, etag)

    def test_put_object_copy_source_if_unmodified_since(self):
        obj = 'object'
        dst_bucket = 'dst-bucket'
        dst_obj = 'dst_object'
        etag = md5().hexdigest()
        self.conn.make_request('PUT', self.bucket, obj)
        self.conn.make_request('PUT', dst_bucket)

        _, headers, _ = self.conn.make_request('HEAD', self.bucket, obj)
        src_datetime = mktime(parsedate(headers['last-modified']))
        src_datetime = src_datetime + DAY
        headers = {'X-Amz-Copy-Source': '/%s/%s' % (self.bucket, obj),
                   'X-Amz-Copy-Source-If-Unmodified-Since':
                   formatdate(src_datetime)}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers=headers)
        self.assertEquals(status, 200)
        self.assertCommonResponseHeaders(headers)
        self._assertObjectEtag(self.bucket, obj, etag)

    def test_put_object_copy_source_if_match(self):
        obj = 'object'
        dst_bucket = 'dst-bucket'
        dst_obj = 'dst_object'
        etag = md5().hexdigest()
        self.conn.make_request('PUT', self.bucket, obj)
        self.conn.make_request('PUT', dst_bucket)

        status, headers, body = \
            self.conn.make_request('HEAD', self.bucket, obj)

        headers = {'X-Amz-Copy-Source': '/%s/%s' % (self.bucket, obj),
                   'X-Amz-Copy-Source-If-Match': etag}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers=headers)
        self.assertEquals(status, 200)
        self.assertCommonResponseHeaders(headers)
        self._assertObjectEtag(self.bucket, obj, etag)

    def test_put_object_copy_source_if_none_match(self):
        obj = 'object'
        dst_bucket = 'dst-bucket'
        dst_obj = 'dst_object'
        etag = md5().hexdigest()
        self.conn.make_request('PUT', self.bucket, obj)
        self.conn.make_request('PUT', dst_bucket)

        headers = {'X-Amz-Copy-Source': '/%s/%s' % (self.bucket, obj),
                   'X-Amz-Copy-Source-If-None-Match': 'none-match'}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers=headers)
        self.assertEquals(status, 200)
        self.assertCommonResponseHeaders(headers)
        self._assertObjectEtag(self.bucket, obj, etag)

    def test_get_object_response_content_type(self):
        obj = 'obj'
        self.conn.make_request('PUT', self.bucket, obj)

        query = 'response-content-type=text/plain'
        status, headers, body = \
            self.conn.make_request('GET', self.bucket, obj, query=query)
        self.assertEquals(status, 200)
        self.assertCommonResponseHeaders(headers)
        self.assertEquals(headers['content-type'], 'text/plain')

    def test_get_object_response_content_language(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)

        query = 'response-content-language=en'
        status, headers, body = \
            self.conn.make_request('GET', self.bucket, obj, query=query)
        self.assertEquals(status, 200)
        self.assertCommonResponseHeaders(headers)
        self.assertEquals(headers['content-language'], 'en')

    def test_get_object_response_cache_control(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)

        query = 'response-cache-control=private'
        status, headers, body = \
            self.conn.make_request('GET', self.bucket, obj, query=query)
        self.assertEquals(status, 200)
        self.assertCommonResponseHeaders(headers)
        self.assertEquals(headers['cache-control'], 'private')

    def test_get_object_response_content_disposition(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)

        query = 'response-content-disposition=inline'
        status, headers, body = \
            self.conn.make_request('GET', self.bucket, obj, query=query)
        self.assertEquals(status, 200)
        self.assertCommonResponseHeaders(headers)
        self.assertEquals(headers['content-disposition'], 'inline')

    def test_get_object_response_content_encoding(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)

        query = 'response-content-encoding=gzip'
        status, headers, body = \
            self.conn.make_request('GET', self.bucket, obj, query=query)
        self.assertEquals(status, 200)
        self.assertCommonResponseHeaders(headers)
        self.assertEquals(headers['content-encoding'], 'gzip')

    def test_get_object_range(self):
        obj = 'object'
        content = 'abcdefghij'
        headers = {'x-amz-meta-test': 'swift'}
        self.conn.make_request(
            'PUT', self.bucket, obj, headers=headers, body=content)

        headers = {'Range': 'bytes=1-5'}
        status, headers, body = \
            self.conn.make_request('GET', self.bucket, obj, headers=headers)
        self.assertEquals(status, 206)
        self.assertCommonResponseHeaders(headers)
        self.assertTrue('content-length' in headers)
        self.assertEquals(headers['content-length'], '5')
        self.assertTrue('x-amz-meta-test' in headers)
        self.assertEquals('swift', headers['x-amz-meta-test'])
        self.assertEquals(body, 'bcdef')

        headers = {'Range': 'bytes=5-'}
        status, headers, body = \
            self.conn.make_request('GET', self.bucket, obj, headers=headers)
        self.assertEquals(status, 206)
        self.assertCommonResponseHeaders(headers)
        self.assertTrue('content-length' in headers)
        self.assertEquals(headers['content-length'], '5')
        self.assertTrue('x-amz-meta-test' in headers)
        self.assertEquals('swift', headers['x-amz-meta-test'])
        self.assertEquals(body, 'fghij')

        headers = {'Range': 'bytes=-5'}
        status, headers, body = \
            self.conn.make_request('GET', self.bucket, obj, headers=headers)
        self.assertEquals(status, 206)
        self.assertCommonResponseHeaders(headers)
        self.assertTrue('content-length' in headers)
        self.assertEquals(headers['content-length'], '5')
        self.assertTrue('x-amz-meta-test' in headers)
        self.assertEquals('swift', headers['x-amz-meta-test'])
        self.assertEquals(body, 'fghij')

        ranges = ['1-2', '4-5']

        headers = {'Range': 'bytes=%s' % ','.join(ranges)}
        status, headers, body = \
            self.conn.make_request('GET', self.bucket, obj, headers=headers)
        self.assertEquals(status, 206)
        self.assertCommonResponseHeaders(headers)
        self.assertTrue('content-length' in headers)

        self.assertTrue('content-type' in headers)  # sanity
        content_type, boundary = headers['content-type'].split(';')

        self.assertEquals('multipart/byteranges', content_type)
        self.assertTrue(boundary.startswith('boundary='))  # sanity
        boundary_str = boundary[len('boundary='):]

        sio = StringIO(body)
        mfile = MultiFile(sio)
        mfile.push(boundary_str)

        def check_line_header(line, expected_key, expected_value):
            key, value = line.split(':', 1)
            self.assertEquals(expected_key, key.strip())
            self.assertEquals(expected_value, value.strip())

        for range_value in ranges:
            start, end = map(int, range_value.split('-'))
            # go to next section and check sanity
            self.assertTrue(mfile.next())

            lines = mfile.readlines()
            # first line should be content-type which
            # includes original content-type
            # e.g. Content-Type: application/octet-stream
            check_line_header(
                lines[0].strip(), 'Content-Type', 'application/octet-stream')

            # second line should be byte range information
            # e.g. Content-Range: bytes 1-2/11
            expected_range = 'bytes %s/%s' % (range_value, len(content))
            check_line_header(
                lines[1].strip(), 'Content-Range', expected_range)
            # rest
            rest = [line for line in lines[2:] if line.strip()]
            self.assertEquals(1, len(rest))  # sanity
            self.assertTrue(content[start:end], rest[0])

        # no next section
        self.assertFalse(mfile.next())  # sanity

    def test_get_object_if_modified_since(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)

        _, headers, _ = self.conn.make_request('HEAD', self.bucket, obj)
        src_datetime = mktime(parsedate(headers['last-modified']))
        src_datetime = src_datetime - DAY
        headers = {'If-Modified-Since': formatdate(src_datetime)}
        status, headers, body = \
            self.conn.make_request('GET', self.bucket, obj, headers=headers)
        self.assertEquals(status, 200)
        self.assertCommonResponseHeaders(headers)

    def test_get_object_if_unmodified_since(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)

        _, headers, _ = self.conn.make_request('HEAD', self.bucket, obj)
        src_datetime = mktime(parsedate(headers['last-modified']))
        src_datetime = src_datetime + DAY
        headers = \
            {'If-Unmodified-Since': formatdate(src_datetime)}
        status, headers, body = \
            self.conn.make_request('GET', self.bucket, obj, headers=headers)
        self.assertEquals(status, 200)
        self.assertCommonResponseHeaders(headers)

    def test_get_object_if_match(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)

        status, headers, body = \
            self.conn.make_request('HEAD', self.bucket, obj)
        etag = headers['etag']

        headers = {'If-Match': etag}
        status, headers, body = \
            self.conn.make_request('GET', self.bucket, obj, headers=headers)
        self.assertEquals(status, 200)
        self.assertCommonResponseHeaders(headers)

    def test_get_object_if_none_match(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)

        headers = {'If-None-Match': 'none-match'}
        status, headers, body = \
            self.conn.make_request('GET', self.bucket, obj, headers=headers)
        self.assertEquals(status, 200)
        self.assertCommonResponseHeaders(headers)

    def test_head_object_range(self):
        obj = 'object'
        content = 'abcdefghij'
        self.conn.make_request('PUT', self.bucket, obj, body=content)

        headers = {'Range': 'bytes=1-5'}
        status, headers, body = \
            self.conn.make_request('HEAD', self.bucket, obj, headers=headers)
        self.assertEquals(headers['content-length'], '5')
        self.assertCommonResponseHeaders(headers)

        headers = {'Range': 'bytes=5-'}
        status, headers, body = \
            self.conn.make_request('HEAD', self.bucket, obj, headers=headers)
        self.assertEquals(headers['content-length'], '5')
        self.assertCommonResponseHeaders(headers)

        headers = {'Range': 'bytes=-5'}
        status, headers, body = \
            self.conn.make_request('HEAD', self.bucket, obj, headers=headers)
        self.assertEquals(headers['content-length'], '5')
        self.assertCommonResponseHeaders(headers)

    def test_head_object_if_modified_since(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)

        _, headers, _ = self.conn.make_request('HEAD', self.bucket, obj)
        dt = mktime(parsedate(headers['last-modified']))
        dt = dt - DAY

        headers = {'If-Modified-Since': formatdate(dt)}
        status, headers, body = \
            self.conn.make_request('HEAD', self.bucket, obj, headers=headers)
        self.assertEquals(status, 200)
        self.assertCommonResponseHeaders(headers)

    def test_head_object_if_unmodified_since(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)

        _, headers, _ = self.conn.make_request('HEAD', self.bucket, obj)
        dt = mktime(parsedate(headers['last-modified']))
        dt = dt + DAY

        headers = {'If-Unmodified-Since': formatdate(dt)}
        status, headers, body = \
            self.conn.make_request('HEAD', self.bucket, obj, headers=headers)
        self.assertEquals(status, 200)
        self.assertCommonResponseHeaders(headers)

    def test_head_object_if_match(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)

        status, headers, body = \
            self.conn.make_request('HEAD', self.bucket, obj)
        etag = headers['etag']

        headers = {'If-Match': etag}
        status, headers, body = \
            self.conn.make_request('HEAD', self.bucket, obj, headers=headers)
        self.assertEquals(status, 200)
        self.assertCommonResponseHeaders(headers)

    def test_head_object_if_none_match(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)

        headers = {'If-None-Match': 'none-match'}
        status, headers, body = \
            self.conn.make_request('HEAD', self.bucket, obj, headers=headers)
        self.assertEquals(status, 200)
        self.assertCommonResponseHeaders(headers)

if __name__ == '__main__':
    unittest.main()
