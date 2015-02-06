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
import cgi

from swift.common import swob
from swift.common.swob import Request
from swift.common.utils import json

from swift3.test.unit import Swift3TestCase
from swift3.etree import Element, SubElement, fromstring, tostring
from swift3.test.unit.test_s3_acl import s3acl
from swift3.subresource import Owner, encode_acl, ACLPublicRead


class TestSwift3Bucket(Swift3TestCase):
    def setup_objects(self):
        self.objects = (('rose', '2011-01-05T02:19:14.275290', 0, 303),
                        ('viola', '2011-01-05T02:19:14.275290', 0, 3909),
                        ('lily', '2011-01-05T02:19:14.275290', 0, 3909),
                        ('with space', '2011-01-05T02:19:14.275290', 0, 390),
                        ('with%20space', '2011-01-05T02:19:14.275290', 0, 390))

        objects = map(
            lambda item: {'name': str(item[0]), 'last_modified': str(item[1]),
                          'hash': str(item[2]), 'bytes': str(item[3])},
            list(self.objects))
        object_list = json.dumps(objects)

        self.prefixes = ['rose', 'viola', 'lily']
        object_list_subdir = []
        for p in self.prefixes:
            object_list_subdir.append({"subdir": p})

        self.swift.register('HEAD', '/v1/AUTH_test/junk', swob.HTTPNoContent,
                            {}, None)
        self.swift.register('HEAD', '/v1/AUTH_test/nojunk', swob.HTTPNotFound,
                            {}, None)
        self.swift.register('GET', '/v1/AUTH_test/junk', swob.HTTPOk, {},
                            object_list)
        self.swift.register('GET', '/v1/AUTH_test/junk_subdir', swob.HTTPOk,
                            {}, json.dumps(object_list_subdir))

    def setUp(self):
        super(TestSwift3Bucket, self).setUp()

        self.setup_objects()

    def test_bucket_HEAD(self):
        req = Request.blank('/junk',
                            environ={'REQUEST_METHOD': 'HEAD'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_bucket_HEAD_error(self):
        req = Request.blank('/nojunk',
                            environ={'REQUEST_METHOD': 'HEAD'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '404')

    def test_bucket_HEAD_slash(self):
        req = Request.blank('/junk/',
                            environ={'REQUEST_METHOD': 'HEAD'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_bucket_HEAD_slash_error(self):
        req = Request.blank('/nojunk/',
                            environ={'REQUEST_METHOD': 'HEAD'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '404')

    @s3acl
    def test_bucket_GET_error(self):
        code = self._test_method_error('GET', '/bucket', swob.HTTPUnauthorized)
        self.assertEquals(code, 'SignatureDoesNotMatch')
        code = self._test_method_error('GET', '/bucket', swob.HTTPForbidden)
        self.assertEquals(code, 'AccessDenied')
        code = self._test_method_error('GET', '/bucket', swob.HTTPNotFound)
        self.assertEquals(code, 'NoSuchBucket')
        code = self._test_method_error('GET', '/bucket', swob.HTTPServerError)
        self.assertEquals(code, 'InternalError')

    def test_bucket_GET(self):
        bucket_name = 'junk'
        req = Request.blank('/%s' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

        elem = fromstring(body, 'ListBucketResult')
        name = elem.find('./Name').text
        self.assertEquals(name, bucket_name)

        objects = elem.iterchildren('Contents')

        names = []
        for o in objects:
            names.append(o.find('./Key').text)
            self.assertTrue(o.find('./LastModified').text.endswith('Z'))

        self.assertEquals(len(names), len(self.objects))
        for i in self.objects:
            self.assertTrue(i[0] in names)

    def test_bucket_GET_subdir(self):
        bucket_name = 'junk_subdir'
        req = Request.blank('/%s' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')
        elem = fromstring(body, 'ListBucketResult')
        name = elem.find('./Name').text
        self.assertEquals(name, bucket_name)

        prefixes = elem.findall('CommonPrefixes')

        self.assertEquals(len(prefixes), len(self.prefixes))
        for p in prefixes:
            self.assertTrue(p.find('./Prefix').text in self.prefixes)

    def test_bucket_GET_is_truncated(self):
        bucket_name = 'junk'

        req = Request.blank('/%s?max-keys=5' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        elem = fromstring(body, 'ListBucketResult')
        self.assertEquals(elem.find('./IsTruncated').text, 'false')

        req = Request.blank('/%s?max-keys=4' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        elem = fromstring(body, 'ListBucketResult')
        self.assertEquals(elem.find('./IsTruncated').text, 'true')

    def test_bucket_GET_max_keys(self):
        bucket_name = 'junk'

        req = Request.blank('/%s?max-keys=5' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        elem = fromstring(body, 'ListBucketResult')
        self.assertEquals(elem.find('./MaxKeys').text, '5')
        _, path = self.swift.calls[-1]
        _, query_string = path.split('?')
        args = dict(cgi.parse_qsl(query_string))
        self.assert_(args['limit'] == '6')

        req = Request.blank('/%s?max-keys=5000' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        elem = fromstring(body, 'ListBucketResult')
        self.assertEquals(elem.find('./MaxKeys').text, '1000')
        _, path = self.swift.calls[-1]
        _, query_string = path.split('?')
        args = dict(cgi.parse_qsl(query_string))
        self.assertEquals(args['limit'], '1001')

    def test_bucket_GET_passthroughs(self):
        bucket_name = 'junk'
        req = Request.blank('/%s?delimiter=a&marker=b&prefix=c' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        elem = fromstring(body, 'ListBucketResult')
        self.assertEquals(elem.find('./Prefix').text, 'c')
        self.assertEquals(elem.find('./Marker').text, 'b')
        self.assertEquals(elem.find('./Delimiter').text, 'a')
        _, path = self.swift.calls[-1]
        _, query_string = path.split('?')
        args = dict(cgi.parse_qsl(query_string))
        self.assertEquals(args['delimiter'], 'a')
        self.assertEquals(args['marker'], 'b')
        self.assertEquals(args['prefix'], 'c')

    def test_bucket_GET_with_nonascii_queries(self):
        bucket_name = 'junk'
        req = Request.blank(
            '/%s?delimiter=\xef\xbc\xa1&marker=\xef\xbc\xa2&'
            'prefix=\xef\xbc\xa3' % bucket_name,
            environ={'REQUEST_METHOD': 'GET'},
            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        elem = fromstring(body, 'ListBucketResult')
        self.assertEquals(elem.find('./Prefix').text, '\xef\xbc\xa3')
        self.assertEquals(elem.find('./Marker').text, '\xef\xbc\xa2')
        self.assertEquals(elem.find('./Delimiter').text, '\xef\xbc\xa1')
        _, path = self.swift.calls[-1]
        _, query_string = path.split('?')
        args = dict(cgi.parse_qsl(query_string))
        self.assertEquals(args['delimiter'], '\xef\xbc\xa1')
        self.assertEquals(args['marker'], '\xef\xbc\xa2')
        self.assertEquals(args['prefix'], '\xef\xbc\xa3')

    def test_bucket_GET_with_delimiter_max_keys(self):
        bucket_name = 'junk'
        req = Request.blank('/%s?delimiter=a&max-keys=2' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')
        elem = fromstring(body, 'ListBucketResult')
        self.assertEquals(elem.find('./NextMarker').text, 'viola')
        self.assertEquals(elem.find('./MaxKeys').text, '2')
        self.assertEquals(elem.find('./IsTruncated').text, 'true')

    def test_bucket_GET_subdir_with_delimiter_max_keys(self):
        bucket_name = 'junk_subdir'
        req = Request.blank('/%s?delimiter=a&max-keys=1' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')
        elem = fromstring(body, 'ListBucketResult')
        self.assertEquals(elem.find('./NextMarker').text, 'rose')
        self.assertEquals(elem.find('./MaxKeys').text, '1')
        self.assertEquals(elem.find('./IsTruncated').text, 'true')

    @s3acl
    def test_bucket_PUT_error(self):
        code = self._test_method_error('PUT', '/bucket', swob.HTTPCreated,
                                       headers={'Content-Length': 'a'})
        self.assertEqual(code, 'InvalidArgument')
        code = self._test_method_error('PUT', '/bucket', swob.HTTPCreated,
                                       headers={'Content-Length': '-1'})
        self.assertEqual(code, 'InvalidArgument')
        code = self._test_method_error('PUT', '/bucket', swob.HTTPUnauthorized)
        self.assertEquals(code, 'SignatureDoesNotMatch')
        code = self._test_method_error('PUT', '/bucket', swob.HTTPForbidden)
        self.assertEquals(code, 'AccessDenied')
        code = self._test_method_error('PUT', '/bucket', swob.HTTPAccepted)
        self.assertEquals(code, 'BucketAlreadyExists')
        code = self._test_method_error('PUT', '/bucket', swob.HTTPServerError)
        self.assertEquals(code, 'InternalError')
        code = self._test_method_error(
            'PUT', '/bucket+bucket', swob.HTTPCreated)
        self.assertEqual(code, 'InvalidBucketName')
        code = self._test_method_error(
            'PUT', '/192.168.11.1', swob.HTTPCreated)
        self.assertEqual(code, 'InvalidBucketName')
        code = self._test_method_error(
            'PUT', '/bucket.-bucket', swob.HTTPCreated)
        self.assertEqual(code, 'InvalidBucketName')
        code = self._test_method_error(
            'PUT', '/bucket-.bucket', swob.HTTPCreated)
        self.assertEqual(code, 'InvalidBucketName')
        code = self._test_method_error('PUT', '/bucket*', swob.HTTPCreated)
        self.assertEqual(code, 'InvalidBucketName')
        code = self._test_method_error('PUT', '/b', swob.HTTPCreated)
        self.assertEqual(code, 'InvalidBucketName')
        code = self._test_method_error(
            'PUT', '/%s' % ''.join(['b' for x in xrange(64)]),
            swob.HTTPCreated)
        self.assertEqual(code, 'InvalidBucketName')

    @s3acl
    def test_bucket_PUT(self):
        req = Request.blank('/bucket',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')
        self.assertEquals(headers['Location'], '/bucket')

    @s3acl
    def test_bucket_PUT_with_location(self):
        elem = Element('CreateBucketConfiguration')
        SubElement(elem, 'LocationConstraint').text = 'US'
        xml = tostring(elem)

        req = Request.blank('/bucket',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=xml)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_bucket_PUT_with_canned_acl(self):
        req = Request.blank('/bucket',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'X-Amz-Acl': 'public-read'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')
        _, _, headers = self.swift.calls_with_headers[-1]
        self.assertTrue('X-Container-Read' in headers)
        self.assertEquals(headers.get('X-Container-Read'), '.r:*,.rlistings')
        self.assertTrue('X-Container-Sysmeta-Swift3-Acl' not in headers)

    @s3acl(s3acl_only=True)
    def test_bucket_PUT_with_canned_s3acl(self):
        account = 'test:tester'
        acl = \
            encode_acl('container', ACLPublicRead(Owner(account, account)))
        req = Request.blank('/bucket',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'X-Amz-Acl': 'public-read'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')
        _, _, headers = self.swift.calls_with_headers[-1]
        self.assertTrue('X-Container-Read' not in headers)
        self.assertTrue('X-Container-Sysmeta-Swift3-Acl' in headers)
        self.assertEquals(headers.get('X-Container-Sysmeta-Swift3-Acl'),
                          acl['x-container-sysmeta-swift3-acl'])

    @s3acl
    def test_bucket_PUT_with_location_error(self):
        elem = Element('CreateBucketConfiguration')
        SubElement(elem, 'LocationConstraint').text = 'XXX'
        xml = tostring(elem)

        req = Request.blank('/bucket',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=xml)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body),
                          'InvalidLocationConstraint')

    @s3acl
    def test_bucket_PUT_with_location_invalid_xml(self):
        req = Request.blank('/bucket',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body='invalid_xml')
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'MalformedXML')

    @s3acl
    def test_bucket_DELETE_error(self):
        code = self._test_method_error('DELETE', '/bucket',
                                       swob.HTTPUnauthorized)
        self.assertEquals(code, 'SignatureDoesNotMatch')
        code = self._test_method_error('DELETE', '/bucket', swob.HTTPForbidden)
        self.assertEquals(code, 'AccessDenied')
        code = self._test_method_error('DELETE', '/bucket', swob.HTTPNotFound)
        self.assertEquals(code, 'NoSuchBucket')
        code = self._test_method_error('DELETE', '/bucket', swob.HTTPConflict)
        self.assertEquals(code, 'BucketNotEmpty')
        code = self._test_method_error('DELETE', '/bucket',
                                       swob.HTTPServerError)
        self.assertEquals(code, 'InternalError')

    @s3acl
    def test_bucket_DELETE(self):
        req = Request.blank('/bucket',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '204')

    def _test_bucket_for_s3acl(self, method, account):
        req = Request.blank('/bucket',
                            environ={'REQUEST_METHOD': method},
                            headers={'Authorization': 'AWS %s:hmac' % account})

        return self.call_swift3(req)

    @s3acl(s3acl_only=True)
    def test_bucket_GET_without_permission(self):
        status, headers, body = self._test_bucket_for_s3acl('GET',
                                                            'test:other')
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    @s3acl(s3acl_only=True)
    def test_bucket_GET_with_read_permission(self):
        status, headers, body = self._test_bucket_for_s3acl('GET',
                                                            'test:read')
        self.assertEquals(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_bucket_GET_with_fullcontrol_permission(self):
        status, headers, body = \
            self._test_bucket_for_s3acl('GET', 'test:full_control')
        self.assertEquals(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_bucket_GET_with_owner_permission(self):
        status, headers, body = self._test_bucket_for_s3acl('GET',
                                                            'test:tester')
        self.assertEquals(status.split()[0], '200')

    def _test_bucket_GET_canned_acl(self, bucket):
        req = Request.blank('/%s' % bucket,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})

        return self.call_swift3(req)

    @s3acl(s3acl_only=True)
    def test_bucket_GET_authenticated_users(self):
        status, headers, body = \
            self._test_bucket_GET_canned_acl('authenticated')
        self.assertEquals(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_bucket_GET_all_users(self):
        status, headers, body = self._test_bucket_GET_canned_acl('public')
        self.assertEquals(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_bucket_DELETE_without_permission(self):
        status, headers, body = self._test_bucket_for_s3acl('DELETE',
                                                            'test:other')
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    @s3acl(s3acl_only=True)
    def test_bucket_DELETE_with_write_permission(self):
        status, headers, body = self._test_bucket_for_s3acl('DELETE',
                                                            'test:write')
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    @s3acl(s3acl_only=True)
    def test_bucket_DELETE_with_fullcontrol_permission(self):
        status, headers, body = \
            self._test_bucket_for_s3acl('DELETE', 'test:full_control')
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

if __name__ == '__main__':
    unittest.main()
