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
from swift.common.middleware.versioned_writes import DELETE_MARKER_CONTENT_TYPE
from swift.common.swob import Request
from swift.common.utils import json

from swift3.test.unit import Swift3TestCase
from swift3.etree import Element, SubElement, fromstring, tostring
from swift3.test.unit.test_s3_acl import s3acl
from swift3.subresource import Owner, encode_acl, ACLPublicRead
from swift3.request import MAX_32BIT_INT


class TestSwift3Bucket(Swift3TestCase):
    def setup_objects(self):
        self.objects = (('rose', '2011-01-05T02:19:14.275290', 0, 303),
                        ('viola', '2011-01-05T02:19:14.275290', '0', 3909),
                        ('lily', '2011-01-05T02:19:14.275290', '0', '3909'),
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

        self.swift.register('DELETE', '/v1/AUTH_test/bucket+segments',
                            swob.HTTPNoContent, {}, json.dumps([]))
        self.swift.register('DELETE', '/v1/AUTH_test/bucket+segments/rose',
                            swob.HTTPNoContent, {}, json.dumps([]))
        self.swift.register('DELETE', '/v1/AUTH_test/bucket+segments/viola',
                            swob.HTTPNoContent, {}, json.dumps([]))
        self.swift.register('DELETE', '/v1/AUTH_test/bucket+segments/lily',
                            swob.HTTPNoContent, {}, json.dumps([]))
        self.swift.register('DELETE', '/v1/AUTH_test/bucket+segments/with'
                            ' space', swob.HTTPNoContent, {}, json.dumps([]))
        self.swift.register('DELETE', '/v1/AUTH_test/bucket+segments/with%20'
                            'space', swob.HTTPNoContent, {}, json.dumps([]))
        self.swift.register('GET', '/v1/AUTH_test/bucket+segments?format=json'
                            '&marker=with%2520space', swob.HTTPOk, {},
                            json.dumps([]))
        self.swift.register('GET', '/v1/AUTH_test/bucket+segments?format=json'
                            '&marker=', swob.HTTPOk, {}, object_list)
        self.swift.register('HEAD', '/v1/AUTH_test/junk', swob.HTTPNoContent,
                            {}, None)
        self.swift.register('HEAD', '/v1/AUTH_test/nojunk', swob.HTTPNotFound,
                            {}, None)
        self.swift.register('GET', '/v1/AUTH_test/junk', swob.HTTPOk, {},
                            object_list)
        self.swift.register('GET', '/v1/AUTH_test/junk-subdir', swob.HTTPOk,
                            {}, json.dumps(object_list_subdir))

    def setUp(self):
        super(TestSwift3Bucket, self).setUp()
        self.setup_objects()

    def test_bucket_HEAD(self):
        req = Request.blank('/junk',
                            environ={'REQUEST_METHOD': 'HEAD'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_swift3(req)
        self.assertEqual(status.split()[0], '200')

    def test_bucket_HEAD_error(self):
        req = Request.blank('/nojunk',
                            environ={'REQUEST_METHOD': 'HEAD'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_swift3(req)
        self.assertEqual(status.split()[0], '404')
        self.assertEqual(body, '')  # sanity

    def test_bucket_HEAD_slash(self):
        req = Request.blank('/junk/',
                            environ={'REQUEST_METHOD': 'HEAD'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_swift3(req)
        self.assertEqual(status.split()[0], '200')

    def test_bucket_HEAD_slash_error(self):
        req = Request.blank('/nojunk/',
                            environ={'REQUEST_METHOD': 'HEAD'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_swift3(req)
        self.assertEqual(status.split()[0], '404')

    @s3acl
    def test_bucket_GET_error(self):
        code = self._test_method_error('GET', '/bucket', swob.HTTPUnauthorized)
        self.assertEqual(code, 'SignatureDoesNotMatch')
        code = self._test_method_error('GET', '/bucket', swob.HTTPForbidden)
        self.assertEqual(code, 'AccessDenied')
        code = self._test_method_error('GET', '/bucket', swob.HTTPNotFound)
        self.assertEqual(code, 'NoSuchBucket')
        code = self._test_method_error('GET', '/bucket', swob.HTTPServerError)
        self.assertEqual(code, 'InternalError')

    def test_bucket_GET(self):
        bucket_name = 'junk'
        req = Request.blank('/%s' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_swift3(req)
        self.assertEqual(status.split()[0], '200')

        elem = fromstring(body, 'ListBucketResult')
        name = elem.find('./Name').text
        self.assertEqual(name, bucket_name)

        objects = elem.iterchildren('Contents')

        names = []
        for o in objects:
            names.append(o.find('./Key').text)
            self.assertEqual('2011-01-05T02:19:14.275Z',
                             o.find('./LastModified').text)
            self.assertEqual('"0"', o.find('./ETag').text)

        self.assertEqual(len(names), len(self.objects))
        for i in self.objects:
            self.assertTrue(i[0] in names)

    def test_bucket_GET_subdir(self):
        bucket_name = 'junk-subdir'
        req = Request.blank('/%s' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_swift3(req)
        self.assertEqual(status.split()[0], '200')
        elem = fromstring(body, 'ListBucketResult')
        name = elem.find('./Name').text
        self.assertEqual(name, bucket_name)

        prefixes = elem.findall('CommonPrefixes')

        self.assertEqual(len(prefixes), len(self.prefixes))
        for p in prefixes:
            self.assertTrue(p.find('./Prefix').text in self.prefixes)

    def test_bucket_GET_is_truncated(self):
        bucket_name = 'junk'

        req = Request.blank('/%s?max-keys=5' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_swift3(req)
        elem = fromstring(body, 'ListBucketResult')
        self.assertEqual(elem.find('./IsTruncated').text, 'false')

        req = Request.blank('/%s?max-keys=4' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_swift3(req)
        elem = fromstring(body, 'ListBucketResult')
        self.assertEqual(elem.find('./IsTruncated').text, 'true')

    def test_bucket_GET_max_keys(self):
        bucket_name = 'junk'

        req = Request.blank('/%s?max-keys=5' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_swift3(req)
        elem = fromstring(body, 'ListBucketResult')
        self.assertEqual(elem.find('./MaxKeys').text, '5')
        _, path = self.swift.calls[-1]
        _, query_string = path.split('?')
        args = dict(cgi.parse_qsl(query_string))
        self.assertEqual(args['limit'], '6')

        req = Request.blank('/%s?max-keys=5000' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_swift3(req)
        elem = fromstring(body, 'ListBucketResult')
        self.assertEqual(elem.find('./MaxKeys').text, '5000')
        _, path = self.swift.calls[-1]
        _, query_string = path.split('?')
        args = dict(cgi.parse_qsl(query_string))
        self.assertEqual(args['limit'], '1001')

    def test_bucket_GET_str_max_keys(self):
        bucket_name = 'junk'

        req = Request.blank('/%s?max-keys=invalid' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_swift3(req)
        self.assertEqual(self._get_error_code(body), 'InvalidArgument')

    def test_bucket_GET_negative_max_keys(self):
        bucket_name = 'junk'

        req = Request.blank('/%s?max-keys=-1' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_swift3(req)
        self.assertEqual(self._get_error_code(body), 'InvalidArgument')

    def test_bucket_GET_over_32bit_int_max_keys(self):
        bucket_name = 'junk'

        req = Request.blank('/%s?max-keys=%s' %
                            (bucket_name, MAX_32BIT_INT + 1),
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_swift3(req)
        self.assertEqual(self._get_error_code(body), 'InvalidArgument')

    def test_bucket_GET_passthroughs(self):
        bucket_name = 'junk'
        req = Request.blank('/%s?delimiter=a&marker=b&prefix=c' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_swift3(req)
        elem = fromstring(body, 'ListBucketResult')
        self.assertEqual(elem.find('./Prefix').text, 'c')
        self.assertEqual(elem.find('./Marker').text, 'b')
        self.assertEqual(elem.find('./Delimiter').text, 'a')
        _, path = self.swift.calls[-1]
        _, query_string = path.split('?')
        args = dict(cgi.parse_qsl(query_string))
        self.assertEqual(args['delimiter'], 'a')
        self.assertEqual(args['marker'], 'b')
        self.assertEqual(args['prefix'], 'c')

    def test_bucket_GET_with_nonascii_queries(self):
        bucket_name = 'junk'
        req = Request.blank(
            '/%s?delimiter=\xef\xbc\xa1&marker=\xef\xbc\xa2&'
            'prefix=\xef\xbc\xa3' % bucket_name,
            environ={'REQUEST_METHOD': 'GET'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'Date': self.get_date_header()})
        status, headers, body = self.call_swift3(req)
        elem = fromstring(body, 'ListBucketResult')
        self.assertEqual(elem.find('./Prefix').text, '\xef\xbc\xa3')
        self.assertEqual(elem.find('./Marker').text, '\xef\xbc\xa2')
        self.assertEqual(elem.find('./Delimiter').text, '\xef\xbc\xa1')
        _, path = self.swift.calls[-1]
        _, query_string = path.split('?')
        args = dict(cgi.parse_qsl(query_string))
        self.assertEqual(args['delimiter'], '\xef\xbc\xa1')
        self.assertEqual(args['marker'], '\xef\xbc\xa2')
        self.assertEqual(args['prefix'], '\xef\xbc\xa3')

    def test_bucket_GET_with_delimiter_max_keys(self):
        bucket_name = 'junk'
        req = Request.blank('/%s?delimiter=a&max-keys=2' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_swift3(req)
        self.assertEqual(status.split()[0], '200')
        elem = fromstring(body, 'ListBucketResult')
        self.assertEqual(elem.find('./NextMarker').text, 'viola')
        self.assertEqual(elem.find('./MaxKeys').text, '2')
        self.assertEqual(elem.find('./IsTruncated').text, 'true')

    def test_bucket_GET_subdir_with_delimiter_max_keys(self):
        bucket_name = 'junk-subdir'
        req = Request.blank('/%s?delimiter=a&max-keys=1' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_swift3(req)
        self.assertEqual(status.split()[0], '200')
        elem = fromstring(body, 'ListBucketResult')
        self.assertEqual(elem.find('./NextMarker').text, 'rose')
        self.assertEqual(elem.find('./MaxKeys').text, '1')
        self.assertEqual(elem.find('./IsTruncated').text, 'true')

    def test_bucket_GET_with_versions_versioning_not_configured(self):
        self.swift.register('GET', '/v1/AUTH_test/junk+versioning',
                            swob.HTTPNotFound, {}, None)
        for obj in self.objects:
            self.swift.register('HEAD', '/v1/AUTH_test/junk/%s' % obj[0],
                                swob.HTTPOk, {}, None)
        self.swift.register('HEAD', '/v1/AUTH_test/junk/viola',
                            swob.HTTPOk, {}, None)

        req = Request.blank('/junk?versions',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_swift3(req)

        self.assertEqual(status.split()[0], '200')
        elem = fromstring(body, 'ListVersionsResult')
        self.assertEqual(elem.find('./Name').text, 'junk')
        self.assertEqual(elem.find('./Prefix').text, None)
        self.assertEqual(elem.find('./KeyMarker').text, None)
        self.assertEqual(elem.find('./VersionIdMarker').text, None)
        self.assertEqual(elem.find('./MaxKeys').text, '1000')
        self.assertEqual(elem.find('./IsTruncated').text, 'false')
        self.assertEqual(elem.findall('./DeleteMarker'), [])
        versions = elem.findall('./Version')
        objects = list(self.objects)
        objects.sort(key=lambda o: o[0])
        self.assertEqual(len(versions), len(objects))
        self.assertEqual([v.find('./Key').text for v in versions],
                         [v[0] for v in objects])
        self.assertEqual([v.find('./IsLatest').text for v in versions],
                         ['true' for v in objects])
        self.assertEqual([v.find('./VersionId').text for v in versions],
                         ['null' for v in objects])
        # Last modified in self.objects is 2011-01-05T02:19:14.275290 but
        # the returned value is 2011-01-05T02:19:14.275Z
        self.assertEqual([v.find('./LastModified').text for v in versions],
                         [v[1][:-3] + 'Z' for v in objects])
        self.assertEqual([v.find('./ETag').text for v in versions],
                         ['"%s"' % v[2] for v in objects])
        self.assertEqual([v.find('./Size').text for v in versions],
                         [str(v[3]) for v in objects])
        self.assertEqual([v.find('./Owner/ID').text for v in versions],
                         ['test:tester' for v in objects])
        self.assertEqual([v.find('./Owner/DisplayName').text
                          for v in versions],
                         ['test:tester' for v in objects])
        self.assertEqual([v.find('./StorageClass').text for v in versions],
                         ['STANDARD' for v in objects])

    def test_bucket_GET_with_versions(self):
        versioned_objects = [
            {'name': '004rose/2', 'hash': '0', 'bytes': '0',
             'last_modified': '2010-03-01T17:09:51.510928',
             'content_type': DELETE_MARKER_CONTENT_TYPE},
            {'name': '004rose/1', 'hash': '1234', 'bytes': '6',
             'last_modified': '2010-03-01T17:09:50.510928'},
        ]
        self.swift.register('GET', '/v1/AUTH_test/junk+versioning',
                            swob.HTTPOk, {}, json.dumps(versioned_objects))
        for obj in self.objects:
            if obj[0] == 'rose':
                headers = {'X-Object-Sysmeta-Version-Id': '3'}
            else:
                headers = {}
            self.swift.register('HEAD', '/v1/AUTH_test/junk/%s' % obj[0],
                                swob.HTTPOk, headers, None)

        req = Request.blank('/junk?versions',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_swift3(req)

        self.assertEqual(status.split()[0], '200')
        elem = fromstring(body, 'ListVersionsResult')
        self.assertEqual(elem.find('./Name').text, 'junk')
        delete_markers = elem.findall('./DeleteMarker')
        self.assertEqual(len(delete_markers), 1)
        self.assertEqual(delete_markers[0].find('./IsLatest').text, 'false')
        self.assertEqual(delete_markers[0].find('./VersionId').text, '2')
        self.assertEqual(delete_markers[0].find('./Key').text, 'rose')
        versions = elem.findall('./Version')
        self.assertEqual(len(versions), len(self.objects) + 1)
        self.assertEqual(versions[2].find('./IsLatest').text, 'false')
        self.assertEqual(versions[2].find('./VersionId').text, '1')
        # Test that version id is retrieved from sysmeta
        self.assertEqual(versions[1].find('./VersionId').text, '3')
        self.assertEqual(versions[2].find('./Key').text, 'rose')

        # with max keys
        req = Request.blank('/junk?versions&max-keys=3',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_swift3(req)

        self.assertEqual(status.split()[0], '200')
        elem = fromstring(body, 'ListVersionsResult')
        self.assertEqual(elem.find('./MaxKeys').text, '3')
        self.assertEqual(elem.find('./IsTruncated').text, 'true')
        delete_markers = elem.findall('./DeleteMarker')
        self.assertEqual(len(delete_markers), 1)
        versions = elem.findall('./Version')
        self.assertEqual(len(versions), 2)
        self.assertEqual([v.find('./Key').text for v in versions],
                         ['lily', 'rose'])
        self.assertEqual([v.find('./VersionId').text for v in versions],
                         ['null', '3'])
        self.assertEqual([v.find('./IsLatest').text for v in versions],
                         ['true', 'true'])

        # with key-marker
        req = Request.blank('/junk?versions&max-keys=2&key-marker=rose',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_swift3(req)

        self.assertEqual(status.split()[0], '200')
        elem = fromstring(body, 'ListVersionsResult')
        self.assertEqual(elem.find('./MaxKeys').text, '2')
        self.assertEqual(elem.find('./IsTruncated').text, 'true')
        delete_markers = elem.findall('./DeleteMarker')
        self.assertEqual(len(delete_markers), 1)
        self.assertEqual(delete_markers[0].find('./Key').text, 'rose')
        self.assertEqual(delete_markers[0].find('./VersionId').text, '2')
        versions = elem.findall('./Version')
        self.assertEqual(len(versions), 1)
        self.assertEqual(versions[0].find('./Key').text, 'rose')
        self.assertEqual(versions[0].find('./VersionId').text, '3')
        self.assertEqual(versions[0].find('./IsLatest').text, 'true')

        # with key-marker and version-id-marker
        req = Request.blank(
            '/junk?versions&key-marker=rose&version-id-marker=2',
            environ={'REQUEST_METHOD': 'GET'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'Date': self.get_date_header()})
        status, headers, body = self.call_swift3(req)

        self.assertEqual(status.split()[0], '200')
        elem = fromstring(body, 'ListVersionsResult')
        self.assertEqual(elem.find('./IsTruncated').text, 'false')
        delete_markers = elem.findall('./DeleteMarker')
        self.assertEqual(len(delete_markers), 0)
        versions = elem.findall('./Version')
        self.assertEqual(len(versions), len(self.objects) - 1)
        self.assertEqual(versions[0].find('./Key').text, 'rose')
        self.assertEqual(versions[0].find('./VersionId').text, '1')
        self.assertEqual(versions[0].find('./IsLatest').text, 'false')

        # with key-marker and non-existent version-id-marker
        req = Request.blank(
            '/junk?versions&key-marker=rose&version-id-marker=x',
            environ={'REQUEST_METHOD': 'GET'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'Date': self.get_date_header()})
        status, headers, body = self.call_swift3(req)

        self.assertEqual(status.split()[0], '200')
        elem = fromstring(body, 'ListVersionsResult')
        self.assertEqual(elem.find('./Name').text, 'junk')
        delete_markers = elem.findall('./DeleteMarker')
        self.assertEqual(len(delete_markers), 0)
        versions = elem.findall('./Version')
        self.assertEqual(len(versions), len(self.objects) - 2)
        self.assertEqual(versions[0].find('./Key').text, 'viola')
        self.assertEqual(versions[0].find('./IsLatest').text, 'true')
        self.assertEqual(versions[0].find('./VersionId').text, 'null')

    @s3acl
    def test_bucket_PUT_error(self):
        code = self._test_method_error('PUT', '/bucket', swob.HTTPCreated,
                                       headers={'Content-Length': 'a'})
        self.assertEqual(code, 'InvalidArgument')
        code = self._test_method_error('PUT', '/bucket', swob.HTTPCreated,
                                       headers={'Content-Length': '-1'})
        self.assertEqual(code, 'InvalidArgument')
        code = self._test_method_error('PUT', '/bucket', swob.HTTPUnauthorized)
        self.assertEqual(code, 'SignatureDoesNotMatch')
        code = self._test_method_error('PUT', '/bucket', swob.HTTPForbidden)
        self.assertEqual(code, 'AccessDenied')
        code = self._test_method_error('PUT', '/bucket', swob.HTTPAccepted)
        self.assertEqual(code, 'BucketAlreadyExists')
        code = self._test_method_error('PUT', '/bucket', swob.HTTPServerError)
        self.assertEqual(code, 'InternalError')
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
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_swift3(req)
        self.assertEqual(status.split()[0], '200')
        self.assertEqual(headers['Location'], '/bucket')

        # Apparently some clients will include a chunked transfer-encoding
        # even with no body
        req = Request.blank('/bucket',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'Transfer-Encoding': 'chunked'})
        status, headers, body = self.call_swift3(req)
        self.assertEqual(status.split()[0], '200')
        self.assertEqual(headers['Location'], '/bucket')

    def _test_bucket_PUT_with_location(self, root_element):
        elem = Element(root_element)
        SubElement(elem, 'LocationConstraint').text = 'US'
        xml = tostring(elem)

        req = Request.blank('/bucket',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()},
                            body=xml)
        status, headers, body = self.call_swift3(req)
        self.assertEqual(status.split()[0], '200')

    @s3acl
    def test_bucket_PUT_with_location(self):
        self._test_bucket_PUT_with_location('CreateBucketConfiguration')

    @s3acl
    def test_bucket_PUT_with_ami_location(self):
        # ec2-ami-tools apparently uses CreateBucketConstraint instead?
        self._test_bucket_PUT_with_location('CreateBucketConstraint')

    @s3acl
    def test_bucket_PUT_with_strange_location(self):
        # Even crazier: it doesn't seem to matter
        self._test_bucket_PUT_with_location('foo')

    def test_bucket_PUT_with_canned_acl(self):
        req = Request.blank('/bucket',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'X-Amz-Acl': 'public-read'})
        status, headers, body = self.call_swift3(req)
        self.assertEqual(status.split()[0], '200')
        _, _, headers = self.swift.calls_with_headers[-1]
        self.assertTrue('X-Container-Read' in headers)
        self.assertEqual(headers.get('X-Container-Read'), '.r:*,.rlistings')
        self.assertTrue('X-Container-Sysmeta-Swift3-Acl' not in headers)

    @s3acl(s3acl_only=True)
    def test_bucket_PUT_with_canned_s3acl(self):
        account = 'test:tester'
        acl = \
            encode_acl('container', ACLPublicRead(Owner(account, account)))
        req = Request.blank('/bucket',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'X-Amz-Acl': 'public-read'})
        status, headers, body = self.call_swift3(req)
        self.assertEqual(status.split()[0], '200')
        _, _, headers = self.swift.calls_with_headers[-1]
        self.assertTrue('X-Container-Read' not in headers)
        self.assertTrue('X-Container-Sysmeta-Swift3-Acl' in headers)
        self.assertEqual(headers.get('X-Container-Sysmeta-Swift3-Acl'),
                         acl['x-container-sysmeta-swift3-acl'])

    @s3acl
    def test_bucket_PUT_with_location_error(self):
        elem = Element('CreateBucketConfiguration')
        SubElement(elem, 'LocationConstraint').text = 'XXX'
        xml = tostring(elem)

        req = Request.blank('/bucket',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()},
                            body=xml)
        status, headers, body = self.call_swift3(req)
        self.assertEqual(self._get_error_code(body),
                         'InvalidLocationConstraint')

    @s3acl
    def test_bucket_PUT_with_location_invalid_xml(self):
        req = Request.blank('/bucket',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()},
                            body='invalid_xml')
        status, headers, body = self.call_swift3(req)
        self.assertEqual(self._get_error_code(body), 'MalformedXML')

    def _test_method_error_delete(self, path, sw_resp):
        self.swift.register('HEAD', '/v1/AUTH_test' + path, sw_resp, {}, None)
        return self._test_method_error('DELETE', path, sw_resp)

    @s3acl
    def test_bucket_DELETE_error(self):
        code = self._test_method_error_delete('/bucket', swob.HTTPUnauthorized)
        self.assertEqual(code, 'SignatureDoesNotMatch')
        code = self._test_method_error_delete('/bucket', swob.HTTPForbidden)
        self.assertEqual(code, 'AccessDenied')
        code = self._test_method_error_delete('/bucket', swob.HTTPNotFound)
        self.assertEqual(code, 'NoSuchBucket')
        code = self._test_method_error_delete('/bucket', swob.HTTPServerError)
        self.assertEqual(code, 'InternalError')

        # bucket not empty is now validated at swift3
        self.swift.register('HEAD', '/v1/AUTH_test/bucket', swob.HTTPNoContent,
                            {'X-Container-Object-Count': '1'}, None)
        code = self._test_method_error('DELETE', '/bucket', swob.HTTPConflict)
        self.assertEqual(code, 'BucketNotEmpty')

    @s3acl
    def test_bucket_DELETE(self):
        # overwrite default HEAD to return x-container-object-count
        self.swift.register(
            'HEAD', '/v1/AUTH_test/bucket', swob.HTTPNoContent,
            {'X-Container-Object-Count': 0}, None)

        req = Request.blank('/bucket',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_swift3(req)
        self.assertEqual(status.split()[0], '204')

    @s3acl
    def test_bucket_DELETE_error_while_segment_bucket_delete(self):
        # An error occurred while deleting segment objects
        self.swift.register('DELETE', '/v1/AUTH_test/bucket+segments/lily',
                            swob.HTTPServiceUnavailable, {}, json.dumps([]))
        # overwrite default HEAD to return x-container-object-count
        self.swift.register(
            'HEAD', '/v1/AUTH_test/bucket', swob.HTTPNoContent,
            {'X-Container-Object-Count': 0}, None)

        req = Request.blank('/bucket',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_swift3(req)
        self.assertEqual(status.split()[0], '503')
        called = [(method, path) for method, path, _ in
                  self.swift.calls_with_headers]
        # Don't delete original bucket when error occurred in segment container
        self.assertNotIn(('DELETE', '/v1/AUTH_test/bucket'), called)

    def _test_bucket_for_s3acl(self, method, account):
        req = Request.blank('/bucket',
                            environ={'REQUEST_METHOD': method},
                            headers={'Authorization': 'AWS %s:hmac' % account,
                                     'Date': self.get_date_header()})

        return self.call_swift3(req)

    @s3acl(s3acl_only=True)
    def test_bucket_GET_without_permission(self):
        status, headers, body = self._test_bucket_for_s3acl('GET',
                                                            'test:other')
        self.assertEqual(self._get_error_code(body), 'AccessDenied')

    @s3acl(s3acl_only=True)
    def test_bucket_GET_with_read_permission(self):
        status, headers, body = self._test_bucket_for_s3acl('GET',
                                                            'test:read')
        self.assertEqual(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_bucket_GET_with_fullcontrol_permission(self):
        status, headers, body = \
            self._test_bucket_for_s3acl('GET', 'test:full_control')
        self.assertEqual(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_bucket_GET_with_owner_permission(self):
        status, headers, body = self._test_bucket_for_s3acl('GET',
                                                            'test:tester')
        self.assertEqual(status.split()[0], '200')

    def _test_bucket_GET_canned_acl(self, bucket):
        req = Request.blank('/%s' % bucket,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})

        return self.call_swift3(req)

    @s3acl(s3acl_only=True)
    def test_bucket_GET_authenticated_users(self):
        status, headers, body = \
            self._test_bucket_GET_canned_acl('authenticated')
        self.assertEqual(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_bucket_GET_all_users(self):
        status, headers, body = self._test_bucket_GET_canned_acl('public')
        self.assertEqual(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_bucket_DELETE_without_permission(self):
        status, headers, body = self._test_bucket_for_s3acl('DELETE',
                                                            'test:other')
        self.assertEqual(self._get_error_code(body), 'AccessDenied')
        # Don't delete anything in backend Swift
        called = [method for method, _, _ in self.swift.calls_with_headers]
        self.assertNotIn('DELETE', called)

    @s3acl(s3acl_only=True)
    def test_bucket_DELETE_with_write_permission(self):
        status, headers, body = self._test_bucket_for_s3acl('DELETE',
                                                            'test:write')
        self.assertEqual(self._get_error_code(body), 'AccessDenied')
        # Don't delete anything in backend Swift
        called = [method for method, _, _ in self.swift.calls_with_headers]
        self.assertNotIn('DELETE', called)

    @s3acl(s3acl_only=True)
    def test_bucket_DELETE_with_fullcontrol_permission(self):
        status, headers, body = \
            self._test_bucket_for_s3acl('DELETE', 'test:full_control')
        self.assertEqual(self._get_error_code(body), 'AccessDenied')
        # Don't delete anything in backend Swift
        called = [method for method, _, _ in self.swift.calls_with_headers]
        self.assertNotIn('DELETE', called)


if __name__ == '__main__':
    unittest.main()
