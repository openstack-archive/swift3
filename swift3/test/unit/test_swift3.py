# Copyright (c) 2011-2014 OpenStack Foundation.
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
from datetime import datetime
import cgi
import hashlib
import base64
from urllib import unquote, quote

import simplejson

from swift.common import swob
from swift.common.swob import Request

from swift3 import middleware as swift3
from swift3.test.unit.helpers import FakeSwift
from swift3.etree import fromstring, tostring, Element, SubElement
from swift3.request import Request as S3Request

XMLNS_XSI = 'http://www.w3.org/2001/XMLSchema-instance'


class FakeApp(object):
    def __init__(self):
        self.swift = FakeSwift()

    def _update_s3_path_info(self, env):
        """
        For S3 requests, Swift auth middleware replaces a user name in
        env['PATH_INFO'] with a valid tenant id.
        E.g. '/v1/test:tester/bucket/object' will become
        '/v1/AUTH_test/bucket/object'.  This method emulates the behavior.
        """
        _, authorization = env['HTTP_AUTHORIZATION'].split(' ')
        tenant_user, sign = authorization.rsplit(':', 1)
        tenant, user = tenant_user.rsplit(':', 1)

        path = env['PATH_INFO']
        env['PATH_INFO'] = path.replace(tenant_user, 'AUTH_' + tenant)

    def __call__(self, env, start_response):
        if 'HTTP_AUTHORIZATION' in env:
            self._update_s3_path_info(env)

        return self.swift(env, start_response)


class TestSwift3(unittest.TestCase):
    def setup_buckets(self):
        self.buckets = (('apple', 1, 200), ('orange', 3, 430))

        json_pattern = ['"name":%s', '"count":%s', '"bytes":%s']
        json_pattern = '{' + ','.join(json_pattern) + '}'
        json_out = []
        for b in self.buckets:
            name = simplejson.dumps(b[0])
            json_out.append(json_pattern %
                            (name, b[1], b[2]))
        bucket_list = '[' + ','.join(json_out) + ']'

        self.swift.register('GET', '/v1/AUTH_test', swob.HTTPOk, {},
                            bucket_list)

    def setup_objects(self):
        self.objects = (('rose', '2011-01-05T02:19:14.275290', 0, 303),
                        ('viola', '2011-01-05T02:19:14.275290', 0, 3909),
                        ('lily', '2011-01-05T02:19:14.275290', 0, 3909),
                        ('with space', '2011-01-05T02:19:14.275290', 0, 390),
                        ('with%20space', '2011-01-05T02:19:14.275290', 0, 390))

        json_pattern = ['"name":"%s"', '"last_modified":"%s"', '"hash":"%s"',
                        '"bytes":%s']
        json_pattern = '{' + ','.join(json_pattern) + '}'
        json_out = []
        for b in self.objects:
            json_out.append(json_pattern % b)
        object_list = '[' + ','.join(json_out) + ']'
        self.swift.register('HEAD', '/v1/AUTH_test/junk', swob.HTTPNoContent,
                            {}, object_list)
        self.swift.register('GET', '/v1/AUTH_test/junk', swob.HTTPOk, {},
                            object_list)

    def setUp(self):
        self.app = FakeApp()
        self.swift = self.app.swift
        self.swift3 = swift3.filter_factory({})(self.app)

        self.swift.register('GET', '/something', swob.HTTPOk, {}, 'FAKE APP')

        self.setup_buckets()
        self.setup_objects()

        self.object_body = 'hello'
        self.response_headers = {'Content-Type': 'text/html',
                                 'Content-Length': len(self.object_body),
                                 'x-object-meta-test': 'swift',
                                 'etag': '1b2cf535f27731c974343645a3985328',
                                 'last-modified': '2011-01-05T02:19:14.275290'}

        self.swift.register('PUT', '/v1/AUTH_test/bucket',
                            swob.HTTPCreated, {}, None)
        self.swift.register('POST', '/v1/AUTH_test/bucket',
                            swob.HTTPNoContent, {}, None)
        self.swift.register('DELETE', '/v1/AUTH_test/bucket',
                            swob.HTTPNoContent, {}, None)

        self.swift.register('GET', '/v1/AUTH_test/bucket/object',
                            swob.HTTPOk, self.response_headers,
                            self.object_body)
        self.swift.register('PUT', '/v1/AUTH_test/bucket/object',
                            swob.HTTPCreated, {}, None)
        self.swift.register('DELETE', '/v1/AUTH_test/bucket/object',
                            swob.HTTPNoContent, {}, None)

    def _get_error_code(self, body):
        elem = fromstring(body)
        self.assertEquals(elem.tag, 'Error')
        return elem.find('./Code').text

    def call_app(self, req, app=None, expect_exception=False):
        if app is None:
            app = self.app

        req.headers.setdefault("User-Agent", "Mozzarella Foxfire")

        status = [None]
        headers = [None]

        def start_response(s, h, ei=None):
            status[0] = s
            headers[0] = swob.HeaderKeyDict(h)

        body_iter = app(req.environ, start_response)
        body = ''
        caught_exc = None
        try:
            for chunk in body_iter:
                body += chunk
        except Exception as exc:
            if expect_exception:
                caught_exc = exc
            else:
                raise

        if expect_exception:
            return status[0], headers[0], body, caught_exc
        else:
            return status[0], headers[0], body

    def call_swift3(self, req, **kwargs):
        return self.call_app(req, app=self.swift3, **kwargs)

    def test_non_s3_request_passthrough(self):
        req = Request.blank('/something')
        status, headers, body = self.call_swift3(req)
        self.assertEquals(body, 'FAKE APP')

    def test_bad_format_authorization(self):
        req = Request.blank('/something',
                            headers={'Authorization': 'hoge'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_bad_method(self):
        req = Request.blank('/',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'MethodNotAllowed')

    def test_path_info_encode(self):
        bucket_name = 'b%75cket'
        object_name = 'ob%6aect:1'
        self.swift.register('GET', '/v1/AUTH_test/bucket/object:1',
                            swob.HTTPOk, {}, None)
        req = Request.blank('/%s/%s' % (bucket_name, object_name),
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        raw_path_info = "/%s/%s" % (bucket_name, object_name)
        path_info = req.environ['PATH_INFO']
        self.assertEquals(path_info, unquote(raw_path_info))
        self.assertEquals(req.path, quote(path_info))

    def _test_method_error(self, method, path, response_class, headers={}):
        self.swift.register(method, '/v1/AUTH_test' + path, response_class,
                            headers, None)
        headers.update({'Authorization': 'AWS test:tester:hmac'})
        req = Request.blank(path, environ={'REQUEST_METHOD': method},
                            headers=headers)
        status, headers, body = self.call_swift3(req)
        return self._get_error_code(body)

    def test_service_GET_error(self):
        code = self._test_method_error('GET', '', swob.HTTPUnauthorized)
        self.assertEquals(code, 'SignatureDoesNotMatch')
        code = self._test_method_error('GET', '', swob.HTTPForbidden)
        self.assertEquals(code, 'AccessDenied')
        code = self._test_method_error('GET', '', swob.HTTPServerError)
        self.assertEquals(code, 'InternalError')

    def test_service_GET(self):
        req = Request.blank('/',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

        elem = fromstring(body)
        self.assertEquals(elem.tag, 'ListAllMyBucketsResult')

        all_buckets = elem.find('./Buckets')
        buckets = all_buckets.iterchildren('Bucket')
        listing = list(list(buckets)[0])
        self.assertEquals(len(listing), 2)

        names = []
        for b in all_buckets.iterchildren('Bucket'):
            names.append(b.find('./Name').text)

        self.assertEquals(len(names), len(self.buckets))
        for i in self.buckets:
            self.assertTrue(i[0] in names)

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

        elem = fromstring(body)
        self.assertEquals(elem.tag, 'ListBucketResult')
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

    def test_bucket_GET_is_truncated(self):
        bucket_name = 'junk'

        req = Request.blank('/%s' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET',
                                     'QUERY_STRING': 'max-keys=5'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        elem = fromstring(body)
        self.assertEquals(elem.find('./IsTruncated').text, 'false')

        req = Request.blank('/%s' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET',
                                     'QUERY_STRING': 'max-keys=4'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        elem = fromstring(body)
        self.assertEquals(elem.find('./IsTruncated').text, 'true')

    def test_bucket_GET_max_keys(self):
        bucket_name = 'junk'

        req = Request.blank('/%s' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET',
                                     'QUERY_STRING': 'max-keys=5'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        elem = fromstring(body)
        self.assertEquals(elem.find('./MaxKeys').text, '5')
        _, path = self.swift.calls[-1]
        _, query_string = path.split('?')
        args = dict(cgi.parse_qsl(query_string))
        self.assert_(args['limit'] == '6')

        req = Request.blank('/%s' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET',
                                     'QUERY_STRING': 'max-keys=5000'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        elem = fromstring(body)
        self.assertEquals(elem.find('./MaxKeys').text, '1000')
        _, path = self.swift.calls[-1]
        _, query_string = path.split('?')
        args = dict(cgi.parse_qsl(query_string))
        self.assertEquals(args['limit'], '1001')

    def test_bucket_GET_passthroughs(self):
        bucket_name = 'junk'
        req = Request.blank('/%s' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET', 'QUERY_STRING':
                                     'delimiter=a&marker=b&prefix=c'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        elem = fromstring(body)
        self.assertEquals(elem.find('./Prefix').text, 'c')
        self.assertEquals(elem.find('./Marker').text, 'b')
        self.assertEquals(elem.find('./Delimiter').text, 'a')
        _, path = self.swift.calls[-1]
        _, query_string = path.split('?')
        args = dict(cgi.parse_qsl(query_string))
        self.assertEquals(args['delimiter'], 'a')
        self.assertEquals(args['marker'], 'b')
        self.assertEquals(args['prefix'], 'c')

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

    def test_bucket_PUT(self):
        req = Request.blank('/bucket',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

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

    def test_bucket_DELETE(self):
        req = Request.blank('/bucket',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '204')

    def _check_acl(self, owner, body):
        elem = fromstring(body)
        self.assertEquals(elem.tag, 'AccessControlPolicy')
        permission = elem.find('./AccessControlList/Grant/Permission').text
        self.assertEquals(permission, 'FULL_CONTROL')
        name = elem.find('./AccessControlList/Grant/Grantee/ID').text
        self.assertEquals(name, owner)

    def test_bucket_acl_GET(self):
        bucket_name = 'junk'
        req = Request.blank('/%s?acl' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self._check_acl('test:tester', body)

    def test_bucket_acl_PUT(self):
        elem = Element('AccessControlPolicy')
        owner = SubElement(elem, 'Owner')
        SubElement(owner, 'ID').text = 'id'
        acl = SubElement(elem, 'AccessControlList')
        grant = SubElement(acl, 'Grant')
        grantee = SubElement(grant, 'Grantee', nsmap={'xsi': XMLNS_XSI})
        grantee.set('{%s}type' % XMLNS_XSI, 'Group')
        SubElement(grantee, 'URI').text = \
            'http://acs.amazonaws.com/groups/global/AllUsers'
        SubElement(grant, 'Permission').text = 'READ'

        xml = tostring(elem)
        req = Request.blank('/bucket?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=xml)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_bucket_versioning_GET(self):
        bucket_name = 'junk'
        req = Request.blank('/%s?versioning' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        elem = fromstring(body)
        self.assertEquals(elem.tag, 'VersioningConfiguration')

    def _test_object_GETorHEAD(self, method):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': method},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

        for key, val in self.response_headers.iteritems():
            if key in ('content-length', 'content-type', 'content-encoding',
                       'etag', 'last-modified'):
                self.assertTrue(key in headers)
                self.assertEquals(headers[key], val)

            elif key.startswith('x-object-meta-'):
                self.assertTrue('x-amz-meta-' + key[14:] in headers)
                self.assertEquals(headers['x-amz-meta-' + key[14:]], val)

        if method == 'GET':
            self.assertEquals(body, self.object_body)

    def test_object_HEAD(self):
        self._test_object_GETorHEAD('HEAD')

    def test_object_GET_error(self):
        code = self._test_method_error('GET', '/bucket/object',
                                       swob.HTTPUnauthorized)
        self.assertEquals(code, 'SignatureDoesNotMatch')
        code = self._test_method_error('GET', '/bucket/object',
                                       swob.HTTPForbidden)
        self.assertEquals(code, 'AccessDenied')
        code = self._test_method_error('GET', '/bucket/object',
                                       swob.HTTPNotFound)
        self.assertEquals(code, 'NoSuchKey')
        code = self._test_method_error('GET', '/bucket/object',
                                       swob.HTTPServerError)
        self.assertEquals(code, 'InternalError')

    def test_object_GET(self):
        self._test_object_GETorHEAD('GET')

    def test_object_GET_Range(self):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Range': 'bytes=0-3'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '206')

        self.assertTrue('content-range' in headers)
        self.assertTrue(headers['content-range'].startswith('bytes 0-3'))

    def test_object_PUT_error(self):
        code = self._test_method_error('PUT', '/bucket/object',
                                       swob.HTTPUnauthorized)
        self.assertEquals(code, 'SignatureDoesNotMatch')
        code = self._test_method_error('PUT', '/bucket/object',
                                       swob.HTTPForbidden)
        self.assertEquals(code, 'AccessDenied')
        code = self._test_method_error('PUT', '/bucket/object',
                                       swob.HTTPNotFound)
        self.assertEquals(code, 'NoSuchBucket')
        code = self._test_method_error('PUT', '/bucket/object',
                                       swob.HTTPRequestEntityTooLarge)
        self.assertEquals(code, 'EntityTooLarge')
        code = self._test_method_error('PUT', '/bucket/object',
                                       swob.HTTPServerError)
        self.assertEquals(code, 'InternalError')

    def test_object_PUT(self):
        req = Request.blank(
            '/bucket/object',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'x-amz-storage-class': 'REDUCED_REDUNDANCY',
                     'Content-MD5': 'Gyz1NfJ3Mcl0NDZFo5hTKA=='})
        req.date = datetime.now()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

        _, _, headers = self.swift.calls_with_headers[-1]
        self.assertEquals(headers['etag'], self.response_headers['etag'])

    def test_object_PUT_headers(self):
        req = Request.blank(
            '/bucket/object',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'X-Amz-Storage-Class': 'REDUCED_REDUNDANCY',
                     'X-Amz-Meta-Something': 'oh hai',
                     'X-Amz-Copy-Source': '/some/source',
                     'Content-MD5': 'ffoHqOWd280dyE1MT4KuoQ=='})
        req.date = datetime.now()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        _, _, headers = self.swift.calls_with_headers[-1]
        self.assertEquals(headers['ETag'],
                          '7dfa07a8e59ddbcd1dc84d4c4f82aea1')
        self.assertEquals(headers['X-Object-Meta-Something'], 'oh hai')
        self.assertEquals(headers['X-Copy-From'], '/some/source')

    def test_object_DELETE_error(self):
        code = self._test_method_error('DELETE', '/bucket/object',
                                       swob.HTTPUnauthorized)
        self.assertEquals(code, 'SignatureDoesNotMatch')
        code = self._test_method_error('DELETE', '/bucket/object',
                                       swob.HTTPForbidden)
        self.assertEquals(code, 'AccessDenied')
        code = self._test_method_error('DELETE', '/bucket/object',
                                       swob.HTTPNotFound)
        self.assertEquals(code, 'NoSuchKey')
        code = self._test_method_error('DELETE', '/bucket/object',
                                       swob.HTTPServerError)
        self.assertEquals(code, 'InternalError')

    def test_object_DELETE(self):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '204')

    def test_object_multi_DELETE(self):
        self.swift.register('DELETE', '/v1/AUTH_test/bucket/Key1',
                            swob.HTTPNoContent, {}, None)
        self.swift.register('DELETE', '/v1/AUTH_test/bucket/Key2',
                            swob.HTTPNotFound, {}, None)

        elem = Element('Delete')
        for key in ['Key1', 'Key2']:
            obj = SubElement(elem, 'Object')
            SubElement(obj, 'Key').text = key
        body = tostring(elem, use_s3ns=False)

        req = Request.blank('/bucket?delete',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=body)
        req.date = datetime.now()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_object_acl_GET(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self._check_acl('test:tester', body)

    def test_canonical_string(self):
        """
        The hashes here were generated by running the same requests against
        boto.utils.canonical_string
        """
        def canonical_string(path, headers):
            if '?' in path:
                path, query_string = path.split('?', 1)
            else:
                query_string = ''

            req = S3Request({
                'REQUEST_METHOD': 'GET',
                'PATH_INFO': path,
                'QUERY_STRING': query_string,
                'HTTP_AUTHORIZATION': 'AWS X:Y:Z',
            })
            req.headers.update(headers)
            return req._canonical_string()

        def verify(hash, path, headers):
            s = canonical_string(path, headers)
            self.assertEquals(hash, hashlib.md5(s).hexdigest())

        verify('6dd08c75e42190a1ce9468d1fd2eb787', '/bucket/object',
               {'Content-Type': 'text/plain', 'X-Amz-Something': 'test',
                'Date': 'whatever'})

        verify('c8447135da232ae7517328f3429df481', '/bucket/object',
               {'Content-Type': 'text/plain', 'X-Amz-Something': 'test'})

        verify('bf49304103a4de5c325dce6384f2a4a2', '/bucket/object',
               {'content-type': 'text/plain'})

        verify('be01bd15d8d47f9fe5e2d9248cc6f180', '/bucket/object', {})

        verify('e9ec7dca45eef3e2c7276af23135e896', '/bucket/object',
               {'Content-MD5': 'somestuff'})

        verify('a822deb31213ad09af37b5a7fe59e55e', '/bucket/object?acl', {})

        verify('cce5dd1016595cb706c93f28d3eaa18f', '/bucket/object',
               {'Content-Type': 'text/plain', 'X-Amz-A': 'test',
                'X-Amz-Z': 'whatever', 'X-Amz-B': 'lalala',
                'X-Amz-Y': 'lalalalalalala'})

        verify('7506d97002c7d2de922cc0ec34af8846', '/bucket/object',
               {'Content-Type': None, 'X-Amz-Something': 'test'})

        verify('28f76d6162444a193b612cd6cb20e0be', '/bucket/object',
               {'Content-Type': None,
                'X-Amz-Date': 'Mon, 11 Jul 2011 10:52:57 +0000',
                'Date': 'Tue, 12 Jul 2011 10:52:57 +0000'})

        verify('ed6971e3eca5af4ee361f05d7c272e49', '/bucket/object',
               {'Content-Type': None,
                'Date': 'Tue, 12 Jul 2011 10:52:57 +0000'})

        str1 = canonical_string('/', headers=
                                {'Content-Type': None,
                                 'X-Amz-Something': 'test'})
        str2 = canonical_string('/', headers=
                                {'Content-Type': '',
                                 'X-Amz-Something': 'test'})
        str3 = canonical_string('/', headers={'X-Amz-Something': 'test'})

        self.assertEquals(str1, str2)
        self.assertEquals(str2, str3)

    def test_signed_urls_expired(self):
        expire = '1000000000'
        req = Request.blank('/bucket/object?Signature=X&Expires=%s&'
                            'AWSAccessKeyId=test:tester' % expire,
                            environ={'REQUEST_METHOD': 'GET'})
        req.headers['Date'] = datetime.utcnow()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_signed_urls(self):
        expire = '10000000000'
        req = Request.blank('/bucket/object?Signature=X&Expires=%s&'
                            'AWSAccessKeyId=test:tester' % expire,
                            environ={'REQUEST_METHOD': 'GET'})
        req.headers['Date'] = datetime.utcnow()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')
        for _, _, headers in self.swift.calls_with_headers:
            self.assertEquals(headers['Authorization'], 'AWS test:tester:X')
            self.assertEquals(headers['Date'], expire)

    def test_signed_urls_invalid_expire(self):
        expire = 'invalid'
        req = Request.blank('/bucket/object?Signature=X&Expires=%s&'
                            'AWSAccessKeyId=test:tester' % expire,
                            environ={'REQUEST_METHOD': 'GET'})
        req.headers['Date'] = datetime.utcnow()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_signed_urls_no_sign(self):
        expire = 'invalid'
        req = Request.blank('/bucket/object?Expires=%s&'
                            'AWSAccessKeyId=test:tester' % expire,
                            environ={'REQUEST_METHOD': 'GET'})
        req.headers['Date'] = datetime.utcnow()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_token_generation(self):
        req = Request.blank('/bucket/object?uploadId=123456789abcdef'
                            '&partNumber=1',
                            environ={'REQUEST_METHOD': 'PUT'})
        req.headers['Authorization'] = 'AWS test:tester:hmac'
        status, headers, body = self.call_swift3(req)
        _, _, headers = self.swift.calls_with_headers[-1]
        self.assertEquals(base64.urlsafe_b64decode(
            headers['X-Auth-Token']),
            'PUT\n\n\n/bucket/object?partNumber=1&uploadId=123456789abcdef')

    def test_xml_namespace(self):
        def test_xml(ns, prefix):
            return \
                '<AccessControlPolicy %(ns)s>' \
                '<Owner><ID>id</ID></Owner>' \
                '<AccessControlList>' \
                '<Grant>' \
                '<Grantee ' \
                ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"' \
                ' xsi:type="Group">' \
                '<URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>' \
                '</Grantee>' \
                '<%(prefix)sPermission>READ</%(prefix)sPermission>' \
                '</Grant>' \
                '</AccessControlList>' \
                '</AccessControlPolicy>' % ({'ns': ns, 'prefix': prefix})

        xml = test_xml('', '')
        req = Request.blank('/bucket?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=xml)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

        xml = test_xml('xmlns="http://example.com/"', '')
        req = Request.blank('/bucket?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=xml)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

        xml = test_xml('xmlns:s3="http://s3.amazonaws.com/doc/2006-03-01/"',
                       's3:')
        req = Request.blank('/bucket?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=xml)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

        xml = test_xml('xmlns:s3="http://example.com/"', 's3:')
        req = Request.blank('/bucket?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=xml)
        # FIXME: swift3 should handle invalid xml file
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InternalError')

if __name__ == '__main__':
    unittest.main()
