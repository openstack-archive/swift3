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
from mock import patch
from contextlib import nested
from datetime import datetime
import hashlib
import base64
from urllib import unquote, quote
from md5 import md5

from swift.common import swob, utils
from swift.common.swob import Request

from swift3.test.unit import Swift3TestCase
from swift3.request import Request as S3Request
from swift3.etree import fromstring
from swift3.middleware import filter_factory
from swift3.cfg import CONF


class TestSwift3Middleware(Swift3TestCase):
    def setUp(self):
        super(TestSwift3Middleware, self).setUp()

        self.swift.register('GET', '/something', swob.HTTPOk, {}, 'FAKE APP')

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

    def test_canonical_string_v2(self):
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
            return req._string_to_sign(False)

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

        verify('41ecd87e7329c33fea27826c1c9a6f91', '/bucket/object?cors', {})

        verify('d91b062f375d8fab407d6dab41fd154e', '/bucket/object?tagging',
               {})

        verify('ebab878a96814b30eb178e27efb3973f', '/bucket/object?restore',
               {})

        verify('f6bf1b2d92b054350d3679d28739fc69', '/bucket/object?'
               'response-cache-control&response-content-disposition&'
               'response-content-encoding&response-content-language&'
               'response-content-type&response-expires', {})

        str1 = canonical_string('/', headers={'Content-Type': None,
                                              'X-Amz-Something': 'test'})
        str2 = canonical_string('/', headers={'Content-Type': '',
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

    def test_signed_urls_no_access(self):
        expire = 'invalid'
        req = Request.blank('/bucket/object?Expires=%s&'
                            'AWSAccessKeyId=' % expire,
                            environ={'REQUEST_METHOD': 'GET'})
        req.headers['Date'] = datetime.utcnow()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_signed_urls_v4(self):
        req = Request.blank('/bucket/object'
                            '?X-Amz-Algorithm=AWS4-HMAC-SHA256'
                            '&X-Amz-Credential=test/20T20Z/US/s3/aws4_request'
                            '&X-Amz-Date=20130721T201207Z'
                            '&X-Amz-SignedHeaders=host'
                            '&X-Amz-Signature=X',
                            environ={'REQUEST_METHOD': 'GET'})
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')
        for _, _, headers in self.swift.calls_with_headers:
            self.assertEquals('AWS test:X', headers['Authorization'])
            self.assertIn('X-Auth-Token', headers)

    def test_signed_urls_v4_invalid_date(self):
        req = Request.blank('/bucket/object'
                            '?X-Amz-Algorithm=AWS4-HMAC-SHA256'
                            '&X-Amz-Credential=test/20T20Z/US/s3/aws4_request'
                            '&X-Amz-SignedHeaders=host'
                            '&X-Amz-Signature=X',
                            environ={'REQUEST_METHOD': 'GET'})
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    def test_signed_urls_v4_invalid_algorithm(self):
        req = Request.blank('/bucket/object'
                            '?X-Amz-Algorithm=FAKE'
                            '&X-Amz-Credential=test/20T20Z/US/s3/aws4_request'
                            '&X-Amz-Date=20130721T201207Z'
                            '&X-Amz-SignedHeaders=host'
                            '&X-Amz-Signature=X',
                            environ={'REQUEST_METHOD': 'GET'})
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    def test_signed_urls_v4_invalid_signed_headers(self):
        req = Request.blank('/bucket/object'
                            '?X-Amz-Algorithm=AWS4-HMAC-SHA256'
                            '&X-Amz-Credential=test/20T20Z/US/s3/aws4_request'
                            '&X-Amz-Date=20130721T201207Z'
                            '&X-Amz-Signature=X',
                            environ={'REQUEST_METHOD': 'GET'})
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    def test_signed_urls_v4_invalid_credentials(self):
        req = Request.blank('/bucket/object'
                            '?X-Amz-Algorithm=AWS4-HMAC-SHA256'
                            '&X-Amz-Credential=test'
                            '&X-Amz-Date=20130721T201207Z'
                            '&X-Amz-SignedHeaders=host'
                            '&X-Amz-Signature=X',
                            environ={'REQUEST_METHOD': 'GET'})
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_signed_urls_v4_invalid_signature(self):
        req = Request.blank('/bucket/object'
                            '?X-Amz-Algorithm=AWS4-HMAC-SHA256'
                            '&X-Amz-Credential=test/20T20Z/US/s3/aws4_request'
                            '&X-Amz-Date=20130721T201207Z'
                            '&X-Amz-SignedHeaders=host',
                            environ={'REQUEST_METHOD': 'GET'})
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def _test_signed_urls_v4_invalid_signed_headers(self):
        req = Request.blank('/bucket/object'
                            '?X-Amz-Algorithm=AWS4-HMAC-SHA256'
                            '&X-Amz-Credential=test/20T20Z/US/s3/aws4_request'
                            '&X-Amz-Date=20130721T201207Z'
                            '&X-Amz-SignedHeaders=host'
                            '&X-Amz-Signature=X',
                            environ={'REQUEST_METHOD': 'GET'})
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    def test_bucket_virtual_hosted_style(self):
        req = Request.blank('/',
                            environ={'HTTP_HOST': 'bucket.localhost:80',
                                     'REQUEST_METHOD': 'HEAD',
                                     'HTTP_AUTHORIZATION':
                                     'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_object_virtual_hosted_style(self):
        req = Request.blank('/object',
                            environ={'HTTP_HOST': 'bucket.localhost:80',
                                     'REQUEST_METHOD': 'HEAD',
                                     'HTTP_AUTHORIZATION':
                                     'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_token_generation(self):
        self.swift.register('HEAD', '/v1/AUTH_test/bucket+segments/'
                                    'object/123456789abcdef',
                            swob.HTTPOk, {}, None)
        self.swift.register('PUT', '/v1/AUTH_test/bucket+segments/'
                                   'object/123456789abcdef/1',
                            swob.HTTPCreated, {}, None)
        req = Request.blank('/bucket/object?uploadId=123456789abcdef'
                            '&partNumber=1',
                            environ={'REQUEST_METHOD': 'PUT'})
        req.headers['Authorization'] = 'AWS test:tester:hmac'
        status, headers, body = self.call_swift3(req)
        _, _, headers = self.swift.calls_with_headers[-1]
        self.assertEquals(base64.urlsafe_b64decode(
            headers['X-Auth-Token']),
            'PUT\n\n\n/bucket/object?partNumber=1&uploadId=123456789abcdef')

    def test_invalid_uri(self):
        req = Request.blank('/bucket/invalid\xffname',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidURI')

    def test_object_create_bad_md5_unreadable(self):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'PUT',
                                     'HTTP_AUTHORIZATION': 'AWS X:Y:Z',
                                     'HTTP_CONTENT_MD5': '#'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidDigest')

    def test_object_create_bad_md5_too_short(self):
        too_short_digest = md5('hey').hexdigest()[:-1]
        md5_str = too_short_digest.encode('base64').strip()
        req = Request.blank(
            '/bucket/object',
            environ={'REQUEST_METHOD': 'PUT',
                     'HTTP_AUTHORIZATION': 'AWS X:Y:Z',
                     'HTTP_CONTENT_MD5': md5_str})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidDigest')

    def test_object_create_bad_md5_too_long(self):
        too_long_digest = md5('hey').hexdigest() + 'suffix'
        md5_str = too_long_digest.encode('base64').strip()
        req = Request.blank(
            '/bucket/object',
            environ={'REQUEST_METHOD': 'PUT',
                     'HTTP_AUTHORIZATION': 'AWS X:Y:Z',
                     'HTTP_CONTENT_MD5': md5_str})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidDigest')

    def test_invalid_metadata_directive(self):
        req = Request.blank('/',
                            environ={'REQUEST_METHOD': 'GET',
                                     'HTTP_AUTHORIZATION': 'AWS X:Y:Z',
                                     'HTTP_X_AMZ_METADATA_DIRECTIVE':
                                     'invalid'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    def test_invalid_storage_class(self):
        req = Request.blank('/',
                            environ={'REQUEST_METHOD': 'GET',
                                     'HTTP_AUTHORIZATION': 'AWS X:Y:Z',
                                     'HTTP_X_AMZ_STORAGE_CLASS': 'INVALID'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidStorageClass')

    def _test_unsupported_header(self, header):
        req = Request.blank('/error',
                            environ={'REQUEST_METHOD': 'GET',
                                     'HTTP_AUTHORIZATION': 'AWS X:Y:Z'},
                            headers={'x-amz-' + header: 'value'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'NotImplemented')

    def test_mfa(self):
        self._test_unsupported_header('mfa')

    def test_server_side_encryption(self):
        self._test_unsupported_header('server-side-encryption')

    def test_website_redirect_location(self):
        self._test_unsupported_header('website-redirect-location')

    def _test_unsupported_resource(self, resource):
        req = Request.blank('/error?' + resource,
                            environ={'REQUEST_METHOD': 'GET',
                                     'HTTP_AUTHORIZATION': 'AWS X:Y:Z'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'NotImplemented')

    def test_notification(self):
        self._test_unsupported_resource('notification')

    def test_policy(self):
        self._test_unsupported_resource('policy')

    def test_request_payment(self):
        self._test_unsupported_resource('requestPayment')

    def test_torrent(self):
        self._test_unsupported_resource('torrent')

    def test_website(self):
        self._test_unsupported_resource('website')

    def test_cors(self):
        self._test_unsupported_resource('cors')

    def test_tagging(self):
        self._test_unsupported_resource('tagging')

    def test_restore(self):
        self._test_unsupported_resource('restore')

    def test_unsupported_method(self):
        req = Request.blank('/bucket?acl',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        elem = fromstring(body, 'Error')
        self.assertEquals(elem.find('./Code').text, 'MethodNotAllowed')
        self.assertEquals(elem.find('./Method').text, 'POST')
        self.assertEquals(elem.find('./ResourceType').text, 'ACL')

    def test_registered_defaults(self):
        filter_factory(CONF)
        swift_info = utils.get_swift_info()
        self.assertTrue('swift3' in swift_info)
        self.assertEqual(swift_info['swift3'].get('max_bucket_listing'),
                         CONF.max_bucket_listing)
        self.assertEqual(swift_info['swift3'].get('max_parts_listing'),
                         CONF.max_parts_listing)
        self.assertEqual(swift_info['swift3'].get('max_upload_part_num'),
                         CONF.max_upload_part_num)
        self.assertEqual(swift_info['swift3'].get('max_multi_delete_objects'),
                         CONF.max_multi_delete_objects)

    def test_check_pipeline(self):
        with nested(patch("swift3.middleware.CONF"),
                    patch("swift3.middleware.PipelineWrapper"),
                    patch("swift3.middleware.loadcontext")) as \
                (conf, pipeline, _):
            conf.auth_pipeline_check = True
            conf.__file__ = ''

            pipeline.return_value = 'swift3 tempauth proxy-server'
            self.swift3.check_pipeline(conf)

            pipeline.return_value = 'swift3 s3token authtoken keystoneauth ' \
                'proxy-server'
            self.swift3.check_pipeline(conf)

            pipeline.return_value = 'swift3 swauth proxy-server'
            self.swift3.check_pipeline(conf)

            pipeline.return_value = 'swift3 authtoken s3token keystoneauth ' \
                'proxy-server'
            with self.assertRaises(ValueError):
                self.swift3.check_pipeline(conf)

            pipeline.return_value = 'swift3 proxy-server'
            with self.assertRaises(ValueError):
                self.swift3.check_pipeline(conf)

            pipeline.return_value = 'proxy-server'
            with self.assertRaises(ValueError):
                self.swift3.check_pipeline(conf)

    def test_swift3_initialization_with_disabled_pipeline_check(self):
        with nested(patch("swift3.middleware.CONF"),
                    patch("swift3.middleware.PipelineWrapper"),
                    patch("swift3.middleware.loadcontext")) as \
                (conf, pipeline, _):
            # Disable pipeline check
            conf.auth_pipeline_check = False
            conf.__file__ = ''

            pipeline.return_value = 'swift3 tempauth proxy-server'
            self.swift3.check_pipeline(conf)

            pipeline.return_value = 'swift3 s3token authtoken keystoneauth ' \
                'proxy-server'
            self.swift3.check_pipeline(conf)

            pipeline.return_value = 'swift3 swauth proxy-server'
            self.swift3.check_pipeline(conf)

            pipeline.return_value = 'swift3 authtoken s3token keystoneauth ' \
                'proxy-server'
            self.swift3.check_pipeline(conf)

            pipeline.return_value = 'swift3 proxy-server'
            self.swift3.check_pipeline(conf)

            pipeline.return_value = 'proxy-server'
            with self.assertRaises(ValueError):
                self.swift3.check_pipeline(conf)

    def test_signature_v4(self):
        environ = {
            'REQUEST_METHOD': 'GET'}
        headers = {
            'Authorization': 'AWS4-HMAC-SHA256 '
                'Credential=test/20130524/US/s3/aws4_request, '
                'SignedHeaders=host;range;x-amz-date,'
                'Signature=X',
            'X-Amz-Date': '20T20ZS',
            'X-Amz-Content-SHA256': '0123456789'}
        req = Request.blank('/bucket/object', environ=environ, headers=headers)
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200', body)
        for _, _, headers in self.swift.calls_with_headers:
            self.assertEquals('AWS test:X', headers['Authorization'])
            self.assertIn('X-Auth-Token', headers)

    def test_signature_v4_no_date(self):
        environ = {
            'REQUEST_METHOD': 'GET'}
        headers = {
            'Authorization': 'AWS4-HMAC-SHA256 '
                'Credential=test/20130524/US/s3/aws4_request, '
                'SignedHeaders=host;range;x-amz-date,'
                'Signature=X',
            'X-Amz-Content-SHA256': '0123456789'}
        req = Request.blank('/bucket/object', environ=environ, headers=headers)
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '400')
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    def test_signature_v4_no_payload(self):
        environ = {
            'REQUEST_METHOD': 'GET'}
        headers = {
            'Authorization': 'AWS4-HMAC-SHA256 '
                'Credential=test/20130524/US/s3/aws4_request, '
                'SignedHeaders=host;range;x-amz-date,'
                'Signature=X',
            'X-Amz-Date': '20T20ZS'}
        req = Request.blank('/bucket/object', environ=environ, headers=headers)
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '400')
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    def test_signature_v4_bad_authorization_string(self):
        def test(auth_str, error):
            environ = {
                'REQUEST_METHOD': 'GET'}
            headers = {
                'Authorization': auth_str,
                'X-Amz-Date': '20T20ZS',
                'X-Amz-Content-SHA256': '0123456789'}
            req = Request.blank('/bucket/object', environ=environ,
                                headers=headers)
            req.content_type = 'text/plain'
            status, headers, body = self.call_swift3(req)
            self.assertEquals(self._get_error_code(body), error)

        auth_str = ('AWS4-HMAC-SHA256 '
                    'SignedHeaders=host;range;x-amz-date,'
                    'Signature=X')
        test(auth_str, 'AccessDenied')

        auth_str = ('AWS4-HMAC-SHA256 '
                    'Credential=test/20130524/US/s3/aws4_request, '
                    'Signature=X')
        test(auth_str, 'InvalidArgument')

        auth_str = ('AWS4-HMAC-SHA256 '
                    'Credential=test/20130524/US/s3/aws4_request, '
                    'SignedHeaders=host;range;x-amz-date')
        test(auth_str, 'AccessDenied')

    def test_canonical_string_v4(self):
        def canonical_string(path, environ, headers):
            if '?' in path:
                path, query_string = path.split('?', 1)
            else:
                query_string = ''

            env = {
                'REQUEST_METHOD': 'GET',
                'PATH_INFO': path,
                'QUERY_STRING': query_string,
                'HTTP_X_AMZ_DATE': '20T20Z',
                'HTTP_X_AMZ_CONTENT_SHA256': (
                    'e3b0c44298fc1c149afbf4c8996fb924'
                    '27ae41e4649b934ca495991b7852b855')
            }
            env.update(environ)
            req = S3Request(env)
            req.headers.update(headers)
            return req._string_to_sign(True)

        def verify(hash, path, environ, headers):
            s = canonical_string(path, environ, headers)
            s = s.split('\n')[3]
            self.assertEquals(hash, s)

        # all next data got from aws4_testsuite from Amazon
        # get-vanilla
        env = {
            'HTTP_AUTHORIZATION': ('AWS4-HMAC-SHA256 '
                'Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, '
                'SignedHeaders=date;host, Signature=X'),
            'HTTP_HOST': 'host.foo.com'}
        verify('366b91fb121d72a00f46bbe8d395f53a'
               '102b06dfb7e79636515208ed3fa606b1',
               '/', env,
               {'Date': 'Mon, 09 Sep 2011 23:36:00 GMT'})

        # get-relative-relative
        env = {
            'HTTP_AUTHORIZATION': ('AWS4-HMAC-SHA256 '
                'Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, '
                'SignedHeaders=date;host;p, Signature=X'),
            'HTTP_HOST': 'host.foo.com'}
        verify('366b91fb121d72a00f46bbe8d395f53a'
               '102b06dfb7e79636515208ed3fa606b1',
               '/foo/bar/../..', env,
               {'Date': 'Mon, 09 Sep 2011 23:36:00 GMT'})

        # get-header-value-trim
        env = {
            'REQUEST_METHOD': 'POST',
            'HTTP_AUTHORIZATION': ('AWS4-HMAC-SHA256 '
                'Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, '
                'SignedHeaders=date;host;p, Signature=X'),
            'HTTP_HOST': 'host.foo.com'}
        verify('dddd1902add08da1ac94782b05f9278c'
               '08dc7468db178a84f8950d93b30b1f35',
               '/', env,
               {'Date': 'Mon, 09 Sep 2011 23:36:00 GMT',
                'p': ' phfft '})

        # get-slash
        env = {
            'HTTP_AUTHORIZATION': ('AWS4-HMAC-SHA256 '
                'Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, '
                'SignedHeaders=date;host, Signature=X'),
            'HTTP_HOST': 'host.foo.com'}
        verify('366b91fb121d72a00f46bbe8d395f53a'
               '102b06dfb7e79636515208ed3fa606b1',
               '//', env,
               {'Date': 'Mon, 09 Sep 2011 23:36:00 GMT'})

        # get-slash-pointless-dot + get-space
        env = {
            'HTTP_AUTHORIZATION': ('AWS4-HMAC-SHA256 '
                'Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, '
                'SignedHeaders=date;host, Signature=X'),
            'HTTP_HOST': 'host.foo.com'}
        verify('22335f029d8778bf9b2a3133d8a212aa'
               '753e32acac174b7c1310a8437ec4cde6',
               '/./foo/%20/zoo', env,
               {'Date': 'Mon, 09 Sep 2011 23:36:00 GMT'})

        # get-slashes
        env = {
            'HTTP_AUTHORIZATION': ('AWS4-HMAC-SHA256 '
                'Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, '
                'SignedHeaders=date;host, Signature=X'),
            'HTTP_HOST': 'host.foo.com'}
        verify('6bb4476ee8745730c9cb79f33a0c70ba'
               'a6d8af29c0077fa12e4e8f1dd17e7098',
               '//foo//', env,
               {'Date': 'Mon, 09 Sep 2011 23:36:00 GMT'})

        # get-utf8 (not exact)
        env = {
            'HTTP_AUTHORIZATION': ('AWS4-HMAC-SHA256 '
                'Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, '
                'SignedHeaders=date;host, Signature=X'),
            'HTTP_HOST': 'host.foo.com'}
        verify('0ece72d809de065d4b71dfeb9d9cfc19'
               '447df7b517ea061454ebca280ee3a7eb',
               '/foo/%E1%88%B4', env,
               {'Date': 'Mon, 09 Sep 2011 23:36:00 GMT'})

        # get-vanilla-query-order-key
        env = {
            'HTTP_AUTHORIZATION': ('AWS4-HMAC-SHA256 '
                'Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, '
                'SignedHeaders=date;host, Signature=X'),
            'HTTP_HOST': 'host.foo.com'}
        verify('2f23d14fe13caebf6dfda346285c6d9c'
               '14f49eaca8f5ec55c627dd7404f7a727',
               '/?a=foo&b=foo', env,
               {'Date': 'Mon, 09 Sep 2011 23:36:00 GMT'})

        # post-header-key-sort + post-header-value-case
        env = {
            'REQUEST_METHOD': 'POST',
            'HTTP_AUTHORIZATION': ('AWS4-HMAC-SHA256 '
                'Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, '
                'SignedHeaders=date;host;zoo, Signature=X'),
            'HTTP_HOST': 'host.foo.com'}
        verify('3aae6d8274b8c03e2cc96fc7d6bda4b9'
               'bd7a0a184309344470b2c96953e124aa',
               '/', env,
               {'Date': 'Mon, 09 Sep 2011 23:36:00 GMT',
                'ZOO': 'ZOOBAR'})

        # post-x-www-form-urlencoded-parameters
        env = {
            'REQUEST_METHOD': 'POST',
            'HTTP_AUTHORIZATION': ('AWS4-HMAC-SHA256 '
                'Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, '
                'SignedHeaders=date;host;content-type, Signature=X'),
            'HTTP_HOST': 'host.foo.com',
            'HTTP_X_AMZ_CONTENT_SHA256':
                '3ba8907e7a252327488df390ed517c45'
                'b96dead033600219bdca7107d1d3f88a'}
        verify('c4115f9e54b5cecf192b1eaa23b8e88e'
               'd8dc5391bd4fde7b3fff3d9c9fe0af1f',
               '/', env,
               {'Date': 'Mon, 09 Sep 2011 23:36:00 GMT',
                'Content-Type':
                    'application/x-www-form-urlencoded; charset=utf8'})

        # post-x-www-form-urlencoded
        env = {
            'REQUEST_METHOD': 'POST',
            'HTTP_AUTHORIZATION': ('AWS4-HMAC-SHA256 '
                'Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, '
                'SignedHeaders=date;host;content-type, Signature=X'),
            'HTTP_HOST': 'host.foo.com',
            'HTTP_X_AMZ_CONTENT_SHA256':
                '3ba8907e7a252327488df390ed517c45'
                'b96dead033600219bdca7107d1d3f88a'}
        verify('4c5c6e4b52fb5fb947a8733982a8a5a6'
               '1b14f04345cbfe6e739236c76dd48f74',
               '/', env,
               {'Date': 'Mon, 09 Sep 2011 23:36:00 GMT',
                'Content-Type':
                    'application/x-www-form-urlencoded'})


if __name__ == '__main__':
    unittest.main()
