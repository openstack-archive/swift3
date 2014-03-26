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

import xml.dom.minidom
import simplejson

from swift.common.swob import Request, Response, HTTPUnauthorized, \
    HTTPCreated, HTTPNoContent, HTTPAccepted, HTTPBadRequest, HTTPNotFound, \
    HTTPConflict, HTTPForbidden, HTTPRequestEntityTooLarge

from swift3 import middleware as swift3


class FakeApp(object):
    def __init__(self):
        self.app = self
        self.response_args = []

    def __call__(self, env, start_response):
        return "FAKE APP"

    def do_start_response(self, *args):
        self.response_args.extend(args)


class FakeAppService(FakeApp):
    def __init__(self, status=200):
        FakeApp.__init__(self)
        self.status = status
        self.buckets = (('apple', 1, 200), ('orange', 3, 430))

    def __call__(self, env, start_response):
        if self.status == 200:
            start_response(Response().status, [('Content-Type', 'text/xml')])
            json_pattern = ['"name":%s', '"count":%s', '"bytes":%s']
            json_pattern = '{' + ','.join(json_pattern) + '}'
            json_out = []
            for b in self.buckets:
                name = simplejson.dumps(b[0])
                json_out.append(json_pattern %
                                (name, b[1], b[2]))
            account_list = '[' + ','.join(json_out) + ']'
            return account_list
        elif self.status == 401:
            start_response(HTTPUnauthorized().status, [])
        elif self.status == 403:
            start_response(HTTPForbidden().status, [])
        else:
            start_response(HTTPBadRequest().status, [])
        return []


class FakeAppBucket(FakeApp):
    def __init__(self, status=200):
        FakeApp.__init__(self)
        self.status = status
        self.objects = (('rose', '2011-01-05T02:19:14.275290', 0, 303),
                        ('viola', '2011-01-05T02:19:14.275290', 0, 3909),
                        ('lily', '2011-01-05T02:19:14.275290', 0, 3909),
                        ('with space', '2011-01-05T02:19:14.275290', 0, 3909),
                        ('with%20space', '2011-01-05T02:19:14.275290', 0, 3909))

    def __call__(self, env, start_response):
        if env['REQUEST_METHOD'] == 'GET':
            if self.status == 200:
                start_response(Response().status,
                               [('Content-Type', 'text/xml')])
                json_pattern = ['"name":%s', '"last_modified":%s', '"hash":%s',
                                '"bytes":%s']
                json_pattern = '{' + ','.join(json_pattern) + '}'
                json_out = []
                for b in self.objects:
                    name = simplejson.dumps(b[0])
                    time = simplejson.dumps(b[1])
                    json_out.append(json_pattern %
                                    (name, time, b[2], b[3]))
                account_list = '[' + ','.join(json_out) + ']'
                return account_list
            elif self.status == 401:
                start_response(HTTPUnauthorized().status, [])
            elif self.status == 403:
                start_response(HTTPForbidden().status, [])
            elif self.status == 404:
                start_response(HTTPNotFound().status, [])
            else:
                start_response(HTTPBadRequest().status, [])
        elif env['REQUEST_METHOD'] == 'PUT':
            if self.status == 201:
                start_response(HTTPCreated().status, [])
            elif self.status == 401:
                start_response(HTTPUnauthorized().status, [])
            elif self.status == 403:
                start_response(HTTPForbidden().status, [])
            elif self.status == 202:
                start_response(HTTPAccepted().status, [])
            else:
                start_response(HTTPBadRequest().status, [])
        elif env['REQUEST_METHOD'] == 'DELETE':
            if self.status == 204:
                start_response(HTTPNoContent().status, [])
            elif self.status == 401:
                start_response(HTTPUnauthorized().status, [])
            elif self.status == 403:
                start_response(HTTPForbidden().status, [])
            elif self.status == 404:
                start_response(HTTPNotFound().status, [])
            elif self.status == 409:
                start_response(HTTPConflict().status, [])
            else:
                start_response(HTTPBadRequest().status, [])
        return []


class FakeAppObject(FakeApp):
    def __init__(self, status=200):
        FakeApp.__init__(self)
        self.status = status
        self.object_body = 'hello'
        self.response_headers = {'Content-Type': 'text/html',
                                 'Content-Length': len(self.object_body),
                                 'x-object-meta-test': 'swift',
                                 'etag': '1b2cf535f27731c974343645a3985328',
                                 'last-modified': '2011-01-05T02:19:14.275290'}

    def __call__(self, env, start_response):
        req = Request(env)
        if env['REQUEST_METHOD'] == 'GET' or env['REQUEST_METHOD'] == 'HEAD':
            if self.status == 200:
                if 'HTTP_RANGE' in env:
                    resp = Response(request=req, body=self.object_body,
                                    conditional_response=True)
                    return resp(env, start_response)
                start_response(Response(request=req).status,
                               self.response_headers.items())
                if env['REQUEST_METHOD'] == 'GET':
                    return self.object_body
            elif self.status == 401:
                start_response(HTTPUnauthorized(request=req).status, [])
            elif self.status == 403:
                start_response(HTTPForbidden(request=req).status, [])
            elif self.status == 404:
                start_response(HTTPNotFound(request=req).status, [])
            else:
                start_response(HTTPBadRequest(request=req).status, [])
        elif env['REQUEST_METHOD'] == 'PUT':
            if self.status == 201:
                start_response(HTTPCreated(request=req).status,
                               [('etag', self.response_headers['etag'])])
            elif self.status == 401:
                start_response(HTTPUnauthorized(request=req).status, [])
            elif self.status == 403:
                start_response(HTTPForbidden(request=req).status, [])
            elif self.status == 404:
                start_response(HTTPNotFound(request=req).status, [])
            elif self.status == 413:
                start_response(HTTPRequestEntityTooLarge(request=req).status,
                               [])
            else:
                start_response(HTTPBadRequest(request=req).status, [])
        elif env['REQUEST_METHOD'] == 'DELETE':
            if self.status == 204:
                start_response(HTTPNoContent(request=req).status, [])
            elif self.status == 401:
                start_response(HTTPUnauthorized(request=req).status, [])
            elif self.status == 403:
                start_response(HTTPForbidden(request=req).status, [])
            elif self.status == 404:
                start_response(HTTPNotFound(request=req).status, [])
            else:
                start_response(HTTPBadRequest(request=req).status, [])
        return []


def start_response(*args):
    pass


class TestSwift3(unittest.TestCase):
    def setUp(self):
        self.app = swift3.filter_factory({})(FakeApp())

    def test_non_s3_request_passthrough(self):
        req = Request.blank('/something')
        resp = self.app(req.environ, start_response)
        self.assertEquals(resp, 'FAKE APP')

    def test_bad_format_authorization(self):
        req = Request.blank('/something',
                            headers={'Authorization': 'hoge'})
        resp = self.app(req.environ, start_response)
        dom = xml.dom.minidom.parseString("".join(resp))
        self.assertEquals(dom.firstChild.nodeName, 'Error')
        code = dom.getElementsByTagName('Code')[0].childNodes[0].nodeValue
        self.assertEquals(code, 'AccessDenied')

    def test_bad_method(self):
        req = Request.blank('/',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        resp = self.app(req.environ, start_response)
        dom = xml.dom.minidom.parseString("".join(resp))
        self.assertEquals(dom.firstChild.nodeName, 'Error')
        code = dom.getElementsByTagName('Code')[0].childNodes[0].nodeValue
        self.assertEquals(code, 'InvalidURI')

    def _test_method_error(self, cl, method, path, status, headers={}):
        local_app = swift3.filter_factory({})(cl(status))
        headers.update({'Authorization': 'AWS test:tester:hmac'})
        req = Request.blank(path, environ={'REQUEST_METHOD': method},
                            headers=headers)
        resp = local_app(req.environ, start_response)
        dom = xml.dom.minidom.parseString("".join(resp))
        self.assertEquals(dom.firstChild.nodeName, 'Error')
        return dom.getElementsByTagName('Code')[0].childNodes[0].nodeValue

    def test_service_GET_error(self):
        code = self._test_method_error(FakeAppService, 'GET', '/', 401)
        self.assertEquals(code, 'AccessDenied')
        code = self._test_method_error(FakeAppService, 'GET', '/', 403)
        self.assertEquals(code, 'AccessDenied')
        code = self._test_method_error(FakeAppService, 'GET', '/', 0)
        self.assertEquals(code, 'InvalidURI')

    def test_service_GET(self):
        local_app = swift3.filter_factory({})(FakeAppService())
        req = Request.blank('/',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        resp = local_app(req.environ, local_app.app.do_start_response)
        self.assertEquals(local_app.app.response_args[0].split()[0], '200')

        dom = xml.dom.minidom.parseString("".join(resp))
        self.assertEquals(dom.firstChild.nodeName, 'ListAllMyBucketsResult')

        buckets = [n for n in dom.getElementsByTagName('Bucket')]
        listing = [n for n in buckets[0].childNodes if n.nodeName != '#text']
        self.assertEquals(len(listing), 2)

        names = []
        for b in buckets:
            if b.childNodes[0].nodeName == 'Name':
                names.append(b.childNodes[0].childNodes[0].nodeValue)

        self.assertEquals(len(names), len(FakeAppService().buckets))
        for i in FakeAppService().buckets:
            self.assertTrue(i[0] in names)

    def test_bucket_GET_error(self):
        code = self._test_method_error(FakeAppBucket, 'GET', '/bucket', 401)
        self.assertEquals(code, 'AccessDenied')
        code = self._test_method_error(FakeAppBucket, 'GET', '/bucket', 403)
        self.assertEquals(code, 'AccessDenied')
        code = self._test_method_error(FakeAppBucket, 'GET', '/bucket', 404)
        self.assertEquals(code, 'NoSuchBucket')
        code = self._test_method_error(FakeAppBucket, 'GET', '/bucket', 0)
        self.assertEquals(code, 'InvalidURI')

    def test_bucket_GET(self):
        local_app = swift3.filter_factory({})(FakeAppBucket())
        bucket_name = 'junk'
        req = Request.blank('/%s' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        resp = local_app(req.environ, local_app.app.do_start_response)
        self.assertEquals(local_app.app.response_args[0].split()[0], '200')

        dom = xml.dom.minidom.parseString("".join(resp))
        self.assertEquals(dom.firstChild.nodeName, 'ListBucketResult')
        name = dom.getElementsByTagName('Name')[0].childNodes[0].nodeValue
        self.assertEquals(name, bucket_name)

        objects = [n for n in dom.getElementsByTagName('Contents')]

        names = []
        for o in objects:
            if o.childNodes[0].nodeName == 'Key':
                names.append(o.childNodes[0].childNodes[0].nodeValue)
            if o.childNodes[1].nodeName == 'LastModified':
                self.assertTrue(
                    o.childNodes[1].childNodes[0].nodeValue.endswith('Z'))

        self.assertEquals(len(names), len(FakeAppBucket().objects))
        for i in FakeAppBucket().objects:
            self.assertTrue(i[0] in names)

    def test_bucket_GET_is_truncated(self):
        local_app = swift3.filter_factory({})(FakeAppBucket())
        bucket_name = 'junk'

        req = Request.blank('/%s' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET',
                         'QUERY_STRING': 'max-keys=5'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        resp = local_app(req.environ, local_app.app.do_start_response)
        dom = xml.dom.minidom.parseString("".join(resp))
        self.assertEquals(dom.getElementsByTagName('IsTruncated')[0].
                          childNodes[0].nodeValue, 'false')

        req = Request.blank('/%s' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET',
                         'QUERY_STRING': 'max-keys=4'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        resp = local_app(req.environ, local_app.app.do_start_response)
        dom = xml.dom.minidom.parseString("".join(resp))
        self.assertEquals(dom.getElementsByTagName('IsTruncated')[0].
                          childNodes[0].nodeValue, 'true')

    def test_bucket_GET_max_keys(self):
        class FakeApp(object):
            def __call__(self, env, start_response):
                self.query_string = env['QUERY_STRING']
                start_response('200 OK', [])
                return '[]'
        fake_app = FakeApp()
        local_app = swift3.filter_factory({})(fake_app)
        bucket_name = 'junk'

        req = Request.blank('/%s' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET',
                                     'QUERY_STRING': 'max-keys=5'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        resp = local_app(req.environ, lambda *args: None)
        dom = xml.dom.minidom.parseString("".join(resp))
        self.assertEquals(dom.getElementsByTagName('MaxKeys')[0].
                          childNodes[0].nodeValue, '5')
        args = dict(cgi.parse_qsl(fake_app.query_string))
        self.assert_(args['limit'] == '6')

        req = Request.blank('/%s' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET',
                                     'QUERY_STRING': 'max-keys=5000'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        resp = local_app(req.environ, lambda *args: None)
        dom = xml.dom.minidom.parseString("".join(resp))
        self.assertEquals(dom.getElementsByTagName('MaxKeys')[0].
                          childNodes[0].nodeValue, '1000')
        args = dict(cgi.parse_qsl(fake_app.query_string))
        self.assertEquals(args['limit'], '1001')

    def test_bucket_GET_passthroughs(self):
        class FakeApp(object):
            def __call__(self, env, start_response):
                self.query_string = env['QUERY_STRING']
                start_response('200 OK', [])
                return '[]'
        fake_app = FakeApp()
        local_app = swift3.filter_factory({})(fake_app)
        bucket_name = 'junk'
        req = Request.blank('/%s' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET', 'QUERY_STRING':
                                     'delimiter=a&marker=b&prefix=c'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        resp = local_app(req.environ, lambda *args: None)
        dom = xml.dom.minidom.parseString("".join(resp))
        self.assertEquals(dom.getElementsByTagName('Prefix')[0].
                          childNodes[0].nodeValue, 'c')
        self.assertEquals(dom.getElementsByTagName('Marker')[0].
                          childNodes[0].nodeValue, 'b')
        self.assertEquals(dom.getElementsByTagName('Delimiter')[0].
                          childNodes[0].nodeValue, 'a')
        args = dict(cgi.parse_qsl(fake_app.query_string))
        self.assertEquals(args['delimiter'], 'a')
        self.assertEquals(args['marker'], 'b')
        self.assertEquals(args['prefix'], 'c')

    def test_bucket_PUT_error(self):
        code = self._test_method_error(FakeAppBucket, 'PUT', '/bucket', 201,
                                       headers={'Content-Length': 'a'})
        self.assertEqual(code, 'InvalidArgument')
        code = self._test_method_error(FakeAppBucket, 'PUT', '/bucket', 201,
                                       headers={'Content-Length': '-1'})
        self.assertEqual(code, 'InvalidArgument')
        code = self._test_method_error(FakeAppBucket, 'PUT', '/bucket', 401)
        self.assertEquals(code, 'AccessDenied')
        code = self._test_method_error(FakeAppBucket, 'PUT', '/bucket', 403)
        self.assertEquals(code, 'AccessDenied')
        code = self._test_method_error(FakeAppBucket, 'PUT', '/bucket', 202)
        self.assertEquals(code, 'BucketAlreadyExists')
        code = self._test_method_error(FakeAppBucket, 'PUT', '/bucket', 0)
        self.assertEquals(code, 'InvalidURI')

    def test_bucket_PUT(self):
        local_app = swift3.filter_factory({})(FakeAppBucket(201))
        req = Request.blank('/bucket',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        local_app(req.environ, local_app.app.do_start_response)
        self.assertEquals(local_app.app.response_args[0].split()[0], '200')

    def test_bucket_DELETE_error(self):
        code = self._test_method_error(FakeAppBucket, 'DELETE', '/bucket', 401)
        self.assertEquals(code, 'AccessDenied')
        code = self._test_method_error(FakeAppBucket, 'DELETE', '/bucket', 403)
        self.assertEquals(code, 'AccessDenied')
        code = self._test_method_error(FakeAppBucket, 'DELETE', '/bucket', 404)
        self.assertEquals(code, 'NoSuchBucket')
        code = self._test_method_error(FakeAppBucket, 'DELETE', '/bucket', 409)
        self.assertEquals(code, 'BucketNotEmpty')
        code = self._test_method_error(FakeAppBucket, 'DELETE', '/bucket', 0)
        self.assertEquals(code, 'InvalidURI')

    def test_bucket_DELETE(self):
        local_app = swift3.filter_factory({})(FakeAppBucket(204))
        req = Request.blank('/bucket',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        local_app(req.environ, local_app.app.do_start_response)
        self.assertEquals(local_app.app.response_args[0].split()[0], '204')

    def _check_acl(self, owner, resp):
        dom = xml.dom.minidom.parseString("".join(resp))
        self.assertEquals(dom.firstChild.nodeName, 'AccessControlPolicy')
        permission = dom.getElementsByTagName('Permission')[0]
        name = permission.childNodes[0].nodeValue
        self.assertEquals(name, 'FULL_CONTROL')
        name = dom.getElementsByTagName('ID')[0].childNodes[0].nodeValue
        self.assertEquals(name, owner)

    def test_bucket_acl_GET(self):
        local_app = swift3.filter_factory({})(FakeAppBucket())
        bucket_name = 'junk'
        req = Request.blank('/%s?acl' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        resp = local_app(req.environ, local_app.app.do_start_response)
        self._check_acl('test:tester', resp)

    def test_bucket_versioning_GET(self):
        local_app = swift3.filter_factory({})(FakeAppBucket())
        bucket_name = 'junk'
        req = Request.blank('/%s?versioning' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        resp = local_app(req.environ, local_app.app.do_start_response)
        dom = xml.dom.minidom.parseString("".join(resp))
        self.assertEquals(dom.firstChild.nodeName, 'VersioningConfiguration')

    def _test_object_GETorHEAD(self, method):
        local_app = swift3.filter_factory({})(FakeAppObject())
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': method},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        resp = local_app(req.environ, local_app.app.do_start_response)
        self.assertEquals(local_app.app.response_args[0].split()[0], '200')

        headers = dict((k.lower(), v) for k, v in
                       local_app.app.response_args[1])
        for key, val in local_app.app.response_headers.iteritems():
            if key in ('content-length', 'content-type', 'content-encoding',
                       'etag', 'last-modified'):
                self.assertTrue(key in headers)
                self.assertEquals(headers[key], val)

            elif key.startswith('x-object-meta-'):
                self.assertTrue('x-amz-meta-' + key[14:] in headers)
                self.assertEquals(headers['x-amz-meta-' + key[14:]], val)

        if method == 'GET':
            self.assertEquals(''.join(resp), local_app.app.object_body)

    def test_object_HEAD(self):
        self._test_object_GETorHEAD('HEAD')

    def test_object_GET_error(self):
        code = self._test_method_error(FakeAppObject, 'GET',
                                       '/bucket/object', 401)
        self.assertEquals(code, 'AccessDenied')
        code = self._test_method_error(FakeAppObject, 'GET',
                                       '/bucket/object', 403)
        self.assertEquals(code, 'AccessDenied')
        code = self._test_method_error(FakeAppObject, 'GET',
                                       '/bucket/object', 404)
        self.assertEquals(code, 'NoSuchKey')
        code = self._test_method_error(FakeAppObject, 'GET',
                                       '/bucket/object', 0)
        self.assertEquals(code, 'InvalidURI')

    def test_object_GET(self):
        self._test_object_GETorHEAD('GET')

    def test_object_GET_Range(self):
        local_app = swift3.filter_factory({})(FakeAppObject())
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Range': 'bytes=0-3'})
        local_app(req.environ, local_app.app.do_start_response)
        self.assertEquals(local_app.app.response_args[0].split()[0], '206')

        headers = dict((k.lower(), v) for k, v in
                       local_app.app.response_args[1])
        self.assertTrue('content-range' in headers)
        self.assertTrue(headers['content-range'].startswith('bytes 0-3'))

    def test_object_PUT_error(self):
        code = self._test_method_error(FakeAppObject, 'PUT',
                                       '/bucket/object', 401)
        self.assertEquals(code, 'AccessDenied')
        code = self._test_method_error(FakeAppObject, 'PUT',
                                       '/bucket/object', 403)
        self.assertEquals(code, 'AccessDenied')
        code = self._test_method_error(FakeAppObject, 'PUT',
                                       '/bucket/object', 404)
        self.assertEquals(code, 'NoSuchBucket')
        code = self._test_method_error(FakeAppObject, 'PUT',
                                       '/bucket/object', 413)
        self.assertEquals(code, 'EntityTooLarge')
        code = self._test_method_error(FakeAppObject, 'PUT',
                                       '/bucket/object', 0)
        self.assertEquals(code, 'InvalidURI')

    def test_object_PUT(self):
        local_app = swift3.filter_factory({})(FakeAppObject(201))
        req = Request.blank(
            '/bucket/object',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'x-amz-storage-class': 'REDUCED_REDUNDANCY',
                     'Content-MD5': 'Gyz1NfJ3Mcl0NDZFo5hTKA=='})
        req.date = datetime.now()
        req.content_type = 'text/plain'
        local_app(req.environ, local_app.app.do_start_response)
        self.assertEquals(local_app.app.response_args[0].split()[0], '200')

        headers = dict((k.lower(), v) for k, v in
                       local_app.app.response_args[1])
        self.assertEquals(headers['etag'],
                          "\"%s\"" % local_app.app.response_headers['etag'])

    def test_object_PUT_headers(self):
        class FakeApp(object):
            def __call__(self, env, start_response):
                self.req = Request(env)
                start_response('200 OK', [])
                return []
        app = FakeApp()
        local_app = swift3.filter_factory({})(app)
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
        local_app(req.environ, lambda *args: None)
        self.assertEquals(app.req.headers['ETag'],
                          '7dfa07a8e59ddbcd1dc84d4c4f82aea1')
        self.assertEquals(app.req.headers['X-Object-Meta-Something'], 'oh hai')
        self.assertEquals(app.req.headers['X-Copy-From'], '/some/source')

    def test_object_DELETE_error(self):
        code = self._test_method_error(FakeAppObject, 'DELETE',
                                       '/bucket/object', 401)
        self.assertEquals(code, 'AccessDenied')
        code = self._test_method_error(FakeAppObject, 'DELETE',
                                       '/bucket/object', 403)
        self.assertEquals(code, 'AccessDenied')
        code = self._test_method_error(FakeAppObject, 'DELETE',
                                       '/bucket/object', 404)
        self.assertEquals(code, 'NoSuchKey')
        code = self._test_method_error(FakeAppObject, 'DELETE',
                                       '/bucket/object', 0)
        self.assertEquals(code, 'InvalidURI')

    def test_object_DELETE(self):
        local_app = swift3.filter_factory({})(FakeAppObject(204))
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        local_app(req.environ, local_app.app.do_start_response)
        self.assertEquals(local_app.app.response_args[0].split()[0], '204')

    def test_object_multi_DELETE(self):
        local_app = swift3.filter_factory({})(FakeAppBucket())
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <Delete>\
                  <Object>\
                    <Key>Key1</Key>\
                  </Object>\
                  <Object>\
                    <Key>Key2</Key>\
                  </Object>\
                </Delete>'
        req = Request.blank('/bucket?delete',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=body)
        req.date = datetime.now()
        req.content_type = 'text/plain'
        local_app(req.environ, local_app.app.do_start_response)
        self.assertEquals(local_app.app.response_args[0].split()[0], '200')

    def test_object_acl_GET(self):
        local_app = swift3.filter_factory({})(FakeAppObject())
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        resp = local_app(req.environ, local_app.app.do_start_response)
        self._check_acl('test:tester', resp)

    def test_canonical_string(self):
        """
        The hashes here were generated by running the same requests against
        boto.utils.canonical_string
        """
        def verify(hash, path, headers):
            req = Request.blank(path, headers=headers)
            self.assertEquals(hash, hashlib.md5(
                swift3.canonical_string(req)).hexdigest())

        verify('6dd08c75e42190a1ce9468d1fd2eb787', '/bucket/object',
               {'Content-Type': 'text/plain', 'X-Amz-Something': 'test',
                'Date': 'whatever'})

        verify('c8447135da232ae7517328f3429df481', '/bucket/object',
               {'Content-Type': 'text/plain', 'X-Amz-Something': 'test'})

        verify('bf49304103a4de5c325dce6384f2a4a2', '/bucket/object',
               {'content-type': 'text/plain'})

        verify('be01bd15d8d47f9fe5e2d9248cc6f180', '/bucket/object', {})

        verify('8d28cc4b8322211f6cc003256cd9439e', 'bucket/object',
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

        req1 = Request.blank('/', headers=
                             {'Content-Type': None, 'X-Amz-Something': 'test'})
        req2 = Request.blank('/', headers=
                             {'Content-Type': '', 'X-Amz-Something': 'test'})
        req3 = Request.blank('/', headers={'X-Amz-Something': 'test'})

        self.assertEquals(swift3.canonical_string(req1),
                          swift3.canonical_string(req2))
        self.assertEquals(swift3.canonical_string(req2),
                          swift3.canonical_string(req3))

    def test_signed_urls(self):
        class FakeApp(object):
            def __call__(self, env, start_response):
                self.req = Request(env)
                start_response('200 OK', [])
                return []
        app = FakeApp()
        local_app = swift3.filter_factory({})(app)
        req = Request.blank('/bucket/object?Signature=X&Expires=Y&'
                            'AWSAccessKeyId=Z',
                            environ={'REQUEST_METHOD': 'GET'})
        req.headers['Date'] = datetime.utcnow()
        req.content_type = 'text/plain'
        local_app(req.environ, lambda *args: None)
        self.assertEquals(req.headers['Authorization'], 'AWS Z:X')
        self.assertEquals(req.headers['Date'], 'Y')

    def test_token_generation(self):
        req = Request.blank('/bucket/object?uploadId=123456789abcdef'
                            '&partNumber=1',
                            environ={'REQUEST_METHOD': 'PUT'})
        req.headers['Authorization'] = 'AWS X:Y'
        self.app(req.environ, start_response)
        self.assertEquals(base64.urlsafe_b64decode(
            req.headers['X-Auth-Token']),
            'PUT\n\n\n/bucket/object?partNumber=1&uploadId=123456789abcdef')

if __name__ == '__main__':
    unittest.main()
