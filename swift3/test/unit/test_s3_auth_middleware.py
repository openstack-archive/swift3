# Copyright (c) 2017 OpenStack Foundation.
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

from swift.common.swob import wsgify
from swift.common.swob import Request, Response

from swift3.etree import fromstring
from swift3.response import AccessDenied, SignatureDoesNotMatch
from swift3.s3_auth_middleware import S3Auth


class FakeApp(object):

    def __init__(self, headers={}):
        self.headers = headers

    @wsgify
    def __call__(self, request):
        resp = None
        if 'swift.authorize' in request.environ:
            resp = request.environ['swift.authorize'](request)
        if not resp:
            resp = Response(headers=self.headers)
        resp.environ = request.environ
        return resp


class S3TokenMiddlewareTestBase(unittest.TestCase):

    def _get_error_message(self, body):
        elem = fromstring(body, 'Error')
        return elem.find('./Message').text

    def setUp(self):
        self.environ = {'swift3.auth_details': {
            'access_key': 'akey',
            'check_signature': lambda req: self.valid
        }}
        self.valid = True

    def test_passthrough(self):
        app = S3Auth(FakeApp(), None)
        resp = Request.blank('/path', environ={}).get_response(app)
        self.assertEqual(resp.status_int, 200)
        self.assertNotIn('swift.authorize', resp.environ)

    def test_s3_creds_valid(self):
        app = S3Auth(
            FakeApp(headers={'x-account-meta-s3-secret': 'secret'}), None)
        resp = Request.blank('/path', environ=self.environ).get_response(app)
        self.assertEqual(resp.status_int, 200)
        self.assertIn('swift.authorize', resp.environ)

    def test_s3_creds_invalid(self):
        app = S3Auth(
            FakeApp(headers={'x-account-meta-s3-secret': 'secret'}), None)
        self.valid = False
        resp = Request.blank('/path', environ=self.environ).get_response(app)
        self.assertEqual(resp.status_int, 403)
        self.assertEqual(
            self._get_error_message(resp.body), SignatureDoesNotMatch._msg)
        self.assertNotIn('swift.authorize', resp.environ)

    def test_s3_creds_secret_missing(self):
        app = S3Auth(FakeApp(), None)
        resp = Request.blank('/path', environ=self.environ).get_response(app)
        self.assertEqual(resp.status_int, 403)
        self.assertEqual(
            self._get_error_message(resp.body),
            AccessDenied._msg)
        self.assertNotIn('swift.authorize', resp.environ)
