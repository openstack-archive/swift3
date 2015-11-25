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
from cStringIO import StringIO

from swift.common.swob import Request, HTTPAccepted

from swift3.test.unit import Swift3TestCase
from swift3.etree import fromstring, tostring, Element, SubElement, XMLNS_XSI
from swift3.test.unit.test_s3_acl import s3acl
import mock
from swift3.response import InvalidArgument
from swift3.acl_utils import handle_acl_header


class TestSwift3Acl(Swift3TestCase):

    def setUp(self):
        super(TestSwift3Acl, self).setUp()
        # All ACL API should be called against to existing bucket.
        self.swift.register('PUT', '/v1/AUTH_test/bucket',
                            HTTPAccepted, {}, None)

    def _check_acl(self, owner, body):
        elem = fromstring(body, 'AccessControlPolicy')
        permission = elem.find('./AccessControlList/Grant/Permission').text
        self.assertEquals(permission, 'FULL_CONTROL')
        name = elem.find('./AccessControlList/Grant/Grantee/ID').text
        self.assertEquals(name, owner)

    def test_bucket_acl_GET(self):
        req = Request.blank('/bucket?acl',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
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
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()},
                            body=xml)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

        req = Request.blank('/bucket?acl',
                            environ={'REQUEST_METHOD': 'PUT',
                                     'wsgi.input': StringIO(xml)},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'Transfer-Encoding': 'chunked'})
        self.assertIsNone(req.content_length)
        self.assertIsNone(req.message_length())
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_bucket_canned_acl_PUT(self):
        req = Request.blank('/bucket?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'X-AMZ-ACL': 'public-read'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_bucket_canned_acl_PUT_with_s3acl(self):
        req = Request.blank('/bucket?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'X-AMZ-ACL': 'public-read'})
        with mock.patch('swift3.request.handle_acl_header') as mock_handler:
            status, headers, body = self.call_swift3(req)
            self.assertEquals(status.split()[0], '200')
            self.assertEquals(mock_handler.call_count, 0)

    def test_bucket_fails_with_both_acl_header_and_xml_PUT(self):
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
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'X-AMZ-ACL': 'public-read'},
                            body=xml)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body),
                          'UnexpectedContent')

    def test_object_acl_GET(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_swift3(req)
        self._check_acl('test:tester', body)

    def test_invalid_xml(self):
        req = Request.blank('/bucket?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()},
                            body='invalid')
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'MalformedACLError')

    def test_handle_acl_header(self):
        def check_generated_acl_header(acl, targets):
            req = Request.blank('/bucket',
                                headers={'X-Amz-Acl': acl})
            handle_acl_header(req)
            for target in targets:
                self.assertTrue(target[0] in req.headers)
                self.assertEquals(req.headers[target[0]], target[1])

        check_generated_acl_header('public-read',
                                   [('X-Container-Read', '.r:*,.rlistings')])
        check_generated_acl_header('public-read-write',
                                   [('X-Container-Read', '.r:*,.rlistings'),
                                    ('X-Container-Write', '.r:*')])
        check_generated_acl_header('private',
                                   [('X-Container-Read', '.'),
                                    ('X-Container-Write', '.')])

    @s3acl(s3acl_only=True)
    def test_handle_acl_header_with_s3acl(self):
        def check_generated_acl_header(acl, targets):
            req = Request.blank('/bucket',
                                headers={'X-Amz-Acl': acl})
            for target in targets:
                self.assertTrue(target not in req.headers)
            self.assertTrue('HTTP_X_AMZ_ACL' in req.environ)
            # TODO: add transration and assertion for s3acl

        check_generated_acl_header('public-read',
                                   ['X-Container-Read'])
        check_generated_acl_header('public-read-write',
                                   ['X-Container-Read', 'X-Container-Write'])
        check_generated_acl_header('private',
                                   ['X-Container-Read', 'X-Container-Write'])

    def test_handle_acl_with_invalid_header_string(self):
        req = Request.blank('/bucket', headers={'X-Amz-Acl': 'invalid'})
        with self.assertRaises(InvalidArgument) as cm:
            handle_acl_header(req)
        self.assertTrue('argument_name' in cm.exception.info)
        self.assertEquals(cm.exception.info['argument_name'], 'x-amz-acl')
        self.assertTrue('argument_value' in cm.exception.info)
        self.assertEquals(cm.exception.info['argument_value'], 'invalid')


if __name__ == '__main__':
    unittest.main()
