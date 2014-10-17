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

from swift.common.swob import Request, HTTPAccepted

from swift3.test.unit import Swift3TestCase
from swift3.etree import fromstring, tostring, Element, SubElement

XMLNS_XSI = 'http://www.w3.org/2001/XMLSchema-instance'


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

    def test_bucket_canned_acl_PUT(self):
        req = Request.blank('/bucket?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'X-AMZ-ACL': 'public-read'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_object_acl_GET(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self._check_acl('test:tester', body)

    def test_invalid_xml(self):
        req = Request.blank('/bucket?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body='invalid')
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'MalformedACLError')

if __name__ == '__main__':
    unittest.main()
