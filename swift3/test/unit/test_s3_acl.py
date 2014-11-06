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
import simplejson as json

from swift.common import swob
from swift.common.swob import Request

from swift3.etree import tostring, Element, SubElement
from swift3.subresource import ACL, ACLPrivate, User, encode_acl, \
    Owner, Grant
from swift3.test.unit.test_middleware import Swift3TestCase
from swift3.utils import sysmeta_header
from swift3.cfg import CONF

XMLNS_XSI = 'http://www.w3.org/2001/XMLSchema-instance'


def _gen_test_acl(owner, permission=None, grantee=None):
    if permission is None:
        return ACL(owner, [])

    if grantee is None:
        grantee = User('test:tester')
    return ACL(owner, [Grant(grantee, permission)])


def _make_xml(owner='test:tester', permission='READ', grantee=None):
    if grantee is None:
        grantee = Element('Grantee', nsmap={'xsi': XMLNS_XSI})
        grantee.set('{%s}type' % XMLNS_XSI, 'CanonicalUser')
        SubElement(grantee, 'ID').text = 'test:tester'
        SubElement(grantee, 'DisplayName').text = 'test:tester'
    elem = Element('AccessControlPolicy')
    elem_owner = SubElement(elem, 'Owner')
    SubElement(elem_owner, 'ID').text = owner
    SubElement(elem_owner, 'DisplayName').text = owner
    acl_list_elem = SubElement(elem, 'AccessControlList')
    elem_grant = SubElement(acl_list_elem, 'Grant')
    elem_grant.append(grantee)
    SubElement(elem_grant, 'Permission').text = permission
    return tostring(elem)


class TestSwift3S3Acl(Swift3TestCase):

    def setUp(self):
        super(TestSwift3S3Acl, self).setUp()

        CONF.s3_acl = True

        self.swift.register('HEAD', '/v1/AUTH_test/bucket', swob.HTTPNoContent,
                            encode_acl('container',
                                       ACLPrivate(Owner('test:tester',
                                                        'test:tester'))),
                            None)
        self.swift.register('HEAD', '/v1/AUTH_test/bucket/object',
                            swob.HTTPOk,
                            encode_acl('object',
                                       ACLPrivate(Owner('test:tester',
                                                        'test:tester'))),
                            None)

        self.swift.register('PUT', '/v1/AUTH_test/bucket',
                            swob.HTTPCreated, {}, None)
        self.swift.register('PUT', '/v1/AUTH_test/bucket/object',
                            swob.HTTPCreated, {}, None)
        self.swift.register('POST', '/v1/AUTH_test/bucket/object',
                            swob.HTTPAccepted, {}, None)

    def tearDown(self):
        CONF.s3_acl = False

    def test_bucket_acl_PUT_with_other_owner(self):
        req = Request.blank('/bucket?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=tostring(
                                ACLPrivate(
                                    Owner(id='test:other',
                                          name='test:other')).elem()))
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_object_acl_PUT_xml_error(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body="invalid xml")
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'MalformedACLError')

    def test_canned_acl_private(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-acl': 'private'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_canned_acl_public_read(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-acl': 'public-read'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_canned_acl_public_read_write(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-acl': 'public-read-write'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_canned_acl_authenticated_read(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-acl': 'authenticated-read'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_canned_acl_bucket_owner_read(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-acl': 'bucket-owner-read'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_canned_acl_bucket_owner_full_control(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-acl': 'bucket-owner-full-control'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_invalid_canned_acl(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-acl': 'invalid'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidRequest')

    def _test_grant_header(self, permission):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-grant-' + permission:
                                     'id=test:tester'})
        return self.call_swift3(req)

    def test_grant_read(self):
        status, headers, body = self._test_grant_header('read')
        self.assertEquals(status.split()[0], '200')

    def test_grant_write(self):
        status, headers, body = self._test_grant_header('write')
        self.assertEquals(status.split()[0], '200')

    def test_grant_read_acp(self):
        status, headers, body = self._test_grant_header('read-acp')
        self.assertEquals(status.split()[0], '200')

    def test_grant_write_acp(self):
        status, headers, body = self._test_grant_header('write-acp')
        self.assertEquals(status.split()[0], '200')

    def test_grant_full_control(self):
        status, headers, body = self._test_grant_header('full-control')
        self.assertEquals(status.split()[0], '200')

    def test_grant_invalid_permission(self):
        status, headers, body = self._test_grant_header('invalid')
        self.assertEquals(self._get_error_code(body), 'MissingSecurityHeader')

    def test_grant_with_both_header_and_xml(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-grant-full-control':
                                     'id=test:tester'},
                            body=tostring(
                                ACLPrivate(
                                    Owner(id='test:tester',
                                          name='test:tester')).elem()))
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'UnexpectedContent')

    def test_grant_with_both_header_and_canned_acl(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-grant-full-control':
                                     'id=test:tester',
                                     'x-amz-acl': 'public-read'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidRequest')

    def test_grant_email(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-grant-read': 'emailAddress=a@b.c'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'NotImplemented')

    def test_grant_email_xml(self):
        grantee = Element('Grantee', nsmap={'xsi': XMLNS_XSI})
        grantee.set('{%s}type' % XMLNS_XSI, 'AmazonCustomerByEmail')
        SubElement(grantee, 'EmailAddress').text = 'Grantees@email.com'
        xml = _make_xml(grantee=grantee)
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=xml)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'NotImplemented')

    def test_grant_invalid_group_xml(self):
        grantee = Element('Grantee', nsmap={'xsi': XMLNS_XSI})
        grantee.set('{%s}type' % XMLNS_XSI, 'Invalid')
        SubElement(grantee, 'EmailAddress').text = 'Grantees@email.com'
        xml = _make_xml(grantee=grantee)
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=xml)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'MalformedACLError')

    def test_grant_authenticated_users(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-grant-read':
                                     'uri="http://acs.amazonaws.com/groups/'
                                     'global/AuthenticatedUsers"'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_grant_all_users(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-grant-read':
                                     'uri="http://acs.amazonaws.com/groups/'
                                     'global/AllUsers"'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_grant_invalid_uri(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-grant-read':
                                     'uri="http://localhost/"'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    def test_grant_invalid_uri_xml(self):
        elem = Element(ACL.root_tag)
        owner = SubElement(elem, 'Owner')
        SubElement(owner, 'ID').text = 'test:tester'
        SubElement(owner, 'DisplayName').text = 'test:tester'

        acl = SubElement(elem, 'AccessControlList')
        grant = SubElement(acl, 'Grant')
        grantee = SubElement(grant, 'Grantee')
        grantee.set('{%s}type' % 'http://www.w3.org/2001/XMLSchema-instance',
                    'Group')
        SubElement(grantee, 'URI').text = 'invalid'
        SubElement(grant, 'Permission').text = 'READ'
        xml = tostring(elem)

        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=xml)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    def test_grant_invalid_target(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-grant-read': 'key=value'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    def _test_bucket_GET_acl(self, owner, permission):
        owner = Owner(id=owner, name=owner)
        acl = _gen_test_acl(owner, permission)

        self.swift.register('GET', '/v1/AUTH_test/acltest', swob.HTTPNoContent,
                            encode_acl('container', acl),
                            json.dumps([]))
        req = Request.blank('/acltest?acl',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})

        status, headers, body = self.call_swift3(req)
        try:
            return self._get_error_code(body)
        except Exception:
            return status.split()[0]

    def test_bucket_GET_acl_without_permission(self):
        result = self._test_bucket_GET_acl('test:other', None)
        self.assertEquals(result, 'AccessDenied')

    def test_bucket_GET_acl_with_owner_permission(self):
        result = self._test_bucket_GET_acl('test:tester', None)
        self.assertEquals(result, '200')

    def _test_bucket_PUT_acl(self, owner, permission):
        owner = Owner(id=owner, name=owner)
        acl = _gen_test_acl(owner, permission)

        self.swift.register('GET', '/v1/AUTH_test/acltest', swob.HTTPNoContent,
                            encode_acl('container', acl),
                            json.dumps([]))
        self.swift.register('POST', '/v1/AUTH_test/acltest',
                            swob.HTTPNoContent, {}, None)
        req = Request.blank('/acltest?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=tostring(acl.elem()))

        status, headers, body = self.call_swift3(req)
        try:
            return self._get_error_code(body)
        except Exception:
            return status.split()[0]

    def test_bucket_PUT_acl_without_permission(self):
        result = self._test_bucket_PUT_acl('test:other', None)
        self.assertEquals(result, 'AccessDenied')

    def test_bucket_PUT_acl_with_owner_permission(self):
        result = self._test_bucket_PUT_acl('test:tester', None)
        self.assertEquals(result, '200')

    def _test_object_GET_acl(self, owner, permission):
        owner = Owner(id=owner, name=owner)
        acl = _gen_test_acl(owner, permission)

        self.swift.register('HEAD', '/v1/AUTH_test/acltest/acltest',
                            swob.HTTPOk,
                            encode_acl('object', acl),
                            None)
        req = Request.blank('/acltest/acltest?acl',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})

        status, headers, body = self.call_swift3(req)
        try:
            return self._get_error_code(body)
        except Exception:
            return status.split()[0]

    def test_object_GET_acl_without_permission(self):
        result = self._test_object_GET_acl('test:other', None)
        self.assertEquals(result, 'AccessDenied')

    def test_object_GET_acl_with_owner_permission(self):
        result = self._test_object_GET_acl('test:tester', None)
        self.assertEquals(result, '200')

    def _test_object_PUT_acl(self, owner, permission):
        owner = Owner(id=owner, name=owner)
        acl = _gen_test_acl(owner, permission)

        self.swift.register('HEAD', '/v1/AUTH_test/acltest',
                            swob.HTTPNoContent,
                            {sysmeta_header('container', 'acl'):
                             '["test:tester"]'},
                            None)
        self.swift.register('HEAD', '/v1/AUTH_test/acltest/acltest',
                            swob.HTTPOk,
                            encode_acl('object', acl),
                            None)
        self.swift.register('POST', '/v1/AUTH_test/acltest/acltest',
                            swob.HTTPAccepted, {}, None)
        req = Request.blank('/acltest/acltest?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=tostring(acl.elem()))

        status, headers, body = self.call_swift3(req)
        try:
            return self._get_error_code(body)
        except Exception:
            return status.split()[0]

    def test_object_PUT_acl_without_permission(self):
        result = self._test_object_PUT_acl('test:other', None)
        self.assertEquals(result, 'AccessDenied')

    def test_object_PUT_acl_with_owner_permission(self):
        result = self._test_object_PUT_acl('test:tester', None)
        self.assertEquals(result, '200')

if __name__ == '__main__':
    unittest.main()
