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
    decode_acl, AuthenticatedUsers, AllUsers, Owner, Grant
from swift3.test.unit.test_middleware import Swift3TestCase
from swift3.cfg import CONF

XMLNS_XSI = 'http://www.w3.org/2001/XMLSchema-instance'


def _gen_test_headers(owner, permission=None, grantee=None,
                      resource='container'):
    if permission is None:
        return encode_acl(resource, ACL(owner, []))

    if grantee is None:
        grantee = User('test:tester')
    return encode_acl(resource, ACL(owner, [Grant(grantee, permission)]))


def _make_xml(grantee):
    owner = 'test:tester'
    permission = 'READ'
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
    """
    This class has been tested in the following Controller.
        [S3AclController]
        [BucketController] Case: Conf.s3_acl == True
        [Object Controller] Case: Conf.s3_acl == True
    """

    def setUp(self):
        super(TestSwift3S3Acl, self).setUp()

        CONF.s3_acl = True

        # TEST method is used to resolve a tenant name
        self.swift.register('TEST', '/v1/AUTH_test', swob.HTTPMethodNotAllowed,
                            {}, None)
        self.swift.register('TEST', '/v1/AUTH_X', swob.HTTPMethodNotAllowed,
                            {}, None)

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

    """
    [S3AclController]
    """
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
        grantee = Element('Grantee', nsmap={'xsi': XMLNS_XSI})
        grantee.set('{%s}type' % XMLNS_XSI, 'Group')
        SubElement(grantee, 'URI').text = 'invalid'
        xml = _make_xml(grantee)

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

    def _test_bucket_acl_GET(self, owner, permission):
        owner = Owner(id=owner, name=owner)
        headers = _gen_test_headers(owner, permission)

        self.swift.register('HEAD', '/v1/AUTH_test/bucket', swob.HTTPNoContent,
                            headers, None)
        req = Request.blank('/bucket?acl',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})

        return self.call_swift3(req)

    def test_bucket_acl_GET_without_permission(self):
        status, headers, body = self._test_bucket_acl_GET('test:other', None)
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_bucket_acl_GET_with_read_acp_permission(self):
        status, headers, body = self._test_bucket_acl_GET('test:other',
                                                          'READ_ACP')
        self.assertEquals(status.split()[0], '200')

    def test_bucket_acl_GET_with_fullcontrol_permission(self):
        status, headers, body = self._test_bucket_acl_GET('test:other',
                                                          'FULL_CONTROL')
        self.assertEquals(status.split()[0], '200')

    def test_bucket_acl_GET_with_owner_permission(self):
        status, headers, body = self._test_bucket_acl_GET('test:tester', None)
        self.assertEquals(status.split()[0], '200')

    def _test_bucket_acl_PUT(self, owner, permission, grantee='test:tester'):
        owner = Owner(id=owner, name=owner)
        grantee = User(grantee)
        headers = _gen_test_headers(owner, permission, grantee)
        acl = decode_acl('container', headers)

        self.swift.register('HEAD', '/v1/AUTH_test/bucket', swob.HTTPNoContent,
                            headers, None)
        req = Request.blank('/bucket?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=tostring(acl.elem()))

        return self.call_swift3(req)

    def test_bucket_acl_PUT_without_permission(self):
        status, headers, body = self._test_bucket_acl_PUT('test:other', None,
                                                          'test:other')
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_bucket_acl_PUT_with_write_acp_permission(self):

        status, headers, body = self._test_bucket_acl_PUT('test:other',
                                                          'WRITE_ACP')
        self.assertEquals(status.split()[0], '200')

    def test_bucket_acl_PUT_with_fullcontrol_permission(self):

        status, headers, body = self._test_bucket_acl_PUT('test:other',
                                                          'FULL_CONTROL')
        self.assertEquals(status.split()[0], '200')

    def test_bucket_acl_PUT_with_owner_permission(self):

        status, headers, body = self._test_bucket_acl_PUT('test:tester',
                                                          'FULL_CONTROL')
        self.assertEquals(status.split()[0], '200')

    def _test_object_acl_GET(self, owner, permission):
        owner = Owner(id=owner, name=owner)
        headers = _gen_test_headers(owner, permission, resource='object')

        self.swift.register('HEAD', '/v1/AUTH_test/bucket/object',
                            swob.HTTPOk, headers, None)
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})

        return self.call_swift3(req)

    def test_object_acl_GET_without_permission(self):
        status, headers, body = self._test_object_acl_GET('test:other', None)
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_object_acl_GET_with_read_acp_permission(self):
        status, headers, body = self._test_object_acl_GET('test:other',
                                                          'READ_ACP')
        self.assertEquals(status.split()[0], '200')

    def test_object_acl_GET_with_fullcontrol_permission(self):
        status, headers, body = self._test_object_acl_GET('test:other',
                                                          'FULL_CONTROL')
        self.assertEquals(status.split()[0], '200')

    def test_object_acl_GET_with_owner_permission(self):
        status, headers, body = self._test_object_acl_GET('test:tester', None)
        self.assertEquals(status.split()[0], '200')

    def _test_object_acl_PUT(self, owner, permission):
        owner = Owner(id=owner, name=owner)
        headers = _gen_test_headers(owner, permission, resource='object')
        acl = decode_acl('object', headers)

        self.swift.register('HEAD', '/v1/AUTH_test/bucket/object',
                            swob.HTTPOk, headers, None)
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=tostring(acl.elem()))

        return self.call_swift3(req)

    def test_object_acl_PUT_without_permission(self):
        status, headers, body = self._test_object_acl_PUT('test:other', None)
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_object_acl_PUT_with_write_acp_permission(self):
        status, headers, body = self._test_object_acl_PUT('test:other',
                                                          'WRITE_ACP')
        self.assertEquals(status.split()[0], '200')

    def test_object_acl_PUT_with_fullcontrol_permission(self):
        status, headers, body = self._test_object_acl_PUT('test:other',
                                                          'FULL_CONTROL')
        self.assertEquals(status.split()[0], '200')

    def test_object_acl_PUT_with_owner_permission(self):
        status, headers, body = self._test_object_acl_PUT('test:tester', None)
        self.assertEquals(status.split()[0], '200')

    """
    [BucketController] Case: Conf.s3_acl == True
    """
    def _test_bucket(self, method, owner, permission):
        owner = Owner(id=owner, name=owner)
        headers = _gen_test_headers(owner, permission)

        self.swift.register('HEAD', '/v1/AUTH_test/acltest',
                            swob.HTTPNoContent, headers, None)
        self.swift.register('GET', '/v1/AUTH_test/acltest', swob.HTTPNoContent,
                            headers, json.dumps([]))
        self.swift.register('POST', '/v1/AUTH_test/acltest',
                            swob.HTTPNoContent, {}, None)
        self.swift.register('DELETE', '/v1/AUTH_test/acltest',
                            swob.HTTPNoContent, {}, None)

        req = Request.blank('/acltest',
                            environ={'REQUEST_METHOD': method},
                            headers={'Authorization': 'AWS test:tester:hmac'})

        return self.call_swift3(req)

    def test_bucket_GET_without_permission(self):
        status, headers, body = self._test_bucket('GET', 'test:other', None)
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_bucket_GET_with_read_permission(self):
        status, headers, body = self._test_bucket('GET', 'test:other', 'READ')
        self.assertEquals(status.split()[0], '200')

    def test_bucket_GET_with_fullcontrol_permission(self):
        status, headers, body = self._test_bucket('GET', 'test:other',
                                                  'FULL_CONTROL')
        self.assertEquals(status.split()[0], '200')

    def test_bucket_GET_with_owner_permission(self):
        status, headers, body = self._test_bucket('GET', 'test:tester', None)
        self.assertEquals(status.split()[0], '200')

    def _test_bucket_GET_canned_acl(self, group):
        owner = Owner(id='test:other', name='test:other')
        headers = _gen_test_headers(owner, 'READ', group)
        self.swift.register('GET', '/v1/AUTH_test/acltest', swob.HTTPNoContent,
                            headers, json.dumps([]))
        req = Request.blank('/acltest',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})

        return self.call_swift3(req)

    def test_bucket_GET_authenticated_users(self):
        status, headers, body = \
            self._test_bucket_GET_canned_acl(AuthenticatedUsers())
        self.assertEquals(status.split()[0], '200')

    def test_bucket_GET_all_users(self):
        status, headers, body = self._test_bucket_GET_canned_acl(AllUsers())
        self.assertEquals(status.split()[0], '200')

    def test_bucket_PUT_with_already_exist(self):
        self.swift.register('PUT', '/v1/AUTH_test/acltest',
                            swob.HTTPAccepted, {}, None)
        status, headers, body = self._test_bucket('PUT', 'test:other', None)
        self.assertEquals(self._get_error_code(body), 'BucketAlreadyExists')

    def test_bucket_PUT(self):
        self.swift.register('PUT', '/v1/AUTH_test/acltest',
                            swob.HTTPCreated, {}, None)
        status, headers, body = self._test_bucket('PUT', 'test:other', 'WRITE')
        self.assertEquals(status.split()[0], '200')

    def test_bucket_DELETE_without_permission(self):
        status, headers, body = self._test_bucket('DELETE', 'test:other', None)
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_bucket_DELETE_with_write_permission(self):
        status, headers, body = self._test_bucket('DELETE', 'test:other',
                                                  'WRITE')
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_bucket_DELETE_with_fullcontrol_permission(self):
        status, headers, body = self._test_bucket('DELETE', 'test:other',
                                                  'FULL_CONTROL')
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_bucket_DELETE_with_owner_permission(self):
        status, headers, body = self._test_bucket('DELETE', 'test:tester',
                                                  None)
        self.assertEquals(status.split()[0], '204')

    """
    [Object Controller] Case: Conf.s3_acl == True
    """
    def _test_object(self, method, o_owner, o_permission,
                     grantee='test:tester', c_owner='test:tester',
                     c_permission='FULL_CONTROL', existObject=True):
        c_owner = Owner(id=c_owner, name=c_owner)
        o_owner = Owner(id=o_owner, name=o_owner)
        grantee = User(grantee)
        c_headers = _gen_test_headers(c_owner, c_permission, grantee)
        o_headers = _gen_test_headers(o_owner, o_permission, grantee, 'object')

        self.swift.register('HEAD', '/v1/AUTH_test/bucket',
                            swob.HTTPNoContent, c_headers, None)
        if existObject:
            self.swift.register('HEAD', '/v1/AUTH_test/bucket/object',
                                swob.HTTPOk, o_headers, None)
        else:
            self.swift.register('HEAD', '/v1/AUTH_test/bucket/object',
                                swob.HTTPNotFound, {}, None)
        self.swift.register('GET', '/v1/AUTH_test/bucket/object',
                            swob.HTTPOk, o_headers, '')
        self.swift.register('PUT', '/v1/AUTH_test/bucket/object',
                            swob.HTTPCreated, {}, None)
        self.swift.register('DELETE', '/v1/AUTH_test/bucket/object',
                            swob.HTTPNoContent, {}, None)

        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': method},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        return self.call_swift3(req)

    def test_object_GET_without_permission(self):
        status, headers, body = self._test_object('GET', 'test:other', None)
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_object_GET_with_read_permission(self):
        status, headers, body = self._test_object('GET', 'test:other', 'READ')
        self.assertEquals(status.split()[0], '200')

    def test_object_GET_with_fullcontrol_permission(self):
        status, headers, body = self._test_object('GET', 'test:other',
                                                  'FULL_CONTROL')
        self.assertEquals(status.split()[0], '200')

    def test_object_GET_with_owner_permission(self):
        status, headers, body = self._test_object('GET', 'test:tester', None)
        self.assertEquals(status.split()[0], '200')

    def test_object_PUT_without_permission(self):
        status, headers, body = self._test_object('PUT', 'test:other', None)
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_object_PUT_with_write_permission(self):
        status, headers, body = self._test_object('PUT', 'test:other', 'WRITE',
                                                  existObject=False)
        self.assertEquals(status.split()[0], '200')

    def test_object_PUT_with_fullcontrol_permission(self):
        status, headers, body = self._test_object('PUT', 'test:other',
                                                  'FULL_CONTROL',
                                                  existObject=False)
        self.assertEquals(status.split()[0], '200')

    def test_object_PUT_with_owner_permission(self):
        status, headers, body = self._test_object('PUT', 'test:tester', None,
                                                  existObject=False)
        self.assertEquals(status.split()[0], '200')

    def test_object_PUT_without_overwriting_permission(self):
        status, headers, body = self._test_object('PUT', 'test:other', None)
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_object_PUT_with_overwriting_permission(self):
        status, headers, body = self._test_object('PUT', 'test:other',
                                                  'WRITE')
        self.assertEquals(status.split()[0], '200')

    def test_object_DELETE_without_permission(self):
        status, headers, body = self._test_object('DELETE', 'test:other', None,
                                                  c_owner='test:other',
                                                  c_permission='READ')
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_object_DELETE_with_write_permission(self):
        status, headers, body = self._test_object('DELETE', 'test:tester',
                                                  None,
                                                  c_owner='test:other',
                                                  c_permission='WRITE')
        self.assertEquals(status.split()[0], '204')

    def test_object_DELETE_with_fullcontrol_permission(self):
        status, headers, body = self._test_object('DELETE', 'test:tester',
                                                  None,
                                                  c_owner='test:other')
        self.assertEquals(status.split()[0], '204')

    def test_object_DELETE_with_owner_permission(self):
        status, headers, body = self._test_object('DELETE', 'test:tester',
                                                  None)
        self.assertEquals(status.split()[0], '204')

    def _test_object_copy(self, src_owner='test:tester', src_permission=None,
                          dst_c_owner='test:tester', dst_c_permission=None,
                          dst_c_grantee=None, dst_o_owner='test:tester',
                          dst_o_permission=None, dst_o_grantee=None):

        src_o_headers = _gen_test_headers(Owner(id=src_owner, name=src_owner),
                                          src_permission, None, 'object')
        self.swift.register('HEAD', '/v1/AUTH_test/src_bucket/src_obj',
                            swob.HTTPOk, src_o_headers, None)

        dst_c_headers = _gen_test_headers(Owner(id=dst_c_owner,
                                                name=dst_c_owner),
                                          dst_c_permission, dst_c_grantee)
        self.swift.register('HEAD', '/v1/AUTH_test/dst_bucket',
                            swob.HTTPNoContent, dst_c_headers, None)

        dst_o_headers = _gen_test_headers(Owner(id=dst_o_owner,
                                                name=dst_o_owner),
                                          dst_o_permission, dst_o_grantee,
                                          'object')
        self.swift.register('HEAD', '/v1/AUTH_test/dst_bucket/dst_obj',
                            swob.HTTPOk, dst_o_headers, None)

        self.swift.register('PUT', '/v1/AUTH_test/dst_bucket/dst_obj',
                            swob.HTTPCreated, {}, None)

        req = Request.blank(
            '/dst_bucket/dst_obj',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'X-Amz-Copy-Source': '/src_bucket/src_obj'})

        return self.call_swift3(req)

    def test_object_PUT_copy_with_owner_permission(self):
        status, headers, body = \
            self._test_object_copy()
        self.assertEquals(status.split()[0], '200')

    def test_object_PUT_copy_with_fullcontrol_permission(self):
        status, headers, body = \
            self._test_object_copy(src_owner='test:other',
                                   src_permission='FULL_CONTROL',
                                   dst_c_owner='test:other',
                                   dst_c_permission='FULL_CONTROL',
                                   dst_o_owner='test:other',
                                   dst_o_permission='FULL_CONTROL')
        self.assertEquals(status.split()[0], '200')

    def test_object_PUT_copy_with_grantee_permission(self):
        status, headers, body = \
            self._test_object_copy(src_owner='test:other',
                                   src_permission='READ',
                                   dst_c_owner='test:other',
                                   dst_c_permission='WRITE',
                                   dst_o_owner='test:other',
                                   dst_o_permission='WRITE')
        self.assertEquals(status.split()[0], '200')

    def test_object_PUT_copy_without_src_obj_permission(self):
        status, headers, body = \
            self._test_object_copy(src_owner='test:other')
        self.assertEquals(status.split()[0], '403')

    def test_object_PUT_copy_without_dst_container_permission(self):
        status, headers, body = \
            self._test_object_copy(dst_c_owner='test:other')
        self.assertEquals(status.split()[0], '403')

    def test_object_PUT_copy_without_dst_obj_permission(self):
        status, headers, body = \
            self._test_object_copy(dst_o_owner='test:other')
        self.assertEquals(status.split()[0], '403')

if __name__ == '__main__':
    unittest.main()
