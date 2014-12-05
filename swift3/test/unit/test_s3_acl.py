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
    AuthenticatedUsers, AllUsers, Owner, Grant, PERMISSIONS
from swift3.test.unit.test_middleware import Swift3TestCase
from swift3.cfg import CONF

XMLNS_XSI = 'http://www.w3.org/2001/XMLSchema-instance'


def _gen_test_headers(owner, grants=[], resource='container'):
    if not grants:
        grants = [Grant(User('test:tester'), 'FULL_CONTROL')]
    return encode_acl(resource, ACL(owner, grants))


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


def generate_s3acl_environ(account, swift, owner):

    def gen_grant(permission):
        # generate Grant with a grantee named by "permission"
        account_name = '%s:%s' % (account, permission.lower())
        return Grant(User(account_name), permission)

    grants = map(gen_grant, PERMISSIONS)
    container_headers = _gen_test_headers(owner, grants)
    object_headers = _gen_test_headers(owner, grants, 'object')

    # TEST method is used to resolve a tenant name
    swift.register('TEST', '/v1/AUTH_test', swob.HTTPMethodNotAllowed,
                   {}, None)
    swift.register('TEST', '/v1/AUTH_X', swob.HTTPMethodNotAllowed,
                   {}, None)

    # for bucket
    swift.register('HEAD', '/v1/AUTH_test/bucket', swob.HTTPNoContent,
                   container_headers, None)
    swift.register('PUT', '/v1/AUTH_test/bucket',
                   swob.HTTPCreated, {}, None)
    swift.register('GET', '/v1/AUTH_test/bucket', swob.HTTPNoContent,
                   container_headers, json.dumps([]))
    swift.register('POST', '/v1/AUTH_test/bucket',
                   swob.HTTPNoContent, {}, None)
    swift.register('DELETE', '/v1/AUTH_test/bucket',
                   swob.HTTPNoContent, {}, None)

    # necessary for canned-acl tests
    public_headers = _gen_test_headers(owner, [Grant(AllUsers(), 'READ')])
    swift.register('GET', '/v1/AUTH_test/public', swob.HTTPNoContent,
                   public_headers, json.dumps([]))
    authenticated_headers = _gen_test_headers(
        owner, [Grant(AuthenticatedUsers(), 'READ')], 'bucket')
    swift.register('GET', '/v1/AUTH_test/authenticated',
                   swob.HTTPNoContent, authenticated_headers,
                   json.dumps([]))

    # for object
    swift.register('HEAD', '/v1/AUTH_test/bucket/object', swob.HTTPOk,
                   object_headers, None)


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

        account = 'test'
        owner_name = '%s:tester' % account
        self.default_owner = Owner(owner_name, owner_name)
        generate_s3acl_environ(account, self.swift, self.default_owner)

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

    def _test_bucket_acl_GET(self, account):
        req = Request.blank('/bucket?acl',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS %s:hmac' % account})
        return self.call_swift3(req)

    def test_bucket_acl_GET_without_permission(self):
        status, headers, body = self._test_bucket_acl_GET('test:other')
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_bucket_acl_GET_with_read_acp_permission(self):
        status, headers, body = self._test_bucket_acl_GET('test:read_acp')
        self.assertEquals(status.split()[0], '200')

    def test_bucket_acl_GET_with_fullcontrol_permission(self):
        status, headers, body = self._test_bucket_acl_GET('test:full_control')
        self.assertEquals(status.split()[0], '200')

    def test_bucket_acl_GET_with_owner_permission(self):
        status, headers, body = self._test_bucket_acl_GET('test:tester')
        self.assertEquals(status.split()[0], '200')

    def _test_bucket_acl_PUT(self, account, permission='FULL_CONTROL'):
        acl = ACL(self.default_owner, [Grant(User(account), permission)])
        req = Request.blank('/bucket?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS %s:hmac' % account},
                            body=tostring(acl.elem()))

        return self.call_swift3(req)

    def test_bucket_acl_PUT_without_permission(self):
        status, headers, body = self._test_bucket_acl_PUT('test:other')
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_bucket_acl_PUT_with_write_acp_permission(self):
        status, headers, body = self._test_bucket_acl_PUT('test:write_acp')
        self.assertEquals(status.split()[0], '200')

    def test_bucket_acl_PUT_with_fullcontrol_permission(self):
        status, headers, body = self._test_bucket_acl_PUT('test:full_control')
        self.assertEquals(status.split()[0], '200')

    def test_bucket_acl_PUT_with_owner_permission(self):
        status, headers, body = self._test_bucket_acl_PUT('test:tester')
        self.assertEquals(status.split()[0], '200')

    def _test_object_acl_GET(self, account):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS %s:hmac' % account})
        return self.call_swift3(req)

    def test_object_acl_GET_without_permission(self):
        status, headers, body = self._test_object_acl_GET('test:other')
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_object_acl_GET_with_read_acp_permission(self):
        status, headers, body = self._test_object_acl_GET('test:read_acp')
        self.assertEquals(status.split()[0], '200')

    def test_object_acl_GET_with_fullcontrol_permission(self):
        status, headers, body = self._test_object_acl_GET('test:full_control')
        self.assertEquals(status.split()[0], '200')

    def test_object_acl_GET_with_owner_permission(self):
        status, headers, body = self._test_object_acl_GET('test:tester')
        self.assertEquals(status.split()[0], '200')

    def _test_object_acl_PUT(self, account, permission='FULL_CONTROL'):
        acl = ACL(self.default_owner, [Grant(User(account), permission)])
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS %s:hmac' % account},
                            body=tostring(acl.elem()))

        return self.call_swift3(req)

    def test_object_acl_PUT_without_permission(self):
        status, headers, body = self._test_object_acl_PUT('test:other')
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_object_acl_PUT_with_write_acp_permission(self):
        status, headers, body = self._test_object_acl_PUT('test:write_acp')
        self.assertEquals(status.split()[0], '200')

    def test_object_acl_PUT_with_fullcontrol_permission(self):
        status, headers, body = self._test_object_acl_PUT('test:full_control')
        self.assertEquals(status.split()[0], '200')

    def test_object_acl_PUT_with_owner_permission(self):
        status, headers, body = self._test_object_acl_PUT('test:tester')
        self.assertEquals(status.split()[0], '200')

    """
    [BucketController] Case: Conf.s3_acl == True
    """
    def _test_bucket(self, method, account):
        req = Request.blank('/bucket',
                            environ={'REQUEST_METHOD': method},
                            headers={'Authorization': 'AWS %s:hmac' % account})

        return self.call_swift3(req)

    def test_bucket_GET_without_permission(self):
        status, headers, body = self._test_bucket('GET', 'test:other')
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_bucket_GET_with_read_permission(self):
        status, headers, body = self._test_bucket('GET', 'test:read')
        self.assertEquals(status.split()[0], '200')

    def test_bucket_GET_with_fullcontrol_permission(self):
        status, headers, body = self._test_bucket('GET', 'test:full_control')
        self.assertEquals(status.split()[0], '200')

    def test_bucket_GET_with_owner_permission(self):
        status, headers, body = self._test_bucket('GET', 'test:tester')
        self.assertEquals(status.split()[0], '200')

    def _test_bucket_GET_canned_acl(self, bucket):
        req = Request.blank('/%s' % bucket,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})

        return self.call_swift3(req)

    def test_bucket_GET_authenticated_users(self):
        status, headers, body = \
            self._test_bucket_GET_canned_acl('authenticated')
        self.assertEquals(status.split()[0], '200')

    def test_bucket_GET_all_users(self):
        status, headers, body = self._test_bucket_GET_canned_acl('public')
        self.assertEquals(status.split()[0], '200')

    def test_bucket_PUT_with_already_exist(self):
        self.swift.register('PUT', '/v1/AUTH_test/bucket',
                            swob.HTTPAccepted, {}, None)
        status, headers, body = self._test_bucket('PUT', 'test:tester')
        self.assertEquals(self._get_error_code(body), 'BucketAlreadyExists')

    def test_bucket_PUT(self):
        status, headers, body = self._test_bucket('PUT', 'test:tester')
        self.assertEquals(status.split()[0], '200')

    def test_bucket_DELETE_without_permission(self):
        status, headers, body = self._test_bucket('DELETE', 'test:other')
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_bucket_DELETE_with_write_permission(self):
        status, headers, body = self._test_bucket('DELETE', 'test:write')
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_bucket_DELETE_with_fullcontrol_permission(self):
        status, headers, body = self._test_bucket('DELETE',
                                                  'test:full_control')
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_bucket_DELETE_with_owner_permission(self):
        status, headers, body = self._test_bucket('DELETE', 'test:tester')
        self.assertEquals(status.split()[0], '204')

    """
    [Object Controller] Case: Conf.s3_acl == True
    """

    def _test_object(self, method, account, existObject=True):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': method},
                            headers={'Authorization': 'AWS %s:hmac' % account})
        return self.call_swift3(req)

    def test_object_GET_without_permission(self):
        status, headers, body = self._test_object('GET', 'test:other', None)
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_object_GET_with_read_permission(self):
        status, headers, body = self._test_object('GET', 'test:read')
        self.assertEquals(status.split()[0], '200')

    def test_object_GET_with_fullcontrol_permission(self):
        status, headers, body = self._test_object('GET', 'test:full_control')
        self.assertEquals(status.split()[0], '200')

    def test_object_GET_with_owner_permission(self):
        status, headers, body = self._test_object('GET', 'test:tester')
        self.assertEquals(status.split()[0], '200')

    def test_object_PUT_without_permission(self):
        status, headers, body = self._test_object('PUT', 'test:other')
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_object_PUT_with_write_permission(self):
        status, headers, body = self._test_object('PUT', 'test:write')
        self.assertEquals(status.split()[0], '200')

    def test_object_PUT_with_fullcontrol_permission(self):
        status, headers, body = self._test_object('PUT', 'test:full_control')
        self.assertEquals(status.split()[0], '200')

    def test_object_PUT_with_owner_permission(self):
        status, headers, body = self._test_object('PUT', 'test:tester')
        self.assertEquals(status.split()[0], '200')

    def test_object_PUT_without_overwriting_permission(self):
        status, headers, body = self._test_object('PUT', 'test:other')
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_object_PUT_with_overwriting_permission(self):
        # FIXME: handle object existence
        status, headers, body = self._test_object('PUT', 'test:write')
        self.assertEquals(status.split()[0], '200')

    def test_object_DELETE_without_permission(self):
        status, headers, body = self._test_object('DELETE', 'test:read')
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_object_DELETE_with_write_permission(self):
        status, headers, body = self._test_object('DELETE', 'test:write')
        self.assertEquals(status.split()[0], '204')

    def test_object_DELETE_with_fullcontrol_permission(self):
        status, headers, body = self._test_object('DELETE',
                                                  'test:full_control')
        self.assertEquals(status.split()[0], '204')

    def test_object_DELETE_with_owner_permission(self):
        status, headers, body = self._test_object('DELETE', 'test:tester')
        self.assertEquals(status.split()[0], '204')

    def _test_object_copy(self, account, src_permission=None):
        grants = [Grant(User(account), src_permission)] \
            if src_permission else []
        src_o_headers = _gen_test_headers(self.default_owner, grants, 'object')
        self.swift.register('HEAD', '/v1/AUTH_test/src_bucket/src_obj',
                            swob.HTTPOk, src_o_headers, None)

        req = Request.blank(
            '/bucket/object',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'Authorization': 'AWS %s:hmac' % account,
                     'X-Amz-Copy-Source': '/src_bucket/src_obj'})

        return self.call_swift3(req)

    def test_object_PUT_copy_with_owner_permission(self):
        status, headers, body = \
            self._test_object_copy('test:tester')
        self.assertEquals(status.split()[0], '200')

    def test_object_PUT_copy_with_fullcontrol_permission(self):
        status, headers, body = \
            self._test_object_copy('test:full_control', 'FULL_CONTROL')
        self.assertEquals(status.split()[0], '200')

    def test_object_PUT_copy_with_grantee_permission(self):
        status, headers, body = \
            self._test_object_copy('test:write', 'READ')
        self.assertEquals(status.split()[0], '200')

    def test_object_PUT_copy_without_src_obj_permission(self):
        status, headers, body = \
            self._test_object_copy('test:write')
        self.assertEquals(status.split()[0], '403')

    def test_object_PUT_copy_without_dst_container_permission(self):
        status, headers, body = \
            self._test_object_copy('test:other', 'READ')
        self.assertEquals(status.split()[0], '403')

    def test_object_PUT_copy_without_dst_obj_permission(self):
        headers = _gen_test_headers(self.default_owner,
                                    [Grant(User('test:other'), 'WRITE')])
        self.swift.register('HEAD', '/v1/AUTH_test/bucket',
                            swob.HTTPNoContent, headers, None)
        status, headers, body = \
            self._test_object_copy('test:other', 'READ')
        self.assertEquals(status.split()[0], '403')

if __name__ == '__main__':
    unittest.main()
