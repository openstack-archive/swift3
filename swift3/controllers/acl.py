# Copyright (c) 2010-2014 OpenStack Foundation.
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

from swift.common.http import HTTP_OK
from swift.common.middleware.acl import parse_acl, referrer_allowed

from swift3.controllers.base import Controller
from swift3.response import HTTPOk, S3NotImplemented, MalformedACLError
from swift3.etree import Element, SubElement, fromstring, tostring, \
    DocumentInvalid

XMLNS_XSI = 'http://www.w3.org/2001/XMLSchema-instance'


def add_canonical_user(parent, tag, user, nsmap=None):
    """
    Create an element for cannonical user.
    """
    elem = SubElement(parent, tag, nsmap=nsmap)
    SubElement(elem, 'ID').text = user
    SubElement(elem, 'DisplayName').text = user

    return elem


def get_acl(account_name, headers):
    """
    Attempts to construct an S3 ACL based on what is found in the swift headers
    """

    elem = Element('AccessControlPolicy')
    add_canonical_user(elem, 'Owner', account_name)
    access_control_list = SubElement(elem, 'AccessControlList')

    # grant FULL_CONTROL to myself by default
    grant = SubElement(access_control_list, 'Grant')
    grantee = add_canonical_user(grant, 'Grantee', account_name,
                                 nsmap={'xsi': XMLNS_XSI})
    grantee.set('{%s}type' % XMLNS_XSI, 'CanonicalUser')
    SubElement(grant, 'Permission').text = 'FULL_CONTROL'

    referrers, _ = parse_acl(headers.get('x-container-read'))
    if referrer_allowed('unknown', referrers):
        # grant public-read access
        grant = SubElement(access_control_list, 'Grant')
        grantee = SubElement(grant, 'Grantee', nsmap={'xsi': XMLNS_XSI})
        grantee.set('{%s}type' % XMLNS_XSI, 'Group')
        SubElement(grantee, 'URI').text = \
            'http://acs.amazonaws.com/groups/global/AllUsers'
        SubElement(grant, 'Permission').text = 'READ'

    referrers, _ = parse_acl(headers.get('x-container-write'))
    if referrer_allowed('unknown', referrers):
        # grant public-write access
        grant = SubElement(access_control_list, 'Grant')
        grantee = SubElement(grant, 'Grantee', nsmap={'xsi': XMLNS_XSI})
        grantee.set('{%s}type' % XMLNS_XSI, 'Group')
        SubElement(grantee, 'URI').text = \
            'http://acs.amazonaws.com/groups/global/AllUsers'
        SubElement(grant, 'Permission').text = 'WRITE'

    body = tostring(elem)

    return HTTPOk(body=body, content_type="text/plain")


def swift_acl_translate(acl, group='', user='', xml=False):
    """
    Takes an S3 style ACL and returns a list of header/value pairs that
    implement that ACL in Swift, or "NotImplemented" if there isn't a way to do
    that yet.
    """
    swift_acl = {}
    swift_acl['public-read'] = [['HTTP_X_CONTAINER_READ', '.r:*,.rlistings']]
    # Swift does not support public write:
    # https://answers.launchpad.net/swift/+question/169541
    swift_acl['public-read-write'] = [['HTTP_X_CONTAINER_WRITE', '.r:*'],
                                      ['HTTP_X_CONTAINER_READ',
                                       '.r:*,.rlistings']]

    #TODO: if there's a way to get group and user, this should work for
    # private:
    #swift_acl['private'] = [['HTTP_X_CONTAINER_WRITE',  group + ':' + user], \
    #                  ['HTTP_X_CONTAINER_READ', group + ':' + user]]
    swift_acl['private'] = [['HTTP_X_CONTAINER_WRITE', '.'],
                            ['HTTP_X_CONTAINER_READ', '.']]
    if xml:
        # We are working with XML and need to parse it
        try:
            elem = fromstring(acl, 'AccessControlPolicy')
        except DocumentInvalid:
            raise MalformedACLError()
        acl = 'unknown'
        for grant in elem.findall('./AccessControlList/Grant'):
            permission = grant.find('./Permission').text
            grantee = grant.find('./Grantee').get('{%s}type' % XMLNS_XSI)
            if permission == "FULL_CONTROL" and grantee == 'CanonicalUser' and\
                    acl != 'public-read' and acl != 'public-read-write':
                acl = 'private'
            elif permission == "READ" and grantee == 'Group' and\
                    acl != 'public-read-write':
                acl = 'public-read'
            elif permission == "WRITE" and grantee == 'Group':
                acl = 'public-read-write'
            else:
                acl = 'unsupported'

    if acl == 'authenticated-read':
        return "NotImplemented"
    elif acl not in swift_acl:
        return "InvalidArgument"

    return swift_acl[acl]


class AclController(Controller):
    """
    Handles the following APIs:

     - GET Bucket acl
     - PUT Bucket acl
     - GET Object acl
     - PUT Object acl

    Those APIs are logged as ACL operations in the S3 server log.
    """
    def GET(self, req):
        """
        Handles GET Bucket acl and GET Object acl.
        """
        resp = req.get_response(self.app, method='HEAD')

        return get_acl(req.user_id, resp.headers)

    def PUT(self, req):
        """
        Handles PUT Bucket acl and PUT Object acl.
        """
        if req.object_name:
            # Handle Object ACL
            raise S3NotImplemented()
        else:
            # Handle Bucket ACL

            # We very likely have an XML-based ACL request.
            translated_acl = swift_acl_translate(req.body, xml=True)
            if translated_acl == 'NotImplemented':
                raise S3NotImplemented()
            elif translated_acl == 'InvalidArgument':
                raise MalformedACLError()
            for header, acl in translated_acl:
                req.headers[header] = acl

            resp = req.get_response(self.app)
            resp.status = HTTP_OK
            resp.headers.update({'Location': req.container_name})

            return resp
