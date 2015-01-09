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

from swift3.exception import ACLError
from swift3.controllers.base import Controller
from swift3.response import HTTPOk, S3NotImplemented, MalformedACLError, \
    InvalidArgument, UnexpectedContent
from swift3.etree import Element, SubElement, fromstring, tostring, \
    XMLSyntaxError, DocumentInvalid
from swift3.cfg import CONF

XMLNS_XSI = 'http://www.w3.org/2001/XMLSchema-instance'

MAX_ACL_BODY_SIZE = 200 * 1024


def get_acl(account_name, headers):
    """
    Attempts to construct an S3 ACL based on what is found in the swift headers
    """

    elem = Element('AccessControlPolicy')
    owner = SubElement(elem, 'Owner')
    SubElement(owner, 'ID').text = account_name
    SubElement(owner, 'DisplayName').text = account_name
    access_control_list = SubElement(elem, 'AccessControlList')

    # grant FULL_CONTROL to myself by default
    grant = SubElement(access_control_list, 'Grant')
    grantee = SubElement(grant, 'Grantee', nsmap={'xsi': XMLNS_XSI})
    grantee.set('{%s}type' % XMLNS_XSI, 'CanonicalUser')
    SubElement(grantee, 'ID').text = account_name
    SubElement(grantee, 'DisplayName').text = account_name
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
    swift_acl['public-read'] = [['X-Container-Read', '.r:*,.rlistings']]
    # Swift does not support public write:
    # https://answers.launchpad.net/swift/+question/169541
    swift_acl['public-read-write'] = [['X-Container-Write', '.r:*'],
                                      ['X-Container-Read',
                                       '.r:*,.rlistings']]

    # TODO: if there's a way to get group and user, this should work for
    # private:
    # swift_acl['private'] = \
    #     [['HTTP_X_CONTAINER_WRITE',  group + ':' + user], \
    #      ['HTTP_X_CONTAINER_READ', group + ':' + user]]
    swift_acl['private'] = [['X-Container-Write', '.'],
                            ['X-Container-Read', '.']]
    if xml:
        # We are working with XML and need to parse it
        try:
            elem = fromstring(acl, 'AccessControlPolicy')
        except (XMLSyntaxError, DocumentInvalid):
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
        raise S3NotImplemented()
    elif acl not in swift_acl:
        raise ACLError()

    return swift_acl[acl]


def handle_acl_header(req):
    """
    Handle the x-amz-acl header.
    """
    # Used this method, delete 'HTTP_X_AMZ_ACL' from environ, and header for
    # s3_acl(x-container-sysmeta-swift3-acl) becomes impossible to create.
    # TODO: Modify to be able to use the s3_acl and swift acl
    # (e.g. X-Container-Read) at the same time, if s3_acl is effective.
    if CONF.s3_acl:
        return

    amz_acl = req.environ['HTTP_X_AMZ_ACL']
    # Translate the Amazon ACL to something that can be
    # implemented in Swift, 501 otherwise. Swift uses POST
    # for ACLs, whereas S3 uses PUT.
    del req.environ['HTTP_X_AMZ_ACL']
    if req.query_string:
        req.query_string = ''

    try:
        translated_acl = swift_acl_translate(amz_acl)
    except ACLError:
        raise InvalidArgument('x-amz-acl', amz_acl)

    for header, acl in translated_acl:
        req.headers[header] = acl


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
        if req.is_object_request:
            # Handle Object ACL
            raise S3NotImplemented()
        else:
            # Handle Bucket ACL
            xml = req.xml(MAX_ACL_BODY_SIZE)
            if 'HTTP_X_AMZ_ACL' in req.environ and xml:
                # S3 doesn't allow to give ACL with both ACL header and body.
                raise UnexpectedContent()
            elif 'HTTP_X_AMZ_ACL' in req.environ:
                handle_acl_header(req)
            elif xml:
                # We very likely have an XML-based ACL request.
                try:
                    translated_acl = swift_acl_translate(xml, xml=True)
                except ACLError:
                    raise MalformedACLError()

                for header, acl in translated_acl:
                    req.headers[header] = acl

            resp = req.get_response(self.app, 'POST')
            resp.status = HTTP_OK
            resp.headers.update({'Location': req.container_name})

            return resp
