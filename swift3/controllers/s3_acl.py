# Copyright (c) 2014 OpenStack Foundation.
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

from urllib import quote

from swift3.controllers.base import Controller
from swift3.response import HTTPOk, MissingSecurityHeader, \
    UnexpectedContent, MalformedACLError
from swift3.etree import fromstring, tostring, XMLSyntaxError, DocumentInvalid
from swift3.subresource import ACL
from swift3.utils import LOGGER


def get_acl(headers, body, bucket_owner, object_owner=None):
    """
    Get ACL instance from S3 (e.g. x-amz-grant) headers or S3 acl xml body.
    """
    acl = ACL.from_headers(headers, bucket_owner, object_owner,
                           as_private=False)

    if acl is None:
        # Get acl from request body if possible.
        if not body:
            msg = 'Your request was missing a required header'
            raise MissingSecurityHeader(msg, missing_header_name='x-amz-acl')
        try:
            elem = fromstring(body, ACL.root_tag)
            acl = ACL.from_elem(elem)
        except(XMLSyntaxError, DocumentInvalid):
            raise MalformedACLError()
        except Exception as e:
            LOGGER.error(e)
            raise
    else:
        if body:
            # Specifying grant with both header and xml is not allowed.
            raise UnexpectedContent

    return acl


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
        resp = req.get_response(self.app, 'HEAD', permission='READ_ACP')
        acl = getattr(resp, '%s_acl' %
                      ('object' if req.is_object_request else 'bucket'))

        resp = HTTPOk()
        resp.body = tostring(acl.elem())

        return resp

    def PUT(self, req):
        """
        Handles PUT Bucket acl and PUT Object acl.
        """
        if req.is_object_request:
            b_resp = req.get_response(self.app, 'HEAD', obj='',
                                      skip_check=True)
            o_resp = req.get_response(self.app, 'HEAD', permission='WRITE_ACP')
            req_acl = get_acl(req.headers, req.xml(ACL.max_xml_length),
                              b_resp.bucket_acl.owner,
                              o_resp.object_acl.owner)

            # Don't change the owner of the resource by PUT acl request.
            o_resp.object_acl.check_owner(req_acl.owner.id)

            for g in req_acl.grants:
                LOGGER.debug('Grant %s %s permission on the object /%s/%s' %
                             (g.grantee, g.permission, req.container_name,
                              req.object_name))
            req.object_acl = req_acl
            headers = {}
            src_path = '/%s/%s' % (req.container_name, req.object_name)

            # object-sysmeta' can be updated by 'Copy' method,
            # but can not be by 'POST' method.
            # So headers['X-Copy-From'] for copy request is added here.
            headers['X-Copy-From'] = quote(src_path)
            headers['Content-Length'] = 0
            req.get_response(self.app, 'PUT', headers=headers,
                             skip_check=True)
        else:
            resp = req.get_response(self.app, 'HEAD', permission='WRITE_ACP')

            req_acl = get_acl(req.headers, req.xml(ACL.max_xml_length),
                              resp.bucket_acl.owner)

            # Don't change the owner of the resource by PUT acl request.
            resp.bucket_acl.check_owner(req_acl.owner.id)

            for g in req_acl.grants:
                LOGGER.debug('Grant %s %s permission on the bucket /%s' %
                             (g.grantee, g.permission, req.container_name))

            req.bucket_acl = req_acl
            req.get_response(self.app, 'POST', skip_check=True)

        return HTTPOk()
