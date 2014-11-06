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

from swift3.controllers.acl import handle_acl_header
from swift3.controllers.base import Controller
from swift3.response import AccessDenied, HTTPOk, NoSuchKey
from swift3.etree import Element, SubElement, tostring
from swift3.subresource import ACL, ACLPrivate, Owner
from swift3.cfg import CONF


class ObjectController(Controller):
    """
    Handles requests on objects
    """
    def GETorHEAD(self, req):
        resp = req.get_response(self.app)
        resp.object_acl.check_permission(req.user_id, 'READ')

        if req.method == 'HEAD':
            resp.app_iter = None

        for key in ('content-type', 'content-language', 'expires',
                    'cache-control', 'content-disposition',
                    'content-encoding'):
            if 'response-' + key in req.params:
                resp.headers[key] = req.params['response-' + key]

        return resp

    def HEAD(self, req):
        """
        Handle HEAD Object request
        """
        return self.GETorHEAD(req)

    def GET(self, req):
        """
        Handle GET Object request
        """
        return self.GETorHEAD(req)

    def PUT(self, req):
        """
        Handle PUT Object and PUT Object (Copy) request
        """
        b_resp = req.get_response(self.app, 'HEAD', obj='')
        b_resp.bucket_acl.check_permission(req.user_id, 'WRITE')
        # To avoid overwriting the existing object by unauthorized user,
        # we send HEAD request first before writing the object to make
        # sure that the target object does not exist or the user that sent
        # the PUT request have write permission.
        try:
            o_resp = req.get_response(self.app, 'HEAD')
            o_resp.object_acl.check_permission(req.user_id, 'WRITE')
        except NoSuchKey:
            pass

        if CONF.s3_acl:
            acl = ACL.from_headers(req.headers,
                                   Owner(req.user_id, req.user_id))
            if acl is None:
                # The default acl is private.
                acl = ACLPrivate(Owner(req.user_id, req.user_id))

            req.object_acl = acl
            resp = req.get_response(self.app)
        else:
            if 'HTTP_X_AMZ_ACL' in req.environ:
                handle_acl_header(req)

            resp = req.get_response(self.app)

        if 'HTTP_X_COPY_FROM' in req.environ:
            elem = Element('CopyObjectResult')
            SubElement(elem, 'ETag').text = '"%s"' % resp.etag
            body = tostring(elem, use_s3ns=False)
            return HTTPOk(body=body)

        resp.status = HTTP_OK

        return resp

    def POST(self, req):
        raise AccessDenied()

    def DELETE(self, req):
        """
        Handle DELETE Object request
        """
        b_resp = req.get_response(self.app, 'HEAD', obj='')
        b_resp.bucket_acl.check_permission(req.user_id, 'WRITE')

        return req.get_response(self.app)
