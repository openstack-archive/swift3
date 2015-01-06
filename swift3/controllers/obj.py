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

from swift3.controllers.base import Controller
from swift3.response import HTTPOk, S3NotImplemented
from swift3.etree import Element, SubElement, tostring


class ObjectController(Controller):
    """
    Handles requests on objects
    """
    def GETorHEAD(self, req, method=None):
        resp = req.get_response(self.app, method)

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
        method = None
        # Swift doesn't handle Range header for HEAD requests.  We
        # send a GET request and drop the response body.
        if 'range' in req.headers:
            method = 'GET'

        return self.GETorHEAD(req, method)

    def GET(self, req):
        """
        Handle GET Object request
        """
        return self.GETorHEAD(req)

    def PUT(self, req):
        """
        Handle PUT Object and PUT Object (Copy) request
        """
        resp = req.get_response(self.app)

        if 'X-Amz-Copy-Source' in req.headers:
            elem = Element('CopyObjectResult')
            SubElement(elem, 'ETag').text = '"%s"' % resp.etag
            body = tostring(elem, use_s3ns=False)
            return HTTPOk(body=body, headers=resp.headers)

        resp.status = HTTP_OK
        return resp

    def POST(self, req):
        raise S3NotImplemented()

    def DELETE(self, req):
        """
        Handle DELETE Object request
        """
        return req.get_response(self.app)
