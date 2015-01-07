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
from swift.common.swob import Range, content_range_header_value

from swift3.controllers.base import Controller
from swift3.response import HTTPOk, S3NotImplemented, InvalidRange,\
    HTTPPartialContent
from swift3.etree import Element, SubElement, tostring


class ObjectController(Controller):
    """
    Handles requests on objects
    """
    def _gen_head_range_resp(self, req, resp):
        """
        Swift doesn't handle Range header for HEAD requests.
        So, this mothod generates HEAD range response from HEAD response.
        """
        length = long(resp.headers.get('Content-Length'))
        req_range = req.headers.get('range')

        try:
            range = Range(req_range)
        except ValueError:
            return resp

        ranges = range.ranges_for_length(length)
        if ranges == []:
            raise InvalidRange
        elif ranges:
            if len(ranges) == 1:
                start, end = ranges[0]
                resp.headers['Content-Range'] = \
                    content_range_header_value(start, end, length)
                resp.headers['Content-Length'] = (end - start)
                return HTTPPartialContent(headers=resp.headers)
            else:
                # TODO: It is necessary to confirm whether need to respond to
                #       multi-part response.(e.g. bytes=0-10,20-30)
                pass

        return resp

    def GETorHEAD(self, req):
        resp = req.get_response(self.app)

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
        resp = self.GETorHEAD(req)

        if 'range' in req.headers:
            resp = self._gen_head_range_resp(req, resp)

        return resp

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
