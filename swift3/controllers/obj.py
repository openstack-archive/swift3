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

import sys

from swift.common.http import HTTP_OK, HTTP_PARTIAL_CONTENT
from swift.common.swob import Range, content_range_header_value
from swift.common.utils import split_path

from swift3.controllers.base import Controller
from swift3.response import (S3NotImplemented, InvalidRange, NoSuchKey,
                             InvalidRequest)


class ObjectController(Controller):
    """
    Handles requests on objects
    """
    def _gen_head_range_resp(self, req_range, resp):
        """
        Swift doesn't handle Range header for HEAD requests.
        So, this mothod generates HEAD range response from HEAD response.
        S3 return HEAD range response, if the value of range satisfies the
        conditions which are described in the following document.
        - http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.35
        """
        length = long(resp.headers.get('Content-Length'))

        try:
            content_range = Range(req_range)
        except ValueError:
            return resp

        ranges = content_range.ranges_for_length(length)
        if ranges == []:
            raise InvalidRange()
        elif ranges:
            if len(ranges) == 1:
                start, end = ranges[0]
                resp.headers['Content-Range'] = \
                    content_range_header_value(start, end, length)
                resp.headers['Content-Length'] = (end - start)
                resp.status = HTTP_PARTIAL_CONTENT
                return resp
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
            req_range = req.headers['range']
            resp = self._gen_head_range_resp(req_range, resp)

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
        last_modified = req.check_copy_source(self.app)

        if 'X-Amz-Copy-Source' in req.headers:
            source_container, source_obj = \
                split_path(req.headers['X-Amz-Copy-Source'], 1, 2, True)

            if (req.container_name == source_container and
                    req.object_name == source_obj):
                if req.headers.get('x-amz-metadata-directive',
                                   'COPY') == 'COPY':
                    raise InvalidRequest("This copy request is illegal "
                                         "because it is trying to copy an "
                                         "object to itself without changing "
                                         "the object's metadata, storage "
                                         "class, website redirect location or "
                                         "encryption attributes.")

        resp = req.get_response(self.app)

        if 'X-Amz-Copy-Source' in req.headers:
            resp.append_copy_resp_body(req.controller_name,
                                       last_modified)

        resp.status = HTTP_OK
        return resp

    def POST(self, req):
        raise S3NotImplemented()

    def DELETE(self, req):
        """
        Handle DELETE Object request
        """
        try:
            resp = req.get_response(self.app)
        except NoSuchKey:
            # expect to raise NoSuchBucket when the bucket doesn't exist
            exc_type, exc_value, exc_traceback = sys.exc_info()
            req.get_container_info(self.app)
            raise exc_type, exc_value, exc_traceback
        return resp
