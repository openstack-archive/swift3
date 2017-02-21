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

from swift.common.http import HTTP_OK, HTTP_PARTIAL_CONTENT, HTTP_NO_CONTENT, \
    HTTP_NOT_FOUND
from swift.common.middleware.versioned_writes import \
    DELETE_MARKER_CONTENT_TYPE
from swift.common.swob import Range, content_range_header_value
from swift.common.utils import public, json

from swift3.utils import S3Timestamp, VERSIONING_SUFFIX, versioned_object_name
from swift3.controllers.base import Controller
from swift3.response import S3NotImplemented, InvalidRange, NoSuchKey, \
    InvalidArgument


class ObjectController(Controller):
    """
    Handles requests on objects
    """
    def _gen_head_range_resp(self, req_range, resp):
        """
        Swift doesn't handle Range header for HEAD requests.
        So, this method generates HEAD range response from HEAD response.
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
        object_name = req.object_name
        version_id = req.params.get('versionId')
        if version_id and version_id != 'null':
            # get a specific version in the versioning container
            req.container_name += VERSIONING_SUFFIX
            req.object_name = versioned_object_name(
                req.object_name, req.params.pop('versionId'))

        try:
            resp = req.get_response(self.app)
        except NoSuchKey:
            resp = None
            if version_id and version_id != 'null':
                # if the specific version is not in the versioning container,
                # it might be the current version
                req.container_name = req.container_name[
                    :-len(VERSIONING_SUFFIX)]
                info = req.get_object_info(self.app, object_name=object_name)
                if info.get('meta', {}).get('versionid') == version_id:
                    req.object_name = object_name
                    resp = req.get_response(self.app)
            if resp is None:
                raise

        if req.method == 'HEAD':
            resp.app_iter = None

        if 'x-amz-meta-deleted' in resp.headers:
            raise NoSuchKey(object_name)

        for key in ('content-type', 'content-language', 'expires',
                    'cache-control', 'content-disposition',
                    'content-encoding'):
            if 'response-' + key in req.params:
                resp.headers[key] = req.params['response-' + key]

        return resp

    @public
    def HEAD(self, req):
        """
        Handle HEAD Object request
        """
        resp = self.GETorHEAD(req)

        if 'range' in req.headers:
            req_range = req.headers['range']
            resp = self._gen_head_range_resp(req_range, resp)

        return resp

    @public
    def GET(self, req):
        """
        Handle GET Object request
        """
        return self.GETorHEAD(req)

    @public
    def PUT(self, req):
        """
        Handle PUT Object and PUT Object (Copy) request
        """
        # set X-Timestamp by swift3 to use at copy resp body
        req_timestamp = S3Timestamp.now()
        req.headers['X-Timestamp'] = req_timestamp.internal
        if all(h in req.headers
               for h in ('X-Amz-Copy-Source', 'X-Amz-Copy-Source-Range')):
            raise InvalidArgument('x-amz-copy-source-range',
                                  req.headers['X-Amz-Copy-Source-Range'],
                                  'Illegal copy header')
        req.check_copy_source(self.app)
        resp = req.get_response(self.app)

        if 'X-Amz-Copy-Source' in req.headers:
            resp.append_copy_resp_body(req.controller_name,
                                       req_timestamp.s3xmlformat)

            # delete object metadata from response
            for key in list(resp.headers.keys()):
                if key.startswith('x-amz-meta-'):
                    del resp.headers[key]

        resp.status = HTTP_OK
        return resp

    @public
    def POST(self, req):
        raise S3NotImplemented()

    def _restore_data(self, req, version_to_restore):
        req.object_name = version_to_restore['name']
        name, version_id = req.object_name[3:].rsplit('/', 1)
        resp = req.get_response(self.app, 'GET')

        if resp.status_int == HTTP_NOT_FOUND:
            return resp

        resp.headers['X-Object-Meta-VersionId'] = version_id

        req.container_name = req.container_name[:-len(VERSIONING_SUFFIX)]
        req.object_name = name
        for header, value in resp.headers.items():
            if header.lower() != 'x-timestamp':
                if value.startswith('"'):
                    # remove the double quotes around the value
                    value = value[1:-1]
                req.headers[header] = value

        resp = req.get_response(self.app, 'PUT', body=resp.body)

        return resp

    def _delete_and_restore(self, req, query, etag):
        container_name = req.container_name
        object_name = req.object_name

        req.container_name = container_name + VERSIONING_SUFFIX
        req.object_name = None
        versioned_objects = json.loads(req.get_response(
            self.app, 'GET', query={
                'prefix': versioned_object_name(object_name),
                'reverse': 'true',
                'format': 'json',
            }).body)

        for version_to_restore in versioned_objects:
            if version_to_restore['content_type'] == \
                    DELETE_MARKER_CONTENT_TYPE:
                continue
            resp = self._restore_data(req, version_to_restore)
            if resp:
                break
        else:
            version_to_restore = None

        if version_to_restore:
            # delete the object from the versioning container after copying it
            req.container_name = container_name + VERSIONING_SUFFIX
            req.object_name = version_to_restore['name']
        else:
            # delete the current object if there is nothing to restore
            req.container_name = container_name
            req.object_name = object_name
            # store the original hash value so we know to delete this later
            req.headers['X-Object-Meta-DeletedHash'] = etag
            req.get_response(self.app, 'PUT')
            info = req.get_object_info(self.app)

        resp = req.get_response(self.app, 'DELETE')

        # an extra object is created in the versioning container
        req.container_name = container_name + VERSIONING_SUFFIX
        req.object_name = None
        versioned_objects = json.loads(req.get_response(
            self.app, 'GET', query={
                'prefix': versioned_object_name(object_name),
                'reverse': 'true',
                'format': 'json',
            }).body)

        deleted_etags = {vo['hash']: vo['name']
                         for vo in versioned_objects
                         if vo['content_type'] == DELETE_MARKER_CONTENT_TYPE}

        for vo in versioned_objects:
            if vo['hash'] == etag:
                req.object_name = vo['name']
                resp = req.get_response(self.app, 'DELETE')
            elif vo['hash'] in deleted_etags:
                info = req.get_object_info(self.app, object_name=vo['name'])
                if info.get('meta', {}).get('deletedhash') == etag:
                    # delete the delete marker
                    req.object_name = deleted_etags[vo['hash']]
                    req.get_response(self.app, 'DELETE')
                    # delete the version created by adding the deletedhash
                    # metadata
                    req.object_name = vo['name']
                    resp = req.get_response(self.app, 'DELETE')

        req.container_name = container_name
        return resp

    def _delete_version(self, req, query):
        info = req.get_object_info(self.app)
        version_id = info.get('meta', {}).get('versionid', 'null')

        if version_id == req.params.get('versionId'):
            if info['type'] == DELETE_MARKER_CONTENT_TYPE:
                # if the object is already marked as deleted, just delete it
                resp = req.get_response(self.app, query=query)
            else:
                resp = self._delete_and_restore(req, query, info['etag'])
        else:
            # delete the specific version in the versioning container
            req.container_name += VERSIONING_SUFFIX
            req.object_name = versioned_object_name(
                req.object_name, req.params['versionId'])

            resp = req.get_response(self.app, query=query)

        resp.status = HTTP_NO_CONTENT
        resp.body = ''

        return resp

    @public
    def DELETE(self, req):
        """
        Handle DELETE Object request
        """
        try:
            query = req.gen_multipart_manifest_delete_query(self.app)
            req.headers['Content-Type'] = None  # Ignore client content-type

            if req.params.get('versionId'):
                resp = self._delete_version(req, query)
            else:
                resp = req.get_response(self.app, query=query)

            if query and resp.status_int == HTTP_OK:
                for chunk in resp.app_iter:
                    pass  # drain the bulk-deleter response
                resp.status = HTTP_NO_CONTENT
                resp.body = ''
        except NoSuchKey:
            # expect to raise NoSuchBucket when the bucket doesn't exist
            exc_type, exc_value, exc_traceback = sys.exc_info()
            req.get_container_info(self.app)
            raise exc_type, exc_value, exc_traceback
        return resp
