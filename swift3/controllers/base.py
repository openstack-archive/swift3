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

from swift.common.http import HTTP_OK, HTTP_CREATED, HTTP_ACCEPTED, \
    HTTP_NO_CONTENT, HTTP_NOT_FOUND, HTTP_CONFLICT, \
    HTTP_UNPROCESSABLE_ENTITY, HTTP_REQUEST_ENTITY_TOO_LARGE, \
    HTTP_NOT_MODIFIED, HTTP_PARTIAL_CONTENT, HTTP_PRECONDITION_FAILED, \
    HTTP_REQUESTED_RANGE_NOT_SATISFIABLE, HTTP_LENGTH_REQUIRED

from swift3.response import BucketAlreadyExists, BucketNotEmpty, \
    EntityTooLarge, InvalidDigest, NoSuchBucket, NoSuchKey, \
    PreconditionFailed, InvalidRange, MissingContentLength


class Controller(object):
    """
    Base WSGI controller class for the middleware
    """
    def __init__(self, app, conf, **kwargs):
        self.app = app
        self.conf = conf

    def get_account(self, req, query=None):
        """
        Sends a GET account request to Swift.
        """
        path = '/v1/%s' % (req.access_key)

        return req.get_response(self.app, 'GET', path, query)

    def head_container(self, req):
        """
        Sends a HEAD container request to Swift.
        """
        path = '/v1/%s/%s' % (req.access_key, req.container_name)
        success = [HTTP_NO_CONTENT]
        error = {
            HTTP_NOT_FOUND: (NoSuchBucket, req.container_name),
        }

        return req.get_response(self.app, 'HEAD', path, success=success,
                                error=error)

    def get_container(self, req, query=None):
        """
        Sends a GET container request to Swift.
        """
        path = '/v1/%s/%s' % (req.access_key, req.container_name)
        success = [HTTP_OK, HTTP_NO_CONTENT]
        error = {
            HTTP_NOT_FOUND: (NoSuchBucket, req.container_name),
        }

        return req.get_response(self.app, 'GET', path, query, success=success,
                                error=error)

    def put_container(self, req, account=None, container=None, headers=None):
        """
        Sends a PUT container request to Swift.
        """
        path = '/v1/%s/%s' % (req.access_key, req.container_name)
        success = [HTTP_CREATED, HTTP_NO_CONTENT]
        error = {
            HTTP_ACCEPTED: (BucketAlreadyExists, req.container_name),
        }

        return req.get_response(self.app, 'PUT', path, success=success,
                                error=error)

    def post_container(self, req, account=None, container=None, headers=None):
        """
        Sends a POST container request to Swift.
        """
        path = '/v1/%s/%s' % (req.access_key, req.container_name)
        success = [HTTP_NO_CONTENT]
        error = {
            HTTP_NOT_FOUND: (NoSuchBucket, req.container_name),
        }

        return req.get_response(self.app, 'POST', path, success=success,
                                error=error)

    def delete_container(self, req):
        """
        Sends a DELETE container request to Swift.
        """
        path = '/v1/%s/%s' % (req.access_key, req.container_name)
        success = [HTTP_NO_CONTENT]
        error = {
            HTTP_NOT_FOUND: (NoSuchBucket, req.container_name),
            HTTP_CONFLICT: BucketNotEmpty,
        }

        return req.get_response(self.app, 'DELETE', path, success=success,
                                error=error)

    def head_object(self, req):
        """
        Sends a HEAD object request to Swift.
        """
        path = '/v1/%s/%s/%s' % (req.access_key, req.container_name,
                                 req.object_name)
        success = [HTTP_OK, HTTP_PARTIAL_CONTENT, HTTP_NOT_MODIFIED]
        error = {
            HTTP_NOT_FOUND: (NoSuchKey, req.object_name),
            HTTP_PRECONDITION_FAILED: PreconditionFailed,
        }

        return req.get_response(self.app, 'HEAD', path, success=success,
                                error=error)

    def get_object(self, req):
        """
        Sends a GET object request to Swift.
        """
        path = '/v1/%s/%s/%s' % (req.access_key, req.container_name,
                                 req.object_name)
        success = [HTTP_OK, HTTP_PARTIAL_CONTENT, HTTP_NOT_MODIFIED]
        error = {
            HTTP_NOT_FOUND: (NoSuchKey, req.object_name),
            HTTP_PRECONDITION_FAILED: PreconditionFailed,
            HTTP_REQUESTED_RANGE_NOT_SATISFIABLE: InvalidRange,
        }

        return req.get_response(self.app, 'GET', path, success=success,
                                error=error)

    def put_object(self, req):
        """
        Sends a PUT object request to Swift.
        """
        path = '/v1/%s/%s/%s' % (req.access_key, req.container_name,
                                 req.object_name)
        success = [HTTP_CREATED]
        error = {
            HTTP_NOT_FOUND: (NoSuchBucket, req.container_name),
            HTTP_UNPROCESSABLE_ENTITY: InvalidDigest,
            HTTP_REQUEST_ENTITY_TOO_LARGE: EntityTooLarge,
            HTTP_LENGTH_REQUIRED: MissingContentLength,
        }

        return req.get_response(self.app, 'PUT', path, success=success,
                                error=error)

    def delete_object(self, req):
        """
        Sends a DELETE object request to Swift.
        """
        path = '/v1/%s/%s/%s' % (req.access_key, req.container_name,
                                 req.object_name)
        success = [HTTP_NO_CONTENT]
        error = {
            HTTP_NOT_FOUND: (NoSuchKey, req.object_name),
        }

        return req.get_response(self.app, 'DELETE', path, success=success,
                                error=error)
