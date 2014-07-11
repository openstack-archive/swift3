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

import functools

from swift3.response import S3NotImplemented, InvalidRequest

def bucket_operation(func):
    """
    A decorator to ensure that the request is a bucket operation.
    """
    @functools.wraps(func)
    def wrapped(self, req):
        if req.object_name:
            raise InvalidRequest('The requested sub-resource is not allowed '
                                 'for a key.')

        return func(self, req)

    return wrapped

def object_operation(func):
    """
    A decorator to ensure that the request is an object operation.
    """
    @functools.wraps(func)
    def wrapped(self, req):
        if not req.object_name:
            raise InvalidRequest('A key is not expected for the requested '
                                 'sub-resource.')

        return func(self, req)

    return wrapped


class Controller(object):
    """
    Base WSGI controller class for the middleware
    """
    def __init__(self, app, **kwargs):
        self.app = app


class UnsupportedController(Controller):
    """
    Handles unsupported requests.
    """
    def __init__(self, app, **kwargs):
        raise S3NotImplemented('The requested resource is not implemented')
