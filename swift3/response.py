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

from functools import partial

from swift.common import swob


class HeaderKey(str):
    """
    A string object that normalizes string as S3 clients expect with title().
    """
    def title(self):
        if self.lower() == 'etag':
            # AWS Java SDK expects only 'ETag'.
            return 'ETag'
        if self.lower().startswith('x-amz-'):
            # AWS headers returned by S3 are lowercase.
            return self.lower()
        if self.lower().startswith('x-rgw-'):
            # ceph/s3tests expects the header is lowercase.
            return self.lower()
        return str.title(self)


class HeaderKeyDict(swob.HeaderKeyDict):
    """
    Similar to the HeaderKeyDict class in Swift, but its key name is normalized
    as S3 clients expect.
    """
    def __getitem__(self, key):
        return swob.HeaderKeyDict.__getitem__(self, HeaderKey(key))

    def __setitem__(self, key, value):
        return swob.HeaderKeyDict.__setitem__(self, HeaderKey(key), value)

    def __contains__(self, key):
        return swob.HeaderKeyDict.__contains__(self, HeaderKey(key))

    def __delitem__(self, key):
        return swob.HeaderKeyDict.__delitem__(self, HeaderKey(key))

    def get(self, key, default=None):
        return swob.HeaderKeyDict.get(self, HeaderKey(key), default)

    def pop(self, key, default=None):
        return swob.HeaderKeyDict.pop(self, HeaderKey(key), default)


class Response(swob.Response):
    """
    Similar to the Response class in Swift, but uses our HeaderKeyDict for
    headers instead of Swift's HeaderKeyDict.  This also translates Swift
    specific headers to S3 headers.
    """
    def __init__(self, *args, **kwargs):
        swob.Response.__init__(self, *args, **kwargs)

        headers = HeaderKeyDict()
        for key, val in self.headers.iteritems():
            _key = key.lower()
            if _key.startswith('x-object-meta-'):
                headers['x-amz-meta-' + key[14:]] = val
            elif _key in ('content-length', 'content-type',
                          'content-range', 'content-encoding',
                          'etag', 'last-modified'):
                headers[key] = val
            elif _key == 'x-container-object-count':
                # for ceph/s3tests
                headers['x-rgw-object-count'] = val
            elif _key == 'x-container-bytes-used':
                # for ceph/s3tests
                headers['x-rgw-bytes-used'] = val

        self.headers = headers


class StatusMap(object):
    """
    Similar to the StatusMap class in Swift, but returns swift3.Response
    subclasses instead of swob.HTTPException.
    """
    def __getitem__(self, key):
        return partial(Response, status=key)

status_map = StatusMap()


HTTPOk = status_map[200]
HTTPCreated = status_map[201]
HTTPAccepted = status_map[202]
HTTPNoContent = status_map[204]
HTTPMovedPermanently = status_map[301]
HTTPFound = status_map[302]
HTTPSeeOther = status_map[303]
HTTPNotModified = status_map[304]
HTTPTemporaryRedirect = status_map[307]
HTTPBadRequest = status_map[400]
HTTPUnauthorized = status_map[401]
HTTPForbidden = status_map[403]
HTTPMethodNotAllowed = status_map[405]
HTTPNotFound = status_map[404]
HTTPNotAcceptable = status_map[406]
HTTPRequestTimeout = status_map[408]
HTTPConflict = status_map[409]
HTTPLengthRequired = status_map[411]
HTTPPreconditionFailed = status_map[412]
HTTPRequestEntityTooLarge = status_map[413]
HTTPRequestedRangeNotSatisfiable = status_map[416]
HTTPUnprocessableEntity = status_map[422]
HTTPClientDisconnect = status_map[499]
HTTPServerError = status_map[500]
HTTPInternalServerError = status_map[500]
HTTPNotImplemented = status_map[501]
HTTPBadGateway = status_map[502]
HTTPServiceUnavailable = status_map[503]
HTTPInsufficientStorage = status_map[507]
