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
import base64
import email.utils
import datetime

from swift.common import swob

from swift3.response import AccessDenied, InvalidArgument, InvalidDigest, \
    RequestTimeTooSkewed, Response, SignatureDoesNotMatch
from swift3.exception import NotS3Request

# List of sub-resources that must be maintained as part of the HMAC
# signature string.
ALLOWED_SUB_RESOURCES = sorted([
    'acl', 'delete', 'lifecycle', 'location', 'logging', 'notification',
    'partNumber', 'policy', 'requestPayment', 'torrent', 'uploads', 'uploadId',
    'versionId', 'versioning', 'versions ', 'website'
])


class Request(swob.Request):
    """
    S3 request object.
    """
    def __init__(self, env):
        swob.Request.__init__(self, env)

        self.access_key, self.signature = self._parse_authorization()
        self.container_name, self.object_name = self.split_path(0, 2, True)
        self._validate_headers()
        self.token = base64.urlsafe_b64encode(self._canonical_string())

    def _parse_authorization(self):
        if 'AWSAccessKeyId' in self.params:
            try:
                self.headers['Date'] = self.params['Expires']
                self.headers['Authorization'] = \
                    'AWS %(AWSAccessKeyId)s:%(Signature)s' % self.params
            except KeyError:
                raise AccessDenied()

        if 'Authorization' not in self.headers:
            raise NotS3Request

        try:
            keyword, info = self.headers['Authorization'].split(' ')
        except Exception:
            raise AccessDenied()

        if keyword != 'AWS':
            raise AccessDenied()

        try:
            access_key, signature = info.rsplit(':', 1)
        except Exception:
            err_msg = 'AWS authorization header is invalid.  ' \
                'Expected AwsAccessKeyId:signature'
            raise InvalidArgument('Authorization',
                                  self.headers['Authorization'], err_msg)

        return access_key, signature

    def _validate_headers(self):
        if 'CONTENT_LENGTH' in self.environ:
            try:
                if self.content_length < 0:
                    raise InvalidArgument('Content-Length',
                                          self.content_length)
            except (ValueError, TypeError):
                raise InvalidArgument('Content-Length',
                                      self.environ['CONTENT_LENGTH'])

        if 'Date' in self.headers:
            now = datetime.datetime.utcnow()
            date = email.utils.parsedate(self.headers['Date'])
            if 'Expires' in self.params:
                try:
                    d = email.utils.formatdate(float(self.params['Expires']))
                except ValueError:
                    raise AccessDenied()

                # check expiration
                expdate = email.utils.parsedate(d)
                ex = datetime.datetime(*expdate[0:6])
                if now > ex:
                    raise AccessDenied('Request has expired')
            elif date is not None:
                epoch = datetime.datetime(1970, 1, 1, 0, 0, 0, 0)

                d1 = datetime.datetime(*date[0:6])
                if d1 < epoch:
                    raise AccessDenied()

                # If the standard date is too far ahead or behind, it is an
                # error
                delta = datetime.timedelta(seconds=60 * 5)
                if abs(d1 - now) > delta:
                    raise RequestTimeTooSkewed()
            else:
                raise AccessDenied()

        if 'Content-MD5' in self.headers:
            value = self.headers['Content-MD5']
            if value == '':
                raise InvalidDigest()
            try:
                self.headers['ETag'] = value.decode('base64').encode('hex')
            except Exception:
                raise InvalidDigest()
            if self.headers['ETag'] == '':
                raise SignatureDoesNotMatch()

    def _canonical_string(self):
        """
        Canonicalize a request to a token that can be signed.
        """
        amz_headers = {}

        buf = "%s\n%s\n%s\n" % (self.method,
                                self.headers.get('Content-MD5', ''),
                                self.headers.get('Content-Type') or '')

        for amz_header in sorted((key.lower() for key in self.headers
                                  if key.lower().startswith('x-amz-'))):
            amz_headers[amz_header] = self.headers[amz_header]

        if 'x-amz-date' in amz_headers:
            buf += "\n"
        elif 'Date' in self.headers:
            buf += "%s\n" % self.headers['Date']

        for k in sorted(key.lower() for key in amz_headers):
            buf += "%s:%s\n" % (k, amz_headers[k])

        path = self.environ.get('RAW_PATH_INFO', self.path)
        if self.query_string:
            path += '?' + self.query_string
        if '?' in path:
            path, args = path.split('?', 1)
            params = []
            for key, value in sorted(self.params.items()):
                if key in ALLOWED_SUB_RESOURCES:
                    params.append('%s=%s' % (key, value) if value else key)
            if params:
                return '%s%s?%s' % (buf, path, '&'.join(params))

        return buf + path

    @property
    def controller(self):
        from swift3.middleware import ServiceController, BucketController, \
            ObjectController, AclController, MultiObjectDeleteController, \
            LocationController, LoggingStatusController, PartController, \
            UploadController, UploadsController, VersioningController

        if 'acl' in self.params:
            return AclController
        if 'delete' in self.params:
            return MultiObjectDeleteController
        if 'location' in self.params:
            return LocationController
        if 'logging' in self.params:
            return LoggingStatusController
        if 'partNumber' in self.params:
            return PartController
        if 'uploadId' in self.params:
            return UploadController
        if 'uploads' in self.params:
            return UploadsController
        if 'versioning' in self.params:
            return VersioningController

        if self.container_name and self.object_name:
            return ObjectController
        elif self.container_name:
            return BucketController

        return ServiceController

    def to_swift_req(self):
        """
        Create a Swift request based on this request's environment.
        """
        env = self.environ.copy()

        for key in env:
            if key.startswith('HTTP_X_AMZ_META_'):
                env['HTTP_X_OBJECT_META_' + key[16:]] = env[key]
                del env[key]

            if key == 'HTTP_X_AMZ_COPY_SOURCE':
                env['HTTP_X_COPY_FROM'] = env[key]
                del env[key]

        env['swift.source'] = 'S3'
        env['HTTP_X_AUTH_TOKEN'] = self.token

        if self.object_name:
            path = '/v1/%s/%s/%s' % (self.access_key, self.container_name,
                                     self.object_name)
        elif self.container_name:
            path = '/v1/%s/%s' % (self.access_key, self.container_name)
        else:
            path = '/v1/%s' % (self.access_key)
        env['PATH_INFO'] = path

        env['QUERY_STRING'] = self.query_string

        return swob.Request.blank(quote(path), environ=env)

    def get_response(self, app):
        """
        Calls the application with this request's environment.  Returns a
        Response object that wraps up the application's result.
        """
        sw_req = self.to_swift_req()
        sw_resp = sw_req.get_response(app)

        return Response.from_swift_resp(sw_resp)
