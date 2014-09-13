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

import re
import md5
from urllib import quote
import base64
import email.utils
import datetime

from swift.common import swob
from swift.common.http import HTTP_OK, HTTP_CREATED, HTTP_ACCEPTED, \
    HTTP_NO_CONTENT, HTTP_UNAUTHORIZED, HTTP_FORBIDDEN, HTTP_NOT_FOUND, \
    HTTP_CONFLICT, HTTP_UNPROCESSABLE_ENTITY, HTTP_REQUEST_ENTITY_TOO_LARGE, \
    HTTP_PARTIAL_CONTENT, HTTP_NOT_MODIFIED, HTTP_PRECONDITION_FAILED, \
    HTTP_REQUESTED_RANGE_NOT_SATISFIABLE, HTTP_LENGTH_REQUIRED, \
    HTTP_BAD_REQUEST, HTTP_SERVICE_UNAVAILABLE

from swift.common.constraints import check_utf8

from swift3.controllers import ServiceController, BucketController, \
    ObjectController, AclController, MultiObjectDeleteController, \
    LocationController, LoggingStatusController, PartController, \
    UploadController, UploadsController, VersioningController, \
    UnsupportedController, S3AclController
from swift3.response import AccessDenied, InvalidArgument, InvalidDigest, \
    RequestTimeTooSkewed, Response, SignatureDoesNotMatch, \
    ServiceUnavailable, BucketAlreadyExists, BucketNotEmpty, EntityTooLarge, \
    InternalError, NoSuchBucket, NoSuchKey, PreconditionFailed, InvalidRange, \
    MissingContentLength, InvalidStorageClass, S3NotImplemented, InvalidURI, \
    MalformedXML, InvalidRequest
from swift3.exception import NotS3Request, BadSwiftRequest
from swift3.utils import utf8encode
from swift3.cfg import CONF
from swift3.subresource import decode_acl, encode_acl
from swift3.utils import sysmeta_header

# List of sub-resources that must be maintained as part of the HMAC
# signature string.
ALLOWED_SUB_RESOURCES = sorted([
    'acl', 'delete', 'lifecycle', 'location', 'logging', 'notification',
    'partNumber', 'policy', 'requestPayment', 'torrent', 'uploads', 'uploadId',
    'versionId', 'versioning', 'versions', 'website',
    'response-cache-control', 'response-content-disposition',
    'response-content-encoding', 'response-content-language',
    'response-content-type', 'response-expires', 'cors', 'tagging', 'restore'
])


def _header_acl_property(resource):
    """
    Set and retrieve the acl in self.headers
    """
    def getter(self):
        return decode_acl(resource, self.headers)

    def setter(self, value):
        self.headers.update(encode_acl(resource, value))

    def deleter(self):
        self.headers[sysmeta_header(resource, 'acl')] = ''

    return property(getter, setter, deleter,
                    doc='Get and set the %s acl property' % resource)


class Request(swob.Request):
    """
    S3 request object.
    """

    bucket_acl = _header_acl_property('container')
    object_acl = _header_acl_property('object')

    def __init__(self, env):
        swob.Request.__init__(self, env)

        self.access_key, self.signature = self._parse_authorization()
        self.bucket_in_host = self._parse_host()
        self.container_name, self.object_name = self._parse_uri()
        self._validate_headers()
        self.token = base64.urlsafe_b64encode(self._canonical_string())
        self.user_id = None

        # Avoids that swift.swob.Response replaces Location header value
        # by full URL when absolute path given. See swift.swob for more detail.
        self.environ['swift.leave_relative_location'] = True

    def _parse_host(self):
        storage_domain = CONF.storage_domain
        if not storage_domain:
            return None

        if not storage_domain.startswith('.'):
            storage_domain = '.' + storage_domain

        if 'HTTP_HOST' in self.environ:
            given_domain = self.environ['HTTP_HOST']
        elif 'SERVER_NAME' in self.environ:
            given_domain = self.environ['SERVER_NAME']
        else:
            return None

        port = ''
        if ':' in given_domain:
            given_domain, port = given_domain.rsplit(':', 1)
        if given_domain.endswith(storage_domain):
            return given_domain[:-len(storage_domain)]

        return None

    def _parse_uri(self):
        if not check_utf8(self.environ['PATH_INFO']):
            raise InvalidURI(self.path)

        if self.bucket_in_host:
            obj = self.environ['PATH_INFO'][1:] or None
            return self.bucket_in_host, obj

        return self.split_path(0, 2, True)

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
            keyword, info = self.headers['Authorization'].split(' ', 1)
        except Exception:
            raise AccessDenied()

        if keyword != 'AWS':
            raise NotS3Request

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
            if not re.match('^[A-Za-z0-9+/]+={0,2}$', value):
                # Non-base64-alphabet characters in value.
                raise InvalidDigest(content_md5=value)
            try:
                self.headers['ETag'] = value.decode('base64').encode('hex')
            except Exception:
                raise InvalidDigest(content_md5=value)

        if 'x-amz-metadata-directive' in self.headers:
            value = self.headers['x-amz-metadata-directive']
            if value not in ('COPY', 'REPLACE'):
                err_msg = 'Unknown metadata directive.'
                raise InvalidArgument('x-amz-metadata-directive', value,
                                      err_msg)

        if 'x-amz-storage-class' in self.headers:
            # Only STANDARD is supported now.
            if self.headers['x-amz-storage-class'] != 'STANDARD':
                raise InvalidStorageClass()

        if 'x-amz-mfa' in self.headers:
            raise S3NotImplemented('MFA Delete is not supported.')

        if 'x-amz-server-side-encryption' in self.headers:
            raise S3NotImplemented('Server-side encryption is not supported.')

        if 'x-amz-website-redirect-location' in self.headers:
            raise S3NotImplemented('Website redirection is not supported.')

    @property
    def body(self):
        """
        swob.Request.body is not secure against malicious input.  It consumes
        too much memory without any check when the request body is excessively
        large.  Use xml() instead.
        """
        raise AttributeError("No attribute 'body'")

    def xml(self, max_length, check_md5=False):
        """
        Similar to swob.Request.body, but it checks the content length before
        creating a body string.
        """
        if self.headers.get('transfer-encoding'):
            # FIXME: Raise error only when the input body is larger than
            # 'max_length'.
            raise S3NotImplemented('A header you provided implies '
                                   'functionality that is not implemented',
                                   header='Transfer-Encoding')

        if self.message_length() > max_length:
            raise MalformedXML()

        body = swob.Request.body.fget(self)

        if check_md5:
            self.check_md5(body)

        return body

    def check_md5(self, body):
        if 'HTTP_CONTENT_MD5' not in self.environ:
            raise InvalidRequest('Missing required header for this request: '
                                 'Content-MD5')

        digest = md5.new(body).digest().encode('base64').strip()
        if self.environ['HTTP_CONTENT_MD5'] != digest:
            raise InvalidDigest(content_md5=self.environ['HTTP_CONTENT_MD5'])

    def _canonical_uri(self):
        raw_path_info = self.environ.get('RAW_PATH_INFO', self.path)
        if self.bucket_in_host:
            raw_path_info = '/' + self.bucket_in_host + raw_path_info
        return raw_path_info

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

        path = self._canonical_uri()
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
        if self.is_service_request:
            return ServiceController

        if 'acl' in self.params:
            if CONF.s3_acl:
                return S3AclController
            else:
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

        unsupported = ('notification', 'policy', 'requestPayment', 'torrent',
                       'website', 'cors', 'tagging', 'restore')
        if set(unsupported) & set(self.params):
            return UnsupportedController

        if self.is_object_request:
            return ObjectController
        return BucketController

    @property
    def is_service_request(self):
        return not self.container_name

    @property
    def is_bucket_request(self):
        return self.container_name and not self.object_name

    @property
    def is_object_request(self):
        return self.container_name and self.object_name

    def to_swift_req(self, method, container, obj, query=None,
                     body=None, headers=None):
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
        if method is not None:
            env['REQUEST_METHOD'] = method
        env['HTTP_X_AUTH_TOKEN'] = self.token

        if obj:
            path = '/v1/%s/%s/%s' % (self.access_key, container, obj)
        elif container:
            path = '/v1/%s/%s' % (self.access_key, container)
        else:
            path = '/v1/%s' % (self.access_key)
        env['PATH_INFO'] = path

        query_string = ''
        if query is not None:
            params = []
            for key, value in sorted(query.items()):
                if value is not None:
                    params.append('%s=%s' % (key, quote(str(value))))
                else:
                    params.append(key)
            query_string = '&'.join(params)
        env['QUERY_STRING'] = query_string

        return swob.Request.blank(quote(path), environ=env, body=body,
                                  headers=headers)

    def _swift_success_codes(self, method, container, obj):
        """
        Returns a list of expected success codes from Swift.
        """
        if not container:
            # Swift account access.
            code_map = {
                'GET': [
                    HTTP_OK,
                ],
            }
        elif not obj:
            # Swift container access.
            code_map = {
                'HEAD': [
                    HTTP_NO_CONTENT,
                ],
                'GET': [
                    HTTP_OK,
                    HTTP_NO_CONTENT,
                ],
                'PUT': [
                    HTTP_CREATED,
                ],
                'POST': [
                    HTTP_NO_CONTENT,
                ],
                'DELETE': [
                    HTTP_NO_CONTENT,
                ],
            }
        else:
            # Swift object access.
            code_map = {
                'HEAD': [
                    HTTP_OK,
                    HTTP_PARTIAL_CONTENT,
                    HTTP_NOT_MODIFIED,
                ],
                'GET': [
                    HTTP_OK,
                    HTTP_PARTIAL_CONTENT,
                    HTTP_NOT_MODIFIED,
                ],
                'PUT': [
                    HTTP_CREATED,
                ],
                'POST': [
                    HTTP_ACCEPTED,
                ],
                'DELETE': [
                    HTTP_NO_CONTENT,
                ],
            }

        return code_map[method]

    def _swift_error_codes(self, method, container, obj):
        """
        Returns a dict from expected Swift error codes to the corresponding S3
        error responses.
        """
        if not container:
            # Swift account access.
            code_map = {
                'GET': {
                },
            }
        elif not obj:
            # Swift container access.
            code_map = {
                'HEAD': {
                    HTTP_NOT_FOUND: (NoSuchBucket, container),
                },
                'GET': {
                    HTTP_NOT_FOUND: (NoSuchBucket, container),
                },
                'PUT': {
                    HTTP_ACCEPTED: (BucketAlreadyExists, container),
                },
                'POST': {
                    HTTP_NOT_FOUND: (NoSuchBucket, container),
                },
                'DELETE': {
                    HTTP_NOT_FOUND: (NoSuchBucket, container),
                    HTTP_CONFLICT: BucketNotEmpty,
                },
            }
        else:
            # Swift object access.
            code_map = {
                'HEAD': {
                    HTTP_NOT_FOUND: (NoSuchKey, obj),
                    HTTP_PRECONDITION_FAILED: PreconditionFailed,
                },
                'GET': {
                    HTTP_NOT_FOUND: (NoSuchKey, obj),
                    HTTP_PRECONDITION_FAILED: PreconditionFailed,
                    HTTP_REQUESTED_RANGE_NOT_SATISFIABLE: InvalidRange,
                },
                'PUT': {
                    HTTP_NOT_FOUND: (NoSuchBucket, container),
                    HTTP_UNPROCESSABLE_ENTITY: InvalidDigest,
                    HTTP_REQUEST_ENTITY_TOO_LARGE: EntityTooLarge,
                    HTTP_LENGTH_REQUIRED: MissingContentLength,
                },
                'POST': {
                    HTTP_NOT_FOUND: (NoSuchKey, obj),
                    HTTP_PRECONDITION_FAILED: PreconditionFailed,
                },
                'DELETE': {
                    HTTP_NOT_FOUND: (NoSuchKey, obj),
                },
            }

        return code_map[method]

    def get_response(self, app, method=None, container=None, obj=None,
                     headers=None, body=None, query=None):
        """
        Calls the application with this request's environment.  Returns a
        Response object that wraps up the application's result.
        """
        method = method or self.environ['REQUEST_METHOD']
        if container is None:
            container = self.container_name
        if obj is None:
            obj = self.object_name

        sw_req = self.to_swift_req(method, container, obj, headers=headers,
                                   body=body, query=query)
        sw_resp = sw_req.get_response(app)
        resp = Response.from_swift_resp(sw_resp)
        status = resp.status_int  # pylint: disable-msg=E1101

        if 'HTTP_X_USER_NAME' in sw_resp.environ:
            # keystone
            self.user_id = utf8encode("%s:%s" %
                                      (sw_resp.environ['HTTP_X_TENANT_NAME'],
                                       sw_resp.environ['HTTP_X_USER_NAME']))
        else:
            # tempauth
            self.user_id = self.access_key

        success_codes = self._swift_success_codes(method, container, obj)
        error_codes = self._swift_error_codes(method, container, obj)

        if status in success_codes:
            return resp

        err_msg = resp.body

        if status in error_codes:
            err_resp = error_codes[sw_resp.status_int]
            if isinstance(err_resp, tuple):
                raise err_resp[0](*err_resp[1:])
            else:
                raise err_resp()

        if status == HTTP_BAD_REQUEST:
            raise BadSwiftRequest(err_msg)
        if status == HTTP_UNAUTHORIZED:
            raise SignatureDoesNotMatch()
        if status == HTTP_FORBIDDEN:
            raise AccessDenied()
        if status == HTTP_SERVICE_UNAVAILABLE:
            raise ServiceUnavailable()

        raise InternalError('unexpected status code %d' % status)
