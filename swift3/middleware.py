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

"""
The swift3 middleware will emulate the S3 REST api on top of swift.

The following operations are currently supported:

    * GET Service
    * DELETE Bucket
    * GET Bucket (List Objects)
    * PUT Bucket
    * DELETE Object
    * Delete Multiple Objects
    * GET Object
    * HEAD Object
    * PUT Object
    * PUT Object (Copy)

To add this middleware to your configuration, add the swift3 middleware
in front of the auth middleware, and before any other middleware that
look at swift requests (like rate limiting).

To set up your client, the access key will be the concatenation of the
account and user strings that should look like test:tester, and the
secret access key is the account password.  The host should also point
to the swift storage hostname.  It also will have to use the old style
calling format, and not the hostname based container format.

An example client using the python boto library might look like the
following for an SAIO setup::

    from boto.s3.connection import S3Connection
    connection = S3Connection(
        aws_access_key_id='test:tester',
        aws_secret_access_key='testing',
        port=8080,
        host='127.0.0.1',
        is_secure=False,
        calling_format=boto.s3.connection.OrdinaryCallingFormat())
"""

from urllib import quote
import base64
from xml.sax.saxutils import escape as xml_escape
from xml.dom.minidom import parseString

from simplejson import loads
import email.utils
import datetime
import re

from swift.common.utils import get_logger
from swift.common.swob import Request
from swift3.response import Response, HTTPForbidden, HTTPConflict, \
    HTTPBadRequest, HTTPMethodNotAllowed, HTTPNotFound, HTTPNotImplemented, \
    HTTPLengthRequired, HTTPServiceUnavailable, HTTPNoContent, HTTPOk, \
    HTTPInternalServerError
from swift.common.http import HTTP_OK, HTTP_CREATED, HTTP_ACCEPTED, \
    HTTP_NO_CONTENT, HTTP_UNAUTHORIZED, HTTP_FORBIDDEN, HTTP_NOT_FOUND, \
    HTTP_CONFLICT, HTTP_UNPROCESSABLE_ENTITY, is_success, \
    HTTP_REQUEST_ENTITY_TOO_LARGE


MAX_BUCKET_LISTING = 1000

# List of  sub-resources that must be maintained as part of the HMAC
# signature string.
ALLOWED_SUB_RESOURCES = sorted([
    'acl', 'delete', 'lifecycle', 'location', 'logging', 'notification',
    'partNumber', 'policy', 'requestPayment', 'torrent', 'uploads', 'uploadId',
    'versionId', 'versioning', 'versions ', 'website'
])


def get_err_response(code):
    """
    Given an HTTP response code, create a properly formatted xml error response

    :param code: error code
    :returns: swob.response object
    """
    error_table = {
        'AccessDenied':
        (HTTPForbidden, 'Access denied'),
        'BucketAlreadyExists':
        (HTTPConflict, 'The requested bucket name is not available'),
        'BucketNotEmpty':
        (HTTPConflict, 'The bucket you tried to delete is not empty'),
        'InternalError':
        (HTTPInternalServerError, 'We encountered an internal error. '
            'Please try again.'),
        'InvalidArgument':
        (HTTPBadRequest, 'Invalid Argument'),
        'InvalidBucketName':
        (HTTPBadRequest, 'The specified bucket is not valid'),
        'InvalidURI':
        (HTTPBadRequest, 'Could not parse the specified URI'),
        'InvalidDigest':
        (HTTPBadRequest, 'The Content-MD5 you specified was invalid'),
        'BadDigest':
        (HTTPBadRequest, 'The Content-Length you specified was invalid'),
        'EntityTooLarge':
        (HTTPBadRequest, 'Your proposed upload exceeds the maximum '
            'allowed object size.'),
        'MethodNotAllowed':
        (HTTPMethodNotAllowed, 'The specified method is not allowed '
            'against this resource.'),
        'NoSuchBucket':
        (HTTPNotFound, 'The specified bucket does not exist'),
        'SignatureDoesNotMatch':
        (HTTPForbidden, 'The calculated request signature does not '
            'match your provided one'),
        'RequestTimeTooSkewed':
        (HTTPForbidden, 'The difference between the request time and the'
        ' current time is too large'),
        'NoSuchKey':
        (HTTPNotFound, 'The resource you requested does not exist'),
        'Unsupported':
        (HTTPNotImplemented, 'The feature you requested is not yet'
        ' implemented'),
        'MissingContentLength':
        (HTTPLengthRequired, 'Length Required'),
        'ServiceUnavailable':
        (HTTPServiceUnavailable, 'Please reduce your request rate')}

    resp, message = error_table[code]
    body = '<?xml version="1.0" encoding="UTF-8"?>\r\n<Error>\r\n  ' \
        '<Code>%s</Code>\r\n  <Message>%s</Message>\r\n</Error>\r\n' \
        % (code, message)
    return resp(body=body, content_type='text/xml')


def get_acl(account_name, headers):
    """
    Attempts to construct an S3 ACL based on what is found in the swift headers
    """

    acl = 'private'  # default to private

    if 'x-container-read' in headers:
        if headers['x-container-read'] == ".r:*" or\
            ".r:*," in headers['x-container-read'] or \
                ",*," in headers['x-container-read']:
            acl = 'public-read'
    if 'x-container-write' in headers:
        if headers['x-container-write'] == ".r:*" or\
            ".r:*," in headers['x-container-write'] or \
                ",*," in headers['x-container-write']:
            if acl == 'public-read':
                acl = 'public-read-write'
            else:
                acl = 'public-write'

    if acl == 'private':
        body = ('<AccessControlPolicy>'
                '<Owner>'
                '<ID>%s</ID>'
                '<DisplayName>%s</DisplayName>'
                '</Owner>'
                '<AccessControlList>'
                '<Grant>'
                '<Grantee xmlns:xsi="http://www.w3.org/2001/'
                'XMLSchema-instance" xsi:type="CanonicalUser">'
                '<ID>%s</ID>'
                '<DisplayName>%s</DisplayName>'
                '</Grantee>'
                '<Permission>FULL_CONTROL</Permission>'
                '</Grant>'
                '</AccessControlList>'
                '</AccessControlPolicy>' %
                (account_name, account_name, account_name, account_name))
    elif acl == 'public-read':
        body = ('<AccessControlPolicy>'
                '<Owner>'
                '<ID>%s</ID>'
                '<DisplayName>%s</DisplayName>'
                '</Owner>'
                '<AccessControlList>'
                '<Grant>'
                '<Grantee xmlns:xsi="http://www.w3.org/2001/'
                'XMLSchema-instance" xsi:type="CanonicalUser">'
                '<ID>%s</ID>'
                '<DisplayName>%s</DisplayName>'
                '</Grantee>'
                '<Permission>FULL_CONTROL</Permission>'
                '</Grant>'
                '<Grant>'
                '<Grantee xmlns:xsi="http://www.w3.org/2001/'
                'XMLSchema-instance" xsi:type="Group">'
                '<URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>'
                '</Grantee>'
                '<Permission>READ</Permission>'
                '</Grant>'
                '</AccessControlList>'
                '</AccessControlPolicy>' %
                (account_name, account_name, account_name, account_name))
    elif acl == 'public-read-write':
        body = ('<AccessControlPolicy>'
                '<Owner>'
                '<ID>%s</ID>'
                '<DisplayName>%s</DisplayName>'
                '</Owner>'
                '<AccessControlList>'
                '<Grant>'
                '<Grantee xmlns:xsi="http://www.w3.org/2001/'
                'XMLSchema-instance" xsi:type="CanonicalUser">'
                '<ID>%s</ID>'
                '<DisplayName>%s</DisplayName>'
                '</Grantee>'
                '<Permission>FULL_CONTROL</Permission>'
                '</Grant>'
                '<Grant>'
                '<Grantee xmlns:xsi="http://www.w3.org/2001/'
                'XMLSchema-instance" xsi:type="Group">'
                '<URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>'
                '</Grantee>'
                '<Permission>READ</Permission>'
                '</Grant>'
                '</AccessControlList>'
                '<AccessControlList>'
                '<Grant>'
                '<Grantee xmlns:xsi="http://www.w3.org/2001/'
                'XMLSchema-instance" xsi:type="Group">'
                '<URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>'
                '</Grantee>'
                '<Permission>WRITE</Permission>'
                '</Grant>'
                '</AccessControlList>'
                '</AccessControlPolicy>' %
                (account_name, account_name, account_name, account_name))
    else:
        body = ('<AccessControlPolicy>'
                '<Owner>'
                '<ID>%s</ID>'
                '<DisplayName>%s</DisplayName>'
                '</Owner>'
                '<AccessControlList>'
                '<Grant>'
                '<Grantee xmlns:xsi="http://www.w3.org/2001/'
                'XMLSchema-instance" xsi:type="CanonicalUser">'
                '<ID>%s</ID>'
                '<DisplayName>%s</DisplayName>'
                '</Grantee>'
                '<Permission>FULL_CONTROL</Permission>'
                '</Grant>'
                '</AccessControlList>'
                '</AccessControlPolicy>' %
                (account_name, account_name, account_name, account_name))
    return HTTPOk(body=body, content_type="text/plain")


def canonical_string(req):
    """
    Canonicalize a request to a token that can be signed.
    """
    amz_headers = {}

    buf = "%s\n%s\n%s\n" % (req.method, req.headers.get('Content-MD5', ''),
                            req.headers.get('Content-Type') or '')

    for amz_header in sorted((key.lower() for key in req.headers
                              if key.lower().startswith('x-amz-'))):
        amz_headers[amz_header] = req.headers[amz_header]

    if 'x-amz-date' in amz_headers:
        buf += "\n"
    elif 'Date' in req.headers:
        buf += "%s\n" % req.headers['Date']

    for k in sorted(key.lower() for key in amz_headers):
        buf += "%s:%s\n" % (k, amz_headers[k])

    # RAW_PATH_INFO is enabled in later version than eventlet 0.9.17.
    # When using older version, swift3 uses req.path of swob instead
    # of it.
    path = req.environ.get('RAW_PATH_INFO', req.path)
    if req.query_string:
        path += '?' + req.query_string
    if '?' in path:
        path, args = path.split('?', 1)
        params = []
        for key, value in sorted(req.params.items()):
            if key in ALLOWED_SUB_RESOURCES:
                params.append('%s=%s' % (key, value) if value else key)
        if params:
            return '%s%s?%s' % (buf, path, '&'.join(params))

    return buf + path


def swift_acl_translate(acl, group='', user='', xml=False):
    """
    Takes an S3 style ACL and returns a list of header/value pairs that
    implement that ACL in Swift, or "Unsupported" if there isn't a way to do
    that yet.
    """
    swift_acl = {}
    swift_acl['public-read'] = [['HTTP_X_CONTAINER_READ', '.r:*,.rlistings']]
    # Swift does not support public write:
    # https://answers.launchpad.net/swift/+question/169541
    swift_acl['public-read-write'] = [['HTTP_X_CONTAINER_WRITE', '.r:*'],
                                      ['HTTP_X_CONTAINER_READ',
                                       '.r:*,.rlistings']]

    #TODO: if there's a way to get group and user, this should work for
    # private:
    #swift_acl['private'] = [['HTTP_X_CONTAINER_WRITE',  group + ':' + user], \
    #                  ['HTTP_X_CONTAINER_READ', group + ':' + user]]
    swift_acl['private'] = [['HTTP_X_CONTAINER_WRITE', '.'],
                            ['HTTP_X_CONTAINER_READ', '.']]
    if xml:
        # We are working with XML and need to parse it
        dom = parseString(acl)
        acl = 'unknown'
        for grant in dom.getElementsByTagName('Grant'):
            permission = grant.getElementsByTagName('Permission')[0]\
                .firstChild.data
            grantee = grant.getElementsByTagName('Grantee')[0]\
                .getAttributeNode('xsi:type').nodeValue
            if permission == "FULL_CONTROL" and grantee == 'CanonicalUser' and\
                    acl != 'public-read' and acl != 'public-read-write':
                acl = 'private'
            elif permission == "READ" and grantee == 'Group' and\
                    acl != 'public-read-write':
                acl = 'public-read'
            elif permission == "WRITE" and grantee == 'Group':
                acl = 'public-read-write'
            else:
                acl = 'unsupported'

    if acl == 'authenticated-read':
        return "Unsupported"
    elif acl not in swift_acl:
        return "InvalidArgument"

    return swift_acl[acl]


def validate_bucket_name(name):
    """
    Validates the name of the bucket against S3 criteria,
    http://docs.amazonwebservices.com/AmazonS3/latest/BucketRestrictions.html
    True if valid, False otherwise
    """

    if '_' in name or len(name) < 3 or len(name) > 63 or not \
            name[-1].isalnum():
        # Bucket names should not contain underscores (_)
        # Bucket names must end with a lowercase letter or number
        # Bucket names should be between 3 and 63 characters long
        return False
    elif '.-' in name or '-.' in name or '..' in name or not name[0].isalnum():
        # Bucket names cannot contain dashes next to periods
        # Bucket names cannot contain two adjacent periods
        # Bucket names Must start with a lowercase letter or a number
        return False
    elif re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}"
                  "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", name):
        # Bucket names cannot be formatted as an IP Address
        return False
    else:
        return True


class Controller(object):
    """
    Base WSGI controller class for the middleware
    """
    def __init__(self, req, app, account_name, token, container_name=None,
                 object_name=None, **kwargs):
        self.app = app
        self.account_name = account_name
        self.container_name = container_name
        self.object_name = object_name
        req.environ['HTTP_X_AUTH_TOKEN'] = token
        if object_name:
            req.path_info = '/v1/%s/%s/%s' % (account_name, container_name,
                                              object_name)
        elif container_name:
            req.path_info = '/v1/%s/%s' % (account_name, container_name)
        else:
            req.path_info = '/v1/%s' % (account_name)


class ServiceController(Controller):
    """
    Handles account level requests.
    """
    def GET(self, req):
        """
        Handle GET Service request
        """
        req.query_string = 'format=json'
        resp = req.get_response(self.app)
        status = resp.status_int

        if status != HTTP_OK:
            if status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return get_err_response('AccessDenied')
            else:
                return get_err_response('InternalError')

        containers = loads(resp.body)
        # we don't keep the creation time of a backet (s3cmd doesn't
        # work without that) so we use something bogus.
        body = '<?xml version="1.0" encoding="UTF-8"?>' \
               '<ListAllMyBucketsResult ' \
               'xmlns="http://doc.s3.amazonaws.com/2006-03-01">' \
               '<Buckets>%s</Buckets>' \
               '</ListAllMyBucketsResult>' \
               % ("".join(['<Bucket><Name>%s</Name><CreationDate>'
                           '2009-02-03T16:45:09.000Z</CreationDate></Bucket>'
                           % xml_escape(i['name']) for i in containers]))
        return HTTPOk(content_type='application/xml', body=body)


class BucketController(Controller):
    """
    Handles bucket request.
    """
    def HEAD(self, req):
        """
        Handle HEAD Bucket (Get Metadata) request
        """
        if req.query_string:
                req.query_string = ''

        resp = req.get_response(self.app)
        status = resp.status_int
        headers = resp.headers
        if status == HTTP_NO_CONTENT:
                status = HTTP_OK

        return Response(status=status, headers=headers, app_iter=resp.app_iter)

    def GET(self, req):
        """
        Handle GET Bucket (List Objects) request
        """
        if 'max-keys' in req.params:
            if req.params.get('max-keys').isdigit() is False:
                return get_err_response('InvalidArgument')

        max_keys = min(int(req.params.get('max-keys', MAX_BUCKET_LISTING)),
                       MAX_BUCKET_LISTING)

        req.query_string = 'format=json&limit=%s' % (max_keys + 1)
        if 'marker' in req.params:
            req.query_string += '&marker=%s' % quote(req.params['marker'])
        if 'prefix' in req.params:
            req.query_string += '&prefix=%s' % quote(req.params['prefix'])
        if 'delimiter' in req.params:
            req.query_string += '&delimiter=%s' % \
                quote(req.params['delimiter'])
        resp = req.get_response(self.app)
        status = resp.status_int

        if status != HTTP_OK:
            if status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return get_err_response('AccessDenied')
            elif status == HTTP_NOT_FOUND:
                return get_err_response('NoSuchBucket')
            else:
                return get_err_response('InternalError')

        objects = loads(resp.body)
        body = ('<?xml version="1.0" encoding="UTF-8"?>'
                '<ListBucketResult '
                'xmlns="http://s3.amazonaws.com/doc/2006-03-01">'
                '<Prefix>%s</Prefix>'
                '<Marker>%s</Marker>'
                '<Delimiter>%s</Delimiter>'
                '<IsTruncated>%s</IsTruncated>'
                '<MaxKeys>%s</MaxKeys>'
                '<Name>%s</Name>'
                '%s'
                '%s'
                '</ListBucketResult>' %
                (
                xml_escape(req.params.get('prefix', '')),
                xml_escape(req.params.get('marker', '')),
                xml_escape(req.params.get('delimiter', '')),
                'true' if max_keys > 0 and len(objects) == (max_keys + 1) else
                'false',
                max_keys,
                xml_escape(self.container_name),
                "".join(['<Contents><Key>%s</Key><LastModified>%sZ</LastModif'
                        'ied><ETag>%s</ETag><Size>%s</Size><StorageClass>STA'
                        'NDARD</StorageClass><Owner><ID>%s</ID><DisplayName>'
                        '%s</DisplayName></Owner></Contents>' %
                        (xml_escape(i['name']), i['last_modified'],
                         i['hash'],
                         i['bytes'], self.account_name, self.account_name)
                         for i in objects[:max_keys] if 'subdir' not in i]),
                "".join(['<CommonPrefixes><Prefix>%s</Prefix></CommonPrefixes>'
                         % xml_escape(i['subdir'])
                         for i in objects[:max_keys] if 'subdir' in i])))
        return HTTPOk(body=body, content_type='application/xml')

    def PUT(self, req):
        """
        Handle PUT Bucket request
        """
        if 'HTTP_X_AMZ_ACL' in req.environ:
            amz_acl = req.environ['HTTP_X_AMZ_ACL']
            # Translate the Amazon ACL to something that can be
            # implemented in Swift, 501 otherwise. Swift uses POST
            # for ACLs, whereas S3 uses PUT.
            del req.environ['HTTP_X_AMZ_ACL']
            if req.query_string:
                req.query_string = ''

            translated_acl = swift_acl_translate(amz_acl)
            if translated_acl == 'Unsupported':
                return get_err_response('Unsupported')
            elif translated_acl == 'InvalidArgument':
                return get_err_response('InvalidArgument')

            for header, acl in translated_acl:
                req.headers[header] = acl

        if 'CONTENT_LENGTH' in req.environ:
            try:
                if req.content_length < 0:
                    return get_err_response('InvalidArgument')
            except (ValueError, TypeError):
                return get_err_response('InvalidArgument')

        resp = req.get_response(self.app)
        status = resp.status_int

        if status != HTTP_CREATED and status != HTTP_NO_CONTENT:
            if status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return get_err_response('AccessDenied')
            elif status == HTTP_ACCEPTED:
                return get_err_response('BucketAlreadyExists')
            else:
                return get_err_response('InternalError')

        return HTTPOk(headers={'Location': self.container_name})

    def DELETE(self, req):
        """
        Handle DELETE Bucket request
        """
        resp = req.get_response(self.app)
        status = resp.status_int

        if status != HTTP_NO_CONTENT:
            if status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return get_err_response('AccessDenied')
            elif status == HTTP_NOT_FOUND:
                return get_err_response('NoSuchBucket')
            elif status == HTTP_CONFLICT:
                return get_err_response('BucketNotEmpty')
            else:
                return get_err_response('InternalError')

        return HTTPNoContent()

    def POST(self, req):
        """
        Handle POST Bucket request
        """
        return get_err_response('Unsupported')


class ObjectController(Controller):
    """
    Handles requests on objects
    """
    def GETorHEAD(self, req):
        resp = req.get_response(self.app)
        status = resp.status_int
        headers = resp.headers

        if req.method == 'HEAD':
            resp.app_iter = None

        if is_success(status):
            return Response(status=status, headers=headers,
                            app_iter=resp.app_iter)
        elif status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
            return get_err_response('AccessDenied')
        elif status == HTTP_NOT_FOUND:
            return get_err_response('NoSuchKey')
        else:
            return get_err_response('InternalError')

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
        for key, value in req.environ.items():
            if key.startswith('HTTP_X_AMZ_META_'):
                del req.environ[key]
                req.environ['HTTP_X_OBJECT_META_' + key[16:]] = value
            elif key == 'HTTP_CONTENT_MD5':
                if value == '':
                    return get_err_response('InvalidDigest')
                try:
                    req.environ['HTTP_ETAG'] = \
                        value.decode('base64').encode('hex')
                except Exception:
                    return get_err_response('InvalidDigest')
                if req.environ['HTTP_ETAG'] == '':
                    return get_err_response('SignatureDoesNotMatch')
            elif key == 'HTTP_X_AMZ_COPY_SOURCE':
                req.environ['HTTP_X_COPY_FROM'] = value

        resp = req.get_response(self.app)
        status = resp.status_int

        if status != HTTP_CREATED:
            if status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return get_err_response('AccessDenied')
            elif status == HTTP_NOT_FOUND:
                return get_err_response('NoSuchBucket')
            elif status == HTTP_UNPROCESSABLE_ENTITY:
                return get_err_response('InvalidDigest')
            elif status == HTTP_REQUEST_ENTITY_TOO_LARGE:
                return get_err_response('EntityTooLarge')
            else:
                return get_err_response('InternalError')

        if 'HTTP_X_COPY_FROM' in req.environ:
            body = '<CopyObjectResult>' \
                   '<ETag>"%s"</ETag>' \
                   '</CopyObjectResult>' % resp.etag
            return HTTPOk(body=body)

        return HTTPOk(etag=resp.etag)

    def POST(self, req):
        return get_err_response('AccessDenied')

    def DELETE(self, req):
        """
        Handle DELETE Object request
        """
        try:
            resp = req.get_response(self.app)
        except Exception:
            return get_err_response('InternalError')

        status = resp.status_int

        if status != HTTP_NO_CONTENT:
            if status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return get_err_response('AccessDenied')
            elif status == HTTP_NOT_FOUND:
                return get_err_response('NoSuchKey')
            else:
                return get_err_response('InternalError')

        return HTTPNoContent()


class AclController(Controller):
    """
    Handles the following APIs:

     - GET Bucket acl
     - PUT Bucket acl
     - GET Object acl
     - PUT Object acl

    Those APIs are logged as ACL operations in the S3 server log.
    """
    def GET(self, req):
        """
        Handles GET Bucket acl and GET Object acl.
        """
        if self.object_name:
            # Handle Object ACL

            # ACL requests need to make a HEAD call rather than GET
            req.method = 'HEAD'
            req.script_name = ''
            req.query_string = ''

            resp = req.get_response(self.app)
            status = resp.status_int
            headers = resp.headers

            if is_success(status):
                # Method must be GET or the body wont be returned to the caller
                req.environ['REQUEST_METHOD'] = 'GET'
                return get_acl(self.account_name, headers)
            elif status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return get_err_response('AccessDenied')
            elif status == HTTP_NOT_FOUND:
                return get_err_response('NoSuchKey')
            else:
                return get_err_response('InternalError')

        else:
            # Handle Bucket ACL
            resp = req.get_response(self.app)
            status = resp.status_int
            headers = resp.headers

            if is_success(status):
                return get_acl(self.account_name, headers)

            if status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return get_err_response('AccessDenied')
            elif status == HTTP_NOT_FOUND:
                return get_err_response('NoSuchBucket')
            else:
                return get_err_response('InternalError')

    def PUT(self, req):
        """
        Handles PUT Bucket acl and PUT Object acl.
        """
        if self.object_name:
            # Handle Object ACL
            return get_err_response('Unsupported')
        else:
            # Handle Bucket ACL

            # We very likely have an XML-based ACL request.
            translated_acl = swift_acl_translate(req.body, xml=True)
            if translated_acl == 'Unsupported':
                return get_err_response('Unsupported')
            elif translated_acl == 'InvalidArgument':
                return get_err_response('InvalidArgument')
            for header, acl in translated_acl:
                req.headers[header] = acl
            req.method = 'POST'

            resp = req.get_response(self.app)
            status = resp.status_int

            if status != HTTP_CREATED and status != HTTP_NO_CONTENT:
                if status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                    return get_err_response('AccessDenied')
                elif status == HTTP_ACCEPTED:
                    return get_err_response('BucketAlreadyExists')
                else:
                    return get_err_response('InternalError')

                return HTTPOk(headers={'Location': self.container_name})


class LocationController(Controller):
    """
    Handles GET Bucket location, which is logged as a LOCATION operation in the
    S3 server log.
    """
    def GET(self, req):
        """
        Handles GET Bucket location.
        """
        resp = req.get_response(self.app)
        status = resp.status_int

        if status != HTTP_OK:
            if status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return get_err_response('AccessDenied')
            elif status == HTTP_NOT_FOUND:
                return get_err_response('NoSuchBucket')
            else:
                return get_err_response('InternalError')

        body = ('<?xml version="1.0" encoding="UTF-8"?>'
                '<LocationConstraint '
                'xmlns="http://s3.amazonaws.com/doc/2006-03-01/"')
        if self.location == 'US':
            body += '/>'
        else:
            body += ('>%s</LocationConstraint>' % self.location)
        return HTTPOk(body=body, content_type='application/xml')


class LoggingStatusController(Controller):
    """
    Handles the following APIs:

     - GET Bucket logging
     - PUT Bucket logging

    Those APIs are logged as LOGGING_STATUS operations in the S3 server log.
    """
    def GET(self, req):
        """
        Handles GET Bucket logging.
        """
        resp = req.get_response(self.app)
        status = resp.status_int

        if status != HTTP_OK:
            if status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return get_err_response('AccessDenied')
            elif status == HTTP_NOT_FOUND:
                return get_err_response('NoSuchBucket')
            else:
                return get_err_response('InternalError')

        # logging disabled
        body = ('<?xml version="1.0" encoding="UTF-8"?>'
                '<BucketLoggingStatus '
                'xmlns="http://doc.s3.amazonaws.com/2006-03-01" />')
        return HTTPOk(body=body, content_type='application/xml')

    def PUT(self, req):
        """
        Handles PUT Bucket logging.
        """
        return get_err_response('Unsupported')


class MultiObjectDeleteController(Controller):
    """
    Handles Delete Multiple Objects, which is logged as a MULTI_OBJECT_DELETE
    operation in the S3 server log.
    """
    def POST(self, req):
        """
        Handles Delete Multiple Objects.
        """
        def object_key_iter(xml):
            dom = parseString(xml)
            delete = dom.getElementsByTagName('Delete')[0]
            for obj in delete.getElementsByTagName('Object'):
                key = obj.getElementsByTagName('Key')[0].firstChild.data
                version = None
                if obj.getElementsByTagName('VersionId').length > 0:
                    version = obj.getElementsByTagName('VersionId')[0]\
                        .firstChild.data
                yield (key, version)

        def get_deleted_elem(key):
            return '  <Deleted>\r\n' \
                   '    <Key>%s</Key>\r\n' \
                   '  </Deleted>\r\n' % (key)

        def get_err_elem(key, err_code, message):
            return '  <Error>\r\n' \
                   '    <Key>%s</Key>\r\n' \
                   '    <Code>%s</Code>\r\n' \
                   '    <Message>%s</Message>\r\n' \
                   '  </Error>\r\n' % (key, err_code, message)

        body = '<?xml version="1.0" encoding="UTF-8"?>\r\n' \
               '<DeleteResult ' \
               'xmlns="http://doc.s3.amazonaws.com/2006-03-01">\r\n'
        for key, version in object_key_iter(req.body):
            if version is not None:
                # TODO: delete the specific version of the object
                return get_err_response('Unsupported')

            sub_req = Request(req.environ.copy())
            sub_req.query_string = ''
            sub_req.content_length = 0
            sub_req.method = 'DELETE'
            controller = ObjectController(sub_req, self.app, self.account_name,
                                          req.environ['HTTP_X_AUTH_TOKEN'],
                                          self.container_name, key)
            sub_resp = controller.DELETE(sub_req)
            status = sub_resp.status_int

            if status == HTTP_NO_CONTENT or status == HTTP_NOT_FOUND:
                body += get_deleted_elem(key)
            else:
                if status == HTTP_UNAUTHORIZED:
                    body += get_err_elem(key, 'AccessDenied', 'Access Denied')
                else:
                    body += get_err_elem(key, 'InternalError',
                                         'Internal Error')

        body += '</DeleteResult>\r\n'
        return HTTPOk(body=body)


class PartController(Controller):
    """
    Handles the following APIs:

     - Upload Part
     - Upload Part - Copy

    Those APIs are logged as PART operations in the S3 server log.
    """
    def PUT(self, req):
        """
        Handles Upload Part and Upload Part Copy.
        """
        # Pass it through, the s3multi upload helper will handle it.
        return self.app


class UploadsController(Controller):
    """
    Handles the following APIs:

     - List Multipart Uploads
     - Initiate Multipart Upload

    Those APIs are logged as UPLOADS operations in the S3 server log.
    """
    def GET(self, req):
        """
        Handles List Multipart Uploads
        """
        # Pass it through, the s3multi upload helper will handle it.
        return self.app

    def POST(self, req):
        """
        Handles Initiate Multipart Upload.
        """
        # Pass it through, the s3multi upload helper will handle it.
        return self.app


class UploadController(Controller):
    """
    Handles the following APIs:

     - List Parts
     - Abort Multipart Upload
     - Complete Multipart Upload

    Those APIs are logged as UPLOAD operations in the S3 server log.
    """
    def GET(self, req):
        """
        Handles List Parts.
        """
        # Pass it through, the s3multi upload helper will handle it.
        return self.app

    def DELETE(self, req):
        """
        Handles Abort Multipart Upload.
        """
        # Pass it through, the s3multi upload helper will handle it.
        return self.app

    def POST(self, req):
        """
        Handles Complete Multipart Upload.
        """
        # Pass it through, the s3multi upload helper will handle it.
        return self.app


class VersioningController(Controller):
    """
    Handles the following APIs:

     - GET Bucket versioning
     - PUT Bucket versioning

    Those APIs are logged as VERSIONING operations in the S3 server log.
    """
    def GET(self, req):
        """
        Handles GET Bucket versioning.
        """
        resp = req.get_response(self.app)
        status = resp.status_int

        if status != HTTP_OK:
            if status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return get_err_response('AccessDenied')
            elif status == HTTP_NOT_FOUND:
                return get_err_response('NoSuchBucket')
            else:
                return get_err_response('InternalError')

        # Just report there is no versioning configured here.
        body = ('<VersioningConfiguration '
                'xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>')
        return HTTPOk(body=body, content_type="text/plain")

    def PUT(self, req):
        """
        Handles PUT Bucket versioning.
        """
        return get_err_response('Unsupported')


class Swift3Middleware(object):
    """Swift3 S3 compatibility midleware"""
    def __init__(self, app, conf, *args, **kwargs):
        self.app = app
        self.conf = conf
        self.logger = get_logger(self.conf, log_route='swift3')

    def get_controller(self, req):
        container, obj = req.split_path(0, 2, True)
        d = dict(container_name=container, object_name=obj)

        if 'acl' in req.params:
            return AclController, d
        if 'delete' in req.params:
            return MultiObjectDeleteController, d
        if 'location' in req.params:
            return LocationController, d
        if 'logging' in req.params:
            return LoggingStatusController, d
        if 'partNumber' in req.params:
            return PartController, d
        if 'uploadId' in req.params:
            return UploadController, d
        if 'uploads' in req.params:
            return UploadsController, d
        if 'versioning' in req.params:
            return VersioningController, d

        if container and obj:
            if req.method == 'POST':
                if 'uploads' in req.params or 'uploadId' in req.params:
                    return BucketController, d
            return ObjectController, d
        elif container:
            return BucketController, d

        return ServiceController, d

    def __call__(self, env, start_response):
        req = Request(env)
        try:
            resp = self.handle_request(req)
        except Exception, e:
            self.logger.exception(e)
            resp = get_err_response('ServiceUnavailable')
        return resp(env, start_response)

    def handle_request(self, req):
        self.logger.debug('Calling Swift3 Middleware')
        self.logger.debug(req.__dict__)

        if 'AWSAccessKeyId' in req.params:
            try:
                req.headers['Date'] = req.params['Expires']
                req.headers['Authorization'] = \
                    'AWS %(AWSAccessKeyId)s:%(Signature)s' % req.params
            except KeyError:
                return get_err_response('InvalidArgument')

        if 'Authorization' not in req.headers:
            return self.app

        try:
            keyword, info = req.headers['Authorization'].split(' ')
        except Exception:
            return get_err_response('AccessDenied')

        if keyword != 'AWS':
            return get_err_response('AccessDenied')

        try:
            account, signature = info.rsplit(':', 1)
        except Exception:
            return get_err_response('InvalidArgument')

        try:
            controller, path_parts = self.get_controller(req)
        except ValueError:
            return get_err_response('InvalidURI')

        if 'Date' in req.headers:
            date = email.utils.parsedate(req.headers['Date'])
            expdate = None
            if date is None and 'Expires' in req.params:
                d = email.utils.formatdate(float(req.params['Expires']))
                expdate = email.utils.parsedate(d)

                date = datetime.datetime.utcnow().timetuple()
            elif date is None:
                return get_err_response('AccessDenied')

            epoch = datetime.datetime(1970, 1, 1, 0, 0, 0, 0)
            delta = datetime.timedelta(seconds=60 * 5)

            d1 = datetime.datetime(*date[0:6])
            now = datetime.datetime.utcnow()
            if d1 < epoch:
                return get_err_response('AccessDenied')

            # If the standard date is too far ahead or behind, it is an error
            if abs(d1 - now) > delta:
                return get_err_response('RequestTimeTooSkewed')

            # If there was an expiration date in the parameters, check it also
            if expdate:
                ex = datetime.datetime(*expdate[0:6])
                if (now > ex and (now - ex) > delta):
                    return get_err_response('RequestTimeTooSkewed')

        token = base64.urlsafe_b64encode(canonical_string(req))

        controller = controller(req, self.app, account, token, conf=self.conf,
                                **path_parts)

        if hasattr(controller, req.method):
            res = getattr(controller, req.method)(req)
        else:
            return get_err_response('MethodNotAllowed')

        return res


def filter_factory(global_conf, **local_conf):
    """Standard filter factory to use the middleware with paste.deploy"""
    conf = global_conf.copy()
    conf.update(local_conf)

    def swift3_filter(app):
        return Swift3Middleware(app, conf)

    return swift3_filter
