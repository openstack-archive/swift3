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
from lxml.etree import fromstring, tostring, Element, SubElement

from simplejson import loads
import email.utils
import datetime
import re

from swift.common.utils import get_logger
from swift.common.swob import Request, Response, HTTPForbidden, HTTPConflict, \
    HTTPBadRequest, HTTPMethodNotAllowed, HTTPNotFound, HTTPNotImplemented, \
    HTTPLengthRequired, HTTPServiceUnavailable, HTTPNoContent, HTTPOk, \
    HTTPInternalServerError
from swift.common.http import HTTP_OK, HTTP_CREATED, HTTP_ACCEPTED, \
    HTTP_NO_CONTENT, HTTP_UNAUTHORIZED, HTTP_FORBIDDEN, HTTP_NOT_FOUND, \
    HTTP_CONFLICT, HTTP_UNPROCESSABLE_ENTITY, is_success, \
    HTTP_REQUEST_ENTITY_TOO_LARGE
from swift.common.middleware.acl import parse_acl, referrer_allowed

XMLNS_XSI = 'http://www.w3.org/2001/XMLSchema-instance'

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

    elem = Element('Error')
    SubElement(elem, 'Code').text = code
    SubElement(elem, 'Message').text = message
    body = tostring(elem, xml_declaration=True, encoding='UTF-8')

    return resp(body=body, content_type='text/xml')


def add_canonical_user(parent, tag, user, nsmap=None):
    """
    Create an element for cannonical user.
    """
    elem = SubElement(parent, tag, nsmap=nsmap)
    SubElement(elem, 'ID').text = user
    SubElement(elem, 'DisplayName').text = user

    return elem


def get_acl(account_name, headers):
    """
    Attempts to construct an S3 ACL based on what is found in the swift headers
    """

    elem = Element('AccessControlPolicy')
    add_canonical_user(elem, 'Owner', account_name)
    access_control_list = SubElement(elem, 'AccessControlList')

    # grant FULL_CONTROL to myself by default
    grant = SubElement(access_control_list, 'Grant')
    grantee = add_canonical_user(grant, 'Grantee', account_name,
                                 nsmap={'xsi': XMLNS_XSI})
    grantee.set('{%s}type' % XMLNS_XSI, 'CanonicalUser')
    SubElement(grant, 'Permission').text = 'FULL_CONTROL'

    referrers, _ = parse_acl(headers.get('x-container-read'))
    if referrer_allowed('unknown', referrers):
        # grant public-read access
        grant = SubElement(access_control_list, 'Grant')
        grantee = SubElement(grant, 'Grantee', nsmap={'xsi': XMLNS_XSI})
        grantee.set('{%s}type' % XMLNS_XSI, 'Group')
        SubElement(grantee, 'URI').text = \
            'http://acs.amazonaws.com/groups/global/AllUsers'
        SubElement(grant, 'Permission').text = 'READ'

    referrers, _ = parse_acl(headers.get('x-container-write'))
    if referrer_allowed('unknown', referrers):
        # grant public-write access
        grant = SubElement(access_control_list, 'Grant')
        grantee = SubElement(grant, 'Grantee', nsmap={'xsi': XMLNS_XSI})
        grantee.set('{%s}type' % XMLNS_XSI, 'Group')
        SubElement(grantee, 'URI').text = \
            'http://acs.amazonaws.com/groups/global/AllUsers'
        SubElement(grant, 'Permission').text = 'WRITE'

    body = tostring(elem, xml_declaration=True, encoding='UTF-8')

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
        elem = fromstring(acl)
        acl = 'unknown'
        for grant in elem.findall('./AccessControlList/Grant'):
            permission = grant.find('./Permission').text
            grantee = grant.find('./Grantee').get('{%s}type' % XMLNS_XSI)
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
    def __init__(self, req, app, account_name, token, conf,
                 container_name=None, object_name=None, **kwargs):
        self.app = app
        self.conf = conf
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
        elem = Element('ListAllMyBucketsResult')
        buckets = SubElement(elem, 'Buckets')
        for c in containers:
            bucket = SubElement(buckets, 'Bucket')
            SubElement(bucket, 'Name').text = c['name']
            SubElement(bucket, 'CreationDate').text = \
                '2009-02-03T16:45:09.000Z'

        body = tostring(elem, xml_declaration=True, encoding='UTF-8')

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

        if 'x-container-object-count' in headers:
            headers['x-rgw-object-count'] = headers['x-container-object-count']
        if 'x-container-bytes-used' in headers:
            headers['x-rgw-bytes-used'] = headers['x-container-bytes-used']

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

        elem = Element('ListBucketResult')
        SubElement(elem, 'Prefix').text = req.params.get('prefix')
        SubElement(elem, 'Marker').text = req.params.get('marker')
        SubElement(elem, 'Delimiter').text = req.params.get('delimiter')
        if max_keys > 0 and len(objects) == max_keys + 1:
            is_truncated = 'true'
        else:
            is_truncated = 'false'
        SubElement(elem, 'IsTruncated').text = is_truncated
        SubElement(elem, 'MaxKeys').text = str(max_keys)
        SubElement(elem, 'Name').text = self.container_name

        for o in objects[:max_keys]:
            if 'subdir' not in o:
                contents = SubElement(elem, 'Contents')
                SubElement(contents, 'Key').text = o['name']
                SubElement(contents, 'LastModified').text = \
                    o['last_modified'] + 'Z'
                SubElement(contents, 'ETag').text = o['hash']
                SubElement(contents, 'Size').text = str(o['bytes'])
                add_canonical_user(contents, 'Owner', self.account_name)

        for o in objects[:max_keys]:
            if 'subdir' in o:
                common_prefixes = SubElement(elem, 'CommonPrefixes')
                SubElement(common_prefixes, 'Prefix').text = o['subdir']

        body = tostring(elem, xml_declaration=True, encoding='UTF-8')

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
            new_hdrs = {}
            for key, val in headers.iteritems():
                _key = key.lower()
                if _key.startswith('x-object-meta-'):
                    new_hdrs['x-amz-meta-' + key[14:]] = val
                elif _key in ('content-length', 'content-type',
                              'content-range', 'content-encoding',
                              'etag', 'last-modified'):
                    new_hdrs[key] = val
            return Response(status=status, headers=new_hdrs,
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
            elem = Element('CopyObjectResult')
            SubElement(elem, 'ETag').text = '"%s"' % resp.etag
            body = tostring(elem, xml_declaration=True, encoding='UTF-8')
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

        elem = Element('LocationConstraint')
        if self.conf['location'] != 'US':
            elem.text = self.conf['location']
        body = tostring(elem, xml_declaration=True, encoding='UTF-8')

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
        elem = Element('BucketLoggingStatus')
        body = tostring(elem, xml_declaration=True, encoding='UTF-8')

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
            elem = fromstring(xml)
            for obj in elem.iterchildren('Object'):
                key = obj.find('./Key').text
                version = obj.find('./VersionId')
                if version is not None:
                    version = version.text

                yield (key, version)

        elem = Element('DeleteResult')

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
                deleted = SubElement(elem, 'Deleted')
                SubElement(deleted, 'Key').text = key
            else:
                error = SubElement(elem, 'Error')
                SubElement(error, 'Key').text = key
                if status == HTTP_UNAUTHORIZED:
                    SubElement(error, 'Code').text = 'AccessDenied'
                    SubElement(error, 'Message').text = 'Access Denied'
                else:
                    SubElement(error, 'Code').text = 'InternalError'
                    SubElement(error, 'Message').text = 'Internal Error'

        body = tostring(elem, xml_declaration=True, encoding='UTF-8')

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
        elem = Element('VersioningConfiguration')
        body = tostring(elem, xml_declaration=True, encoding='UTF-8')

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
                return get_err_response('AccessDenied')

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
            now = datetime.datetime.utcnow()
            date = email.utils.parsedate(req.headers['Date'])
            if 'Expires' in req.params:
                try:
                    d = email.utils.formatdate(float(req.params['Expires']))
                except ValueError:
                    return get_err_response('AccessDenied')

                # check expiration
                expdate = email.utils.parsedate(d)
                ex = datetime.datetime(*expdate[0:6])
                if now > ex:
                    return get_err_response('AccessDenied')
            elif date is not None:
                epoch = datetime.datetime(1970, 1, 1, 0, 0, 0, 0)

                d1 = datetime.datetime(*date[0:6])
                if d1 < epoch:
                    return get_err_response('AccessDenied')

                # If the standard date is too far ahead or behind, it is an
                # error
                delta = datetime.timedelta(seconds=60 * 5)
                if abs(d1 - now) > delta:
                    return get_err_response('RequestTimeTooSkewed')
            else:
                return get_err_response('AccessDenied')

        token = base64.urlsafe_b64encode(canonical_string(req))

        controller = controller(req, self.app, account, token, self.conf,
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
