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

from simplejson import loads
import re

from swift.common.utils import get_logger
from swift.common.http import HTTP_OK
from swift.common.middleware.acl import parse_acl, referrer_allowed

from swift3.etree import fromstring, tostring, Element, SubElement
from swift3.exception import NotS3Request
from swift3.request import Request
from swift3.response import HTTPOk, ErrorResponse, AccessDenied, \
    InternalError, InvalidArgument, MalformedACLError, MethodNotAllowed, \
    NoSuchKey, S3NotImplemented

XMLNS_XSI = 'http://www.w3.org/2001/XMLSchema-instance'

MAX_BUCKET_LISTING = 1000

# List of  sub-resources that must be maintained as part of the HMAC
# signature string.
ALLOWED_SUB_RESOURCES = sorted([
    'acl', 'delete', 'lifecycle', 'location', 'logging', 'notification',
    'partNumber', 'policy', 'requestPayment', 'torrent', 'uploads', 'uploadId',
    'versionId', 'versioning', 'versions ', 'website'
])


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

    body = tostring(elem)

    return HTTPOk(body=body, content_type="text/plain")


def swift_acl_translate(acl, group='', user='', xml=False):
    """
    Takes an S3 style ACL and returns a list of header/value pairs that
    implement that ACL in Swift, or "NotImplemented" if there isn't a way to do
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
        return "NotImplemented"
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
    def __init__(self, app, conf, **kwargs):
        self.app = app
        self.conf = conf


class ServiceController(Controller):
    """
    Handles account level requests.
    """
    def GET(self, req):
        """
        Handle GET Service request
        """
        resp = req.get_response(self.app, query={'format': 'json'})

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

        body = tostring(elem)

        return HTTPOk(content_type='application/xml', body=body)


class BucketController(Controller):
    """
    Handles bucket request.
    """
    def HEAD(self, req):
        """
        Handle HEAD Bucket (Get Metadata) request
        """
        return req.get_response(self.app)

    def GET(self, req):
        """
        Handle GET Bucket (List Objects) request
        """
        if 'max-keys' in req.params:
            if req.params.get('max-keys').isdigit() is False:
                raise InvalidArgument('max-keys', req.params['max-keys'])

        max_keys = min(int(req.params.get('max-keys', MAX_BUCKET_LISTING)),
                       MAX_BUCKET_LISTING)

        query = {
            'format': 'json',
            'limit': max_keys + 1,
        }
        if 'marker' in req.params:
            query.update({'marker': req.params['marker']})
        if 'prefix' in req.params:
            query.update({'prefix': req.params['prefix']})
        if 'delimiter' in req.params:
            query.update({'delimiter': req.params['delimiter']})

        resp = req.get_response(self.app, query=query)

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
        SubElement(elem, 'Name').text = req.container_name

        for o in objects[:max_keys]:
            if 'subdir' not in o:
                contents = SubElement(elem, 'Contents')
                SubElement(contents, 'Key').text = o['name']
                SubElement(contents, 'LastModified').text = \
                    o['last_modified'] + 'Z'
                SubElement(contents, 'ETag').text = o['hash']
                SubElement(contents, 'Size').text = str(o['bytes'])
                add_canonical_user(contents, 'Owner', req.access_key)

        for o in objects[:max_keys]:
            if 'subdir' in o:
                common_prefixes = SubElement(elem, 'CommonPrefixes')
                SubElement(common_prefixes, 'Prefix').text = o['subdir']

        body = tostring(elem)

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
            if translated_acl == 'NotImplemented':
                raise S3NotImplemented()
            elif translated_acl == 'InvalidArgument':
                raise InvalidArgument('x-amz-acl', amz_acl)

            for header, acl in translated_acl:
                req.headers[header] = acl

        resp = req.get_response(self.app)
        resp.status = HTTP_OK
        resp.headers.update({'Location': req.container_name})

        return resp

    def DELETE(self, req):
        """
        Handle DELETE Bucket request
        """
        return req.get_response(self.app)

    def POST(self, req):
        """
        Handle POST Bucket request
        """
        raise S3NotImplemented()


class ObjectController(Controller):
    """
    Handles requests on objects
    """
    def GETorHEAD(self, req):
        resp = req.get_response(self.app)
        if req.method == 'HEAD':
            resp.app_iter = None

        return resp

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
        resp = req.get_response(self.app)

        if 'HTTP_X_COPY_FROM' in req.environ:
            elem = Element('CopyObjectResult')
            SubElement(elem, 'ETag').text = '"%s"' % resp.etag
            body = tostring(elem, use_s3ns=False)
            return HTTPOk(body=body)

        resp.status = HTTP_OK

        return resp

    def POST(self, req):
        raise AccessDenied()

    def DELETE(self, req):
        """
        Handle DELETE Object request
        """
        return req.get_response(self.app)


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
        resp = req.get_response(self.app, method='HEAD')

        return get_acl(req.access_key, resp.headers)

    def PUT(self, req):
        """
        Handles PUT Bucket acl and PUT Object acl.
        """
        if req.object_name:
            # Handle Object ACL
            raise S3NotImplemented()
        else:
            # Handle Bucket ACL

            # We very likely have an XML-based ACL request.
            translated_acl = swift_acl_translate(req.body, xml=True)
            if translated_acl == 'NotImplemented':
                raise S3NotImplemented()
            elif translated_acl == 'InvalidArgument':
                raise MalformedACLError()
            for header, acl in translated_acl:
                req.headers[header] = acl

            resp = req.get_response(self.app)
            resp.status = HTTP_OK
            resp.headers.update({'Location': req.container_name})

            return resp


class LocationController(Controller):
    """
    Handles GET Bucket location, which is logged as a LOCATION operation in the
    S3 server log.
    """
    def GET(self, req):
        """
        Handles GET Bucket location.
        """
        req.get_response(self.app, method='HEAD')

        elem = Element('LocationConstraint')
        if self.conf['location'] != 'US':
            elem.text = self.conf['location']
        body = tostring(elem)

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
        req.get_response(self.app, method='HEAD')

        # logging disabled
        elem = Element('BucketLoggingStatus')
        body = tostring(elem)

        return HTTPOk(body=body, content_type='application/xml')

    def PUT(self, req):
        """
        Handles PUT Bucket logging.
        """
        raise S3NotImplemented()


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
                raise S3NotImplemented()

            req.object_name = key

            try:
                req.get_response(self.app, method='DELETE')
            except NoSuchKey:
                pass
            except ErrorResponse as e:
                error = SubElement(elem, 'Error')
                SubElement(error, 'Key').text = key
                SubElement(error, 'Code').text = e.__class__.__name__
                SubElement(error, 'Message').text = e._msg
                continue

            deleted = SubElement(elem, 'Deleted')
            SubElement(deleted, 'Key').text = key

        body = tostring(elem)

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
        return req.get_response(self.app)


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
        return req.get_response(self.app)

    def POST(self, req):
        """
        Handles Initiate Multipart Upload.
        """
        # Pass it through, the s3multi upload helper will handle it.
        return req.get_response(self.app)


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
        return req.get_response(self.app)

    def DELETE(self, req):
        """
        Handles Abort Multipart Upload.
        """
        # Pass it through, the s3multi upload helper will handle it.
        return req.get_response(self.app)

    def POST(self, req):
        """
        Handles Complete Multipart Upload.
        """
        # Pass it through, the s3multi upload helper will handle it.
        return req.get_response(self.app)


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
        req.get_response(self.app, method='HEAD')

        # Just report there is no versioning configured here.
        elem = Element('VersioningConfiguration')
        body = tostring(elem)

        return HTTPOk(body=body, content_type="text/plain")

    def PUT(self, req):
        """
        Handles PUT Bucket versioning.
        """
        raise S3NotImplemented()


class Swift3Middleware(object):
    """Swift3 S3 compatibility midleware"""
    def __init__(self, app, conf, *args, **kwargs):
        self.app = app
        self.conf = conf
        self.logger = get_logger(self.conf, log_route='swift3')

    def __call__(self, env, start_response):
        try:
            req = Request(env)
            resp = self.handle_request(req)
        except NotS3Request:
            resp = self.app
        except ErrorResponse as err_resp:
            if isinstance(err_resp, InternalError):
                self.logger.exception(err_resp)
            resp = err_resp
        except Exception, e:
            self.logger.exception(e)
            resp = InternalError(reason=e)
        return resp(env, start_response)

    def handle_request(self, req):
        self.logger.debug('Calling Swift3 Middleware')
        self.logger.debug(req.__dict__)

        controller = req.controller(self.app, self.conf)

        if hasattr(controller, req.method):
            res = getattr(controller, req.method)(req)
        else:
            raise MethodNotAllowed()

        return res


def filter_factory(global_conf, **local_conf):
    """Standard filter factory to use the middleware with paste.deploy"""
    conf = global_conf.copy()
    conf.update(local_conf)

    def swift3_filter(app):
        return Swift3Middleware(app, conf)

    return swift3_filter
