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

from simplejson import loads

from swift.common.http import HTTP_OK

from swift3.controllers.base import Controller
from swift3.controllers.acl import handle_acl_header
from swift3.subresource import ACL, ACLPrivate
from swift3.etree import Element, SubElement, tostring, fromstring, \
    XMLSyntaxError, DocumentInvalid
from swift3.response import HTTPOk, S3NotImplemented, InvalidArgument, \
    MalformedXML, InvalidLocationConstraint
from swift3.cfg import CONF
from swift3.utils import LOGGER

MAX_PUT_BUCKET_BODY_SIZE = 10240


class BucketController(Controller):
    """
    Handles bucket request.
    """
    def HEAD(self, req):
        """
        Handle HEAD Bucket (Get Metadata) request
        """
        resp = req.get_response(self.app)
        resp.bucket_acl.check_permission(req.user_id, 'READ')

        return HTTPOk(headers=resp.headers)

    def GET(self, req):
        """
        Handle GET Bucket (List Objects) request
        """
        if 'max-keys' in req.params:
            if req.params.get('max-keys').isdigit() is False:
                raise InvalidArgument('max-keys', req.params['max-keys'])

        max_keys = int(req.params.get('max-keys', CONF.max_bucket_listing))
        max_keys = min(max_keys, CONF.max_bucket_listing)

        encoding_type = req.params.get('encoding-type')
        if encoding_type is not None and encoding_type != 'url':
            err_msg = 'Invalid Encoding Method specified in Request'
            raise InvalidArgument('encoding-type', encoding_type, err_msg)

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
        resp.bucket_acl.check_permission(req.user_id, 'READ')

        objects = loads(resp.body)

        elem = Element('ListBucketResult')
        SubElement(elem, 'Name').text = req.container_name
        SubElement(elem, 'Prefix').text = req.params.get('prefix')
        SubElement(elem, 'Marker').text = req.params.get('marker')
        SubElement(elem, 'MaxKeys').text = str(max_keys)

        if 'delimiter' in req.params:
            SubElement(elem, 'Delimiter').text = req.params['delimiter']

        if encoding_type is not None:
            SubElement(elem, 'EncodingType').text = encoding_type

        if max_keys > 0 and len(objects) == max_keys + 1:
            is_truncated = 'true'
        else:
            is_truncated = 'false'
        SubElement(elem, 'IsTruncated').text = is_truncated

        for o in objects[:max_keys]:
            if 'subdir' not in o:
                contents = SubElement(elem, 'Contents')
                SubElement(contents, 'Key').text = o['name']
                SubElement(contents, 'LastModified').text = \
                    o['last_modified'] + 'Z'
                SubElement(contents, 'ETag').text = o['hash']
                SubElement(contents, 'Size').text = str(o['bytes'])
                owner = SubElement(contents, 'Owner')
                SubElement(owner, 'ID').text = req.user_id
                SubElement(owner, 'DisplayName').text = req.user_id
                SubElement(contents, 'StorageClass').text = 'STANDARD'

        for o in objects[:max_keys]:
            if 'subdir' in o:
                common_prefixes = SubElement(elem, 'CommonPrefixes')
                SubElement(common_prefixes, 'Prefix').text = o['subdir']

        body = tostring(elem, encoding_type=encoding_type)

        return HTTPOk(body=body, content_type='application/xml')

    def PUT(self, req):
        """
        Handle PUT Bucket request
        """
        xml = req.xml(MAX_PUT_BUCKET_BODY_SIZE)
        if xml:
            # check location
            try:
                elem = fromstring(xml, 'CreateBucketConfiguration')
                location = elem.find('./LocationConstraint').text
            except (XMLSyntaxError, DocumentInvalid):
                raise MalformedXML()
            except Exception as e:
                LOGGER.error(e)
                raise

            if location != CONF.location:
                # Swift3 cannot support multiple reagions now.
                raise InvalidLocationConstraint()

        if CONF.s3_acl:
            acl = ACL.from_headers(req.headers, req.user_id)
            if acl is None:
                # The default acl is private.
                acl = ACLPrivate(req.user_id)

            # To avoid overwriting the existing bucket's ACL, we send PUT
            # request first before setting the ACL to make sure that the target
            # container does not exist.
            req.get_response(self.app)

            # update metadata
            req.bucket_acl = acl
            req.get_response(self.app, 'POST')
        else:
            if 'HTTP_X_AMZ_ACL' in req.environ:
                handle_acl_header(req)

            resp = req.get_response(self.app)

        resp.status = HTTP_OK
        resp.location = '/' + req.container_name

        return resp

    def DELETE(self, req):
        """
        Handle DELETE Bucket request
        """
        resp = req.get_response(self.app, 'HEAD')
        resp.bucket_acl.check_owner(req.user_id)

        return req.get_response(self.app)

    def POST(self, req):
        """
        Handle POST Bucket request
        """
        raise S3NotImplemented()
