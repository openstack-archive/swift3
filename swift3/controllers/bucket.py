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
from swift3.controllers.acl import add_canonical_user, swift_acl_translate
from swift3.etree import Element, SubElement, tostring
from swift3.response import HTTPOk, S3NotImplemented, InvalidArgument

MAX_BUCKET_LISTING = 1000


class BucketController(Controller):
    """
    Handles bucket request.
    """
    def HEAD(self, req):
        """
        Handle HEAD Bucket (Get Metadata) request
        """
        resp = req.get_response(self.app)

        return HTTPOk(headers=resp.headers)

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
        SubElement(elem, 'Name').text = req.container_name
        SubElement(elem, 'Prefix').text = req.params.get('prefix')
        SubElement(elem, 'Marker').text = req.params.get('marker')
        SubElement(elem, 'MaxKeys').text = str(max_keys)
        SubElement(elem, 'Delimiter').text = req.params.get('delimiter')
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
                add_canonical_user(contents, 'Owner', req.user_id)
                SubElement(contents, 'StorageClass').text = 'STANDARD'

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
        resp.headers.update({'Location': '/' + req.container_name})

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
