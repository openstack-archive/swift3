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

from swift3.controllers.base import Controller
from swift3.etree import Element, SubElement, tostring
from swift3.response import HTTPOk


class ServiceController(Controller):
    """
    Handles account level requests.
    """
    def GET(self, req):
        """
        Handle GET Service request
        """
        resp = self.get_account(req, query={'format': 'json'})

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
