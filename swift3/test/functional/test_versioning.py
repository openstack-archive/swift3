# Copyright (c) 2017 OpenStack Foundation
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

import unittest

from swift3.test.functional.utils import get_error_code
from swift3.etree import fromstring, tostring, Element, SubElement
from swift3.test.functional import Swift3FunctionalTestCase


class TestSwift3Versioning(Swift3FunctionalTestCase):
    def setUp(self):
        super(TestSwift3Versioning, self).setUp()
        status, headers, body = self.conn.make_request('PUT', 'bucket')
        self.assertEqual(status, 200)

    def test_versioning_put(self):
        # Versioning not configured
        status, headers, body = self.conn.make_request(
            'GET', 'bucket', query='versioning')
        self.assertEqual(status, 200)
        elem = fromstring(body)
        self.assertEqual(elem.getchildren(), [])

        # Enable versioning
        elem = Element('VersioningConfiguration')
        SubElement(elem, 'Status').text = 'Enabled'
        xml = tostring(elem)
        status, headers, body = self.conn.make_request(
            'PUT', 'bucket', body=xml, query='versioning')
        self.assertEqual(status, 200)

        status, headers, body = self.conn.make_request(
            'GET', 'bucket', query='versioning')
        self.assertEqual(status, 200)
        elem = fromstring(body)
        self.assertEqual(elem.find('./Status').text, 'Enabled')

        # Suspend versioning
        elem = Element('VersioningConfiguration')
        SubElement(elem, 'Status').text = 'Suspended'
        xml = tostring(elem)
        status, headers, body = self.conn.make_request(
            'PUT', 'bucket', body=xml, query='versioning')
        self.assertEqual(status, 200)

        status, headers, body = self.conn.make_request(
            'GET', 'bucket', query='versioning')
        self.assertEqual(status, 200)
        elem = fromstring(body)
        self.assertEqual(elem.find('./Status').text, 'Suspended')

    def test_versioning_put_error(self):
        # Root tag is not VersioningConfiguration
        elem = Element('foo')
        SubElement(elem, 'Status').text = 'Enabled'
        xml = tostring(elem)
        status, headers, body = self.conn.make_request(
            'PUT', 'bucket', body=xml, query='versioning')
        self.assertEqual(status, 400)
        self.assertEqual(get_error_code(body), 'MalformedXML')

        # Status is not "Enabled" or "Suspended"
        elem = Element('VersioningConfiguration')
        SubElement(elem, 'Status').text = '...'
        xml = tostring(elem)
        status, headers, body = self.conn.make_request(
            'PUT', 'bucket', body=xml, query='versioning')
        self.assertEqual(status, 400)
        self.assertEqual(get_error_code(body), 'MalformedXML')


if __name__ == '__main__':
    unittest.main()
