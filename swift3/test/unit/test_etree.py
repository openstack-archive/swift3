# Copyright (c) 2014 OpenStack Foundation
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

from swift3 import etree


class TestSwift3Etree(unittest.TestCase):
    def test_xml_namespace(self):
        def test_xml(ns, prefix):
            return '<A %(ns)s><%(prefix)sB>C</%(prefix)sB></A>' % \
                ({'ns': ns, 'prefix': prefix})

        # No namespace is same as having the S3 namespace.
        xml = test_xml('', '')
        elem = etree.fromstring(xml)
        self.assertEquals(elem.find('./B').text, 'C')

        # The S3 namespace is handled as no namespace.
        xml = test_xml('xmlns="%s"' % etree.XMLNS_S3, '')
        elem = etree.fromstring(xml)
        self.assertEquals(elem.find('./B').text, 'C')

        xml = test_xml('xmlns:s3="%s"' % etree.XMLNS_S3, 's3:')
        elem = etree.fromstring(xml)
        self.assertEquals(elem.find('./B').text, 'C')

        # Any namespaces without a prefix work as no namespace.
        xml = test_xml('xmlns="http://example.com/"', '')
        elem = etree.fromstring(xml)
        self.assertEquals(elem.find('./B').text, 'C')

        xml = test_xml('xmlns:s3="http://example.com/"', 's3:')
        elem = etree.fromstring(xml)
        self.assertEquals(elem.find('./B'), None)

    def test_xml_with_comments(self):
        xml = '<A><!-- comment --><B>C</B></A>'
        elem = etree.fromstring(xml)
        self.assertEquals(elem.find('./B').text, 'C')

    def test_tostring_non_ascii(self):
        non_ascii = '\xef\xbc\xa1'
        elem = etree.Element('Element')
        obj = etree.SubElement(elem, 'Object')
        etree.SubElement(obj, 'Key').text = non_ascii.decode('utf-8')
        string = etree.tostring(elem, use_s3ns=False)
        self.assertEquals(string.count(non_ascii), 1)


if __name__ == '__main__':
    unittest.main()
