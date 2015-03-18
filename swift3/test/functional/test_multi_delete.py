# Copyright (c) 2015 OpenStack Foundation
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

from swift3.test.functional.utils import assert_common_response_headers, \
    calculate_md5
from swift3.etree import fromstring, tostring, Element, SubElement
from swift3.test.functional import Swift3FunctionalTestCase


def _gen_multi_delete_xml(objects=None):
    elem = Element('Delete')

    for key in objects:
        obj = SubElement(elem, 'Object')
        SubElement(obj, 'Key').text = key

    return tostring(elem, use_s3ns=False)


class TestSwift3MultiDelete(Swift3FunctionalTestCase):
    def setUp(self):
        super(TestSwift3MultiDelete, self).setUp()

    def _prepare_test_delete_multi_objects(self, bucket, objects):
        self.conn.make_request('PUT', bucket)
        for obj in objects:
            self.conn.make_request('PUT', bucket, obj)

    def test_delete_multi_objects(self):
        bucket = 'bucket'
        put_objects = ['obj%s' % var for var in range(1, 5)]
        self._prepare_test_delete_multi_objects(bucket, put_objects)
        query = 'delete'

        # with an Object tag
        req_objects = ['obj1']
        xml = _gen_multi_delete_xml(req_objects)
        content_md5 = calculate_md5(xml)
        status, headers, body = \
            self.conn.make_request('POST', bucket, body=xml,
                                   headers={'Content-MD5': content_md5},
                                   query=query)
        self.assertEquals(status, 200)
        assert_common_response_headers(self, headers)
        self.assertTrue(headers['content-type'] is not None)
        self.assertEquals(headers['content-length'], str(len(body)))
        elem = fromstring(body)
        resp_objects = elem.findall('Deleted')
        self.assertEquals(len(resp_objects), len(req_objects))
        for o in resp_objects:
            self.assertTrue(o.find('Key').text in req_objects)

        # with multiple Object tags
        req_objects = ['obj2', 'obj3']
        xml = _gen_multi_delete_xml(req_objects)
        content_md5 = calculate_md5(xml)
        status, headers, body = \
            self.conn.make_request('POST', bucket, body=xml,
                                   headers={'Content-MD5': content_md5},
                                   query=query)
        self.assertEquals(status, 200)
        elem = fromstring(body, 'DeleteResult')
        resp_objects = elem.findall('Deleted')
        self.assertEquals(len(resp_objects), len(req_objects))
        for o in resp_objects:
            self.assertTrue(o.find('Key').text in req_objects)

        # with multiple Object tags including object does not exist in Swift
        req_objects = ['obj4', 'obj5']
        xml = _gen_multi_delete_xml(req_objects)
        content_md5 = calculate_md5(xml)
        status, headers, body = \
            self.conn.make_request('POST', bucket, body=xml,
                                   headers={'Content-MD5': content_md5},
                                   query=query)
        self.assertEquals(status, 200)
        elem = fromstring(body, 'DeleteResult')
        resp_objects = elem.findall('Deleted')
        self.assertEquals(len(resp_objects), len(req_objects))
        for o in resp_objects:
            self.assertTrue(o.find('Key').text in req_objects)

        # with multiple Object tags that objects do not exist in Swift
        req_objects = ['obj5', 'obj6']
        xml = _gen_multi_delete_xml(req_objects)
        content_md5 = calculate_md5(xml)
        status, headers, body = \
            self.conn.make_request('POST', bucket, body=xml,
                                   headers={'Content-MD5': content_md5},
                                   query=query)
        self.assertEquals(status, 200)
        elem = fromstring(body, 'DeleteResult')
        resp_objects = elem.findall('Deleted')
        self.assertEquals(len(resp_objects), len(req_objects))
        for o in resp_objects:
            self.assertTrue(o.find('Key').text in req_objects)
