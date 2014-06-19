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
from datetime import datetime

from swift.common import swob
from swift.common.swob import Request

from swift3.test.unit import Swift3TestCase
from swift3.etree import tostring, Element, SubElement


class TestSwift3MultiDelete(Swift3TestCase):

    def setUp(self):
        super(TestSwift3MultiDelete, self).setUp()

    def test_object_multi_DELETE(self):
        self.swift.register('DELETE', '/v1/AUTH_test/bucket/Key1',
                            swob.HTTPNoContent, {}, None)
        self.swift.register('DELETE', '/v1/AUTH_test/bucket/Key2',
                            swob.HTTPNotFound, {}, None)

        elem = Element('Delete')
        for key in ['Key1', 'Key2']:
            obj = SubElement(elem, 'Object')
            SubElement(obj, 'Key').text = key
        body = tostring(elem, use_s3ns=False)

        req = Request.blank('/bucket?delete',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=body)
        req.date = datetime.now()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

if __name__ == '__main__':
    unittest.main()
