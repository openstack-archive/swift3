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
import mock

from swift3 import utils

strs = [
    ('Owner', 'owner'),
    ('DisplayName', 'display_name'),
    ('AccessControlPolicy', 'access_control_policy'),
]


class TestSwift3Utils(unittest.TestCase):
    def test_camel_to_snake(self):
        for s1, s2 in strs:
            self.assertEquals(utils.camel_to_snake(s1), s2)

    def test_snake_to_camel(self):
        for s1, s2 in strs:
            self.assertEquals(s1, utils.snake_to_camel(s2))

    def test_validate_bucket_name(self):
        # good cases
        self.assertTrue(utils.validate_bucket_name('bucket'))
        self.assertTrue(utils.validate_bucket_name('bucket1'))
        self.assertTrue(utils.validate_bucket_name('bucket-1'))
        self.assertTrue(utils.validate_bucket_name('b.u.c.k.e.t'))
        self.assertTrue(utils.validate_bucket_name('a'*63))
        # bad cases
        self.assertFalse(utils.validate_bucket_name('a'))
        self.assertFalse(utils.validate_bucket_name('aa'))
        self.assertFalse(utils.validate_bucket_name('a+a'))
        self.assertFalse(utils.validate_bucket_name('a_a'))
        self.assertFalse(utils.validate_bucket_name('Bucket'))
        self.assertFalse(utils.validate_bucket_name('BUCKET'))
        self.assertFalse(utils.validate_bucket_name('bucket-'))
        self.assertFalse(utils.validate_bucket_name('bucket.'))
        self.assertFalse(utils.validate_bucket_name('bucket_'))
        self.assertFalse(utils.validate_bucket_name('bucket.-bucket'))
        self.assertFalse(utils.validate_bucket_name('bucket-.bucket'))
        self.assertFalse(utils.validate_bucket_name('bucket..bucket'))
        self.assertFalse(utils.validate_bucket_name('a'*64))

    def test_validate_bucket_name(self):

        class MockConf(object):
            def __init__(self):
                self.dns_compliant_bucket_names = False

        conf = MockConf()

        with mock.patch('swift3.utils.CONF', conf):
            # good cases
            self.assertTrue(utils.validate_bucket_name('bucket'))
            self.assertTrue(utils.validate_bucket_name('bucket1'))
            self.assertTrue(utils.validate_bucket_name('bucket-1'))
            self.assertTrue(utils.validate_bucket_name('b.u.c.k.e.t'))
            self.assertTrue(utils.validate_bucket_name('a'*63))
            self.assertTrue(utils.validate_bucket_name('a'*255))
            self.assertTrue(utils.validate_bucket_name('a_a'))
            self.assertTrue(utils.validate_bucket_name('Bucket'))
            self.assertTrue(utils.validate_bucket_name('BUCKET'))
            self.assertTrue(utils.validate_bucket_name('bucket-'))
            self.assertTrue(utils.validate_bucket_name('bucket_'))
            self.assertTrue(utils.validate_bucket_name('bucket.-bucket'))
            self.assertTrue(utils.validate_bucket_name('bucket-.bucket'))
            self.assertTrue(utils.validate_bucket_name('bucket..bucket'))
            # bad cases
            self.assertFalse(utils.validate_bucket_name('a'))
            self.assertFalse(utils.validate_bucket_name('aa'))
            self.assertFalse(utils.validate_bucket_name('a+a'))
            # ending with dot seems invalid in US standard, too
            self.assertFalse(utils.validate_bucket_name('bucket.'))
            self.assertFalse(utils.validate_bucket_name('a'*256))


if __name__ == '__main__':
    unittest.main()
