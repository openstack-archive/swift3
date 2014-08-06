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

if __name__ == '__main__':
    unittest.main()
