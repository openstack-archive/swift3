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

from swift3.cfg import Config


class TestSwift3Cfg(unittest.TestCase):
    def test_config(self):
        conf = Config(
            {
                'a': 'str',
                'b': 10,
                'c': True,
            }
        )

        conf.update(
            {
                'a': 'str2',
                'b': '100',
                'c': 'false',
            }
        )

        self.assertEquals(conf['a'], 'str2')
        self.assertEquals(conf['b'], 100)
        self.assertEquals(conf['c'], False)

if __name__ == '__main__':
    unittest.main()
