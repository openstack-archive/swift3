# Copyright (c) 2011-2014 OpenStack Foundation.
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
import traceback
from swift3.test.functional.s3_test_client import Connection


class Swift3FunctionalTestCase(unittest.TestCase):
    def __init__(self, method_name):
        super(Swift3FunctionalTestCase, self).__init__(method_name)
        self.method_name = method_name

    def setUp(self):
        try:
            self.conn = Connection()
            self.conn.reset()
        except Exception:
            message = '%s got an error during initialize process.\n\n%s' % \
                      (self.method_name, traceback.format_exc())
            # TODO: Find a way to make this go to FAIL instead of Error
            self.fail(message)
