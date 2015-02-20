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

from boto.exception import BotoClientError, S3ResponseError
from swift3.etree import fromstring

RETRY_COUNT = 3


def cleanup(conn):
    conn = conn.connect()
    for i in range(0, RETRY_COUNT):
        buckets = conn.get_all_buckets()
        if not buckets:
            break
        for bucket in buckets:
            for obj in bucket.list():
                try:
                    bucket.delete_key(obj.name)
                except (BotoClientError, S3ResponseError):
                    pass
            try:
                conn.delete_bucket(bucket.name)
            except (BotoClientError, S3ResponseError):
                pass


def check_common_response_headers(self, headers):
    self.assertTrue(headers['x-amz-id-2'] is not None)
    self.assertTrue(headers['x-amz-request-id'] is not None)
    self.assertTrue(headers['date'] is not None)
    # TODO; requires consideration
    # self.assertTrue(headers['server'] is not None)


def get_error_code(body):
    elem = fromstring(body, 'Error')
    return elem.find('Code').text
