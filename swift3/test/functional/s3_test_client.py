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

import os
from boto.s3.connection import S3Connection, OrdinaryCallingFormat, \
    BotoClientError, S3ResponseError
from swift3.response import NoSuchKey, NoSuchBucket
from swiftclient.client import get_auth
from swiftclient import Connection as swConnection
from swiftclient import ClientException

RETRY_COUNT = 3


class Connection(object):
    """
    Swift3 Connection class used for S3 functional testing.
    """
    def __init__(self, aws_access_key=os.environ.get('ADMIN_ACCESS_KEY'),
                 aws_secret_key=os.environ.get('ADMIN_SECRET_KEY'),
                 user_id='%s:%s' % (os.environ.get('ADMIN_TENANT'),
                                    os.environ.get('ADMIN_USER'))):
        """
        Initialize method.

        :param aws_access_key: a string of aws access key
        :param aws_secret_key: a string of aws secret key
        :param user_id: a string consists of TENANT and USER name used for
                        asserting Owner ID (not required S3Connection)

        In default, Connection class will be initialized as admin user
        behaves as:
        user_test_admin = admin .admin

        """
        self.aws_access_key = aws_access_key
        self.aws_secret_key = aws_secret_key
        self.user_id = user_id
        swift_host = os.environ.get('SWIFT_HOST').split(':')
        self.host = swift_host[0]
        self.port = int(swift_host[1]) if len(swift_host) == 2 else 80
        self.conn = \
            S3Connection(aws_access_key, aws_secret_key, is_secure=False,
                         host=self.host, port=self.port,
                         calling_format=OrdinaryCallingFormat())

    def reset(self):
        """
        Reset all swift environment to keep clean. As a result by calling this
        method, we can assume the backend swift keeps no containers and no
        objects on this connection's account.
        This method can't delete segments of multipart upload. When s3_acl is
        enabled, it can't delete container and object without permission.
        """
        exceptions = []
        for i in range(RETRY_COUNT):
            try:
                buckets = self.conn.get_all_buckets()
                if not buckets:
                    break
                for bucket in buckets:
                    for obj in bucket.list():
                        try:
                            bucket.delete_key(obj.name)
                        except NoSuchKey:
                            pass
                    try:
                        self.conn.delete_bucket(bucket.name)
                    except NoSuchBucket:
                        pass
            except (BotoClientError, S3ResponseError) as e:
                exceptions.append(e)
        if exceptions:
            # raise the first exception
            raise exceptions.pop(0)

    def make_request(self, method, bucket='', obj='', headers=None, body='',
                     query=None):
        """
        Wrapper method of S3Connection.make_request.

        :param method: a string of HTTP request method
        :param bucket: a string of bucket name
        :param obj: a string of object name
        :param headers: a dictionary of headers
        :param body: a string of data binary sent to S3 as a request body
        :param query: a string of HTTP query argument

        :returns: a tuple of (int(status_code), headers dict, resposne body)
        """
        response = \
            self.conn.make_request(method, bucket=bucket, key=obj,
                                   headers=headers, data=body,
                                   query_args=query, sender=None,
                                   override_num_retries=RETRY_COUNT,
                                   retry_handler=None)
        return response.status, dict(response.getheaders()), response.read()


def get_tester_connection():
    """
    Return tester connection behaves as:
    user_test_tester = testing .admin
    """
    aws_access_key = os.environ.get('TESTER_ACCESS_KEY')
    aws_secret_key = os.environ.get('TESTER_SECRET_KEY')
    user_id = os.environ.get('TESTER_TENANT') + ':' + \
        os.environ.get('TESTER_USER')
    return Connection(aws_access_key, aws_secret_key, user_id)


def get_tester2_connection():
    """
    Return tester2 connection behaves as:
    user_test_tester2 = testing2 .admin
    """
    aws_access_key = os.environ.get('TESTER2_ACCESS_KEY')
    aws_secret_key = os.environ.get('TESTER2_SECRET_KEY')
    user_id = os.environ.get('TESTER2_TENANT') + ':' + \
        os.environ.get('TESTER2_USER')
    return Connection(aws_access_key, aws_secret_key, user_id)


class SwiftConnection(object):
    """
    Swift Connection class used for S3 functional testing.
    """
    def __init__(self, auth_tenant=os.environ.get('ADMIN_TENANT'),
                 auth_user=os.environ.get('ADMIN_USER'),
                 auth_pass=os.environ.get('ADMIN_PASS')):
        """
        Initialize method.

        :param auth_tenant: a string of TENANT name
        :param auth_user: a string of USER name
        :param auth_pass: a string of USER password

        In default, Swift3 Connection class will be initialized as admin user
        behaves as:
        user_test_admin = admin .admin

        """
        auth_version = 2
        if os.environ.get('AUTH') == 'tempauth':
            auth_version = 1
            auth_user = '%s:%s' % (auth_tenant, auth_user)

        url, token = get_auth(os.environ.get('OS_AUTH_URL'),
                              auth_user,
                              auth_pass,
                              tenant_name=auth_tenant,
                              auth_version=auth_version)
        self.conn = swConnection(preauthurl=url, preauthtoken=token)

    def reset(self):
        """
        Reset all swift environment to keep clean. As a result by calling this
        method, we can assume the backend swift keeps no containers and no
        objects on this connection's account.
        """
        exceptions = []
        for i in range(RETRY_COUNT):
            try:
                buckets = self.conn.get_account()
                if not buckets:
                    break
                for bucket in buckets:
                    for obj in self.conn.get_container(bucket):
                        try:
                            isinstance(obj, dict)
                            self.conn.delete_object(bucket, obj['name'])
                        except ClientException:
                            pass
                    try:
                        self.conn.delete_container(bucket)
                    except ClientException:
                        pass
            except ClientException:
                buckets = None
        if exceptions:
            # raise the first exception
            raise exceptions.pop(0)
