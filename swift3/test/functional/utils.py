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

import ConfigParser
import subprocess
import os
from swift3.etree import fromstring


def assert_common_response_headers(self, headers):
    self.assertTrue(headers['x-amz-id-2'] is not None)
    self.assertTrue(headers['x-amz-request-id'] is not None)
    self.assertTrue(headers['date'] is not None)
    # TODO; requires consideration
    # self.assertTrue(headers['server'] is not None)


def get_error_code(body):
    elem = fromstring(body, 'Error')
    return elem.find('Code').text


def create_proxy_server_conf(conf_path, org_conf_path, params):
    proxy_conf = ConfigParser.SafeConfigParser()
    proxy_conf.optionxform = str
    try:
        proxy_conf.read(org_conf_path)
    except IOError:
        raise IOError()

    swift3_sec = 'filter:swift3'
    for k, v in params.items():
        proxy_conf.set(swift3_sec, k, v)

    try:
        with open(conf_path, 'w') as fw:
            proxy_conf.write(fw)
    except IOError:
        raise IOError()


def restart_proxy_server_process(conf_path):
    cmd = '%s/run_proxy.sh %s' % (os.getenv('PWD'), conf_path)
    try:
        subprocess.call(cmd.split(" "))
    except subprocess.CalledProcessError:
        raise subprocess.CalledProcessError()


def reload_proxy_server_conf(params=None):
    conf_path = os.getenv('PROXY_CONF')
    if params:
        org_conf_path = conf_path
        conf_path = '%s/reload-proxy-server.conf' % os.getenv('CONF_DIR')
        create_proxy_server_conf(conf_path, org_conf_path, params)

    restart_proxy_server_process(conf_path)
