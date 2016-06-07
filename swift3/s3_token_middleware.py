# Copyright 2012 OpenStack Foundation
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# Copyright 2011,2012 Akira YOSHIYAMA <akirayoshiyama@gmail.com>
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

# This source code is based ./auth_token.py and ./ec2_token.py.
# See them for their copyright.

"""
S3 Token Middleware

This WSGI component:

* Gets a request from the swift3 middleware with an S3 Authorization
  access key.
* Validates s3 token in Keystone.
* Transforms the account name to AUTH_%(tenant_name).

"""

import json
import logging

import requests
import six

from swift.common.swob import Request, Response
from swift.common.utils import config_true_value, split_path


PROTOCOL_NAME = 'S3 Token Authentication'


class ServiceError(Exception):
    pass


class S3Token(object):
    """Middleware that handles S3 authentication."""

    def __init__(self, app, conf):
        """Common initialization code."""
        self._app = app
        self._logger = logging.getLogger(conf.get('log_name', __name__))
        self._logger.debug('Starting the %s component', PROTOCOL_NAME)
        self._reseller_prefix = conf.get('reseller_prefix', 'AUTH_')
        self._delay_auth_decision = config_true_value(
            conf.get('delay_auth_decision'))

        # where to find the auth service (we use this to validate tokens)
        self._request_uri = conf.get('auth_uri')
        if not self._request_uri:
            self._logger.warning(
                "Use of the auth_host, auth_port, and auth_protocol "
                "configuration options was deprecated in the Newton release "
                "in favor of auth_uri. These options may be removed in a "
                "future release.")
            auth_host = conf.get('auth_host')
            auth_port = int(conf.get('auth_port', 35357))
            auth_protocol = conf.get('auth_protocol', 'https')

            self._request_uri = '%s://%s:%s' % (auth_protocol, auth_host,
                                                auth_port)
        self._request_uri = self._request_uri.rstrip('/')

        # SSL
        insecure = config_true_value(conf.get('insecure'))
        cert_file = conf.get('certfile')
        key_file = conf.get('keyfile')

        if insecure:
            self._verify = False
        elif cert_file and key_file:
            self._verify = (cert_file, key_file)
        elif cert_file:
            self._verify = cert_file
        else:
            self._verify = None

    def _deny_request(self, code):
        error_table = {
            'AccessDenied': (401, 'Access denied'),
            'InvalidURI': (400, 'Could not parse the specified URI'),
        }
        resp = Response(content_type='text/xml')
        resp.status = error_table[code][0]
        error_msg = ('<?xml version="1.0" encoding="UTF-8"?>\r\n'
                     '<Error>\r\n  <Code>%s</Code>\r\n  '
                     '<Message>%s</Message>\r\n</Error>\r\n' %
                     (code, error_table[code][1]))
        if six.PY3:
            error_msg = error_msg.encode()
        resp.body = error_msg
        return resp

    def _json_request(self, creds_json):
        headers = {'Content-Type': 'application/json'}
        try:
            response = requests.post('%s/v2.0/s3tokens' % self._request_uri,
                                     headers=headers, data=creds_json,
                                     verify=self._verify)
        except requests.exceptions.RequestException as e:
            self._logger.info('HTTP connection exception: %s', e)
            resp = self._deny_request('InvalidURI')
            raise ServiceError(resp)

        if response.status_code < 200 or response.status_code >= 300:
            self._logger.debug('Keystone reply error: status=%s reason=%s',
                               response.status_code, response.reason)
            resp = self._deny_request('AccessDenied')
            raise ServiceError(resp)

        return response

    def __call__(self, environ, start_response):
        """Handle incoming request. authenticate and send downstream."""
        req = Request(environ)
        self._logger.debug('Calling S3Token middleware.')

        try:
            parts = split_path(req.path, 1, 4, True)
            version, account, container, obj = parts
        except ValueError:
            msg = 'Not a path query, skipping.'
            self._logger.debug(msg)
            return self._app(environ, start_response)

        # Read request signature and access id.
        if 'Authorization' not in req.headers:
            msg = 'No Authorization header. skipping.'
            self._logger.debug(msg)
            return self._app(environ, start_response)

        token = req.headers.get('X-Auth-Token',
                                req.headers.get('X-Storage-Token'))
        if not token:
            msg = 'You did not specify an auth or a storage token. skipping.'
            self._logger.debug(msg)
            return self._app(environ, start_response)

        auth_header = req.headers['Authorization']
        try:
            access, signature = auth_header.split(' ')[-1].rsplit(':', 1)
        except ValueError:
            if self._delay_auth_decision:
                self._logger.debug('Invalid Authorization header: %s - '
                                   'deferring reject downstream', auth_header)
                return self._app(environ, start_response)
            else:
                self._logger.debug('Invalid Authorization header: %s - '
                                   'rejecting request', auth_header)
                return self._deny_request('InvalidURI')(
                    environ, start_response)

        # NOTE(chmou): This is to handle the special case with nova
        # when we have the option s3_affix_tenant. We will force it to
        # connect to another account than the one
        # authenticated. Before people start getting worried about
        # security, I should point that we are connecting with
        # username/token specified by the user but instead of
        # connecting to its own account we will force it to go to an
        # another account. In a normal scenario if that user don't
        # have the reseller right it will just fail but since the
        # reseller account can connect to every account it is allowed
        # by the swift_auth middleware.
        force_tenant = None
        if ':' in access:
            access, force_tenant = access.split(':')

        # Authenticate request.
        creds = {'credentials': {'access': access,
                                 'token': token,
                                 'signature': signature}}
        creds_json = json.dumps(creds)
        self._logger.debug('Connecting to Keystone sending this JSON: %s',
                           creds_json)
        # NOTE(vish): We could save a call to keystone by having
        #             keystone return token, tenant, user, and roles
        #             from this call.
        #
        # NOTE(chmou): We still have the same problem we would need to
        #              change token_auth to detect if we already
        #              identified and not doing a second query and just
        #              pass it through to swiftauth in this case.
        try:
            resp = self._json_request(creds_json)
        except ServiceError as e:
            resp = e.args[0]  # NB: swob.Response, not requests.Response
            if self._delay_auth_decision:
                msg = 'Received error, deferring rejection based on error: %s'
                self._logger.debug(msg, resp.status)
                return self._app(environ, start_response)
            else:
                msg = 'Received error, rejecting request with error: %s'
                self._logger.debug(msg, resp.status)
                return resp(environ, start_response)

        self._logger.debug('Keystone Reply: Status: %d, Output: %s',
                           resp.status_code, resp.content)

        try:
            identity_info = resp.json()
            token_id = str(identity_info['access']['token']['id'])
            tenant = identity_info['access']['token']['tenant']
        except (ValueError, KeyError):
            if self._delay_auth_decision:
                error = ('Error on keystone reply: %d %s - '
                         'deferring rejection downstream')
                self._logger.debug(error, resp.status_code, resp.content)
                return self._app(environ, start_response)
            else:
                error = ('Error on keystone reply: %d %s - '
                         'rejecting request')
                self._logger.debug(error, resp.status_code, resp.content)
                return self._deny_request('InvalidURI')(
                    environ, start_response)

        req.headers['X-Auth-Token'] = token_id
        tenant_to_connect = force_tenant or tenant['id']
        if six.PY2 and isinstance(tenant_to_connect, six.text_type):
            tenant_to_connect = tenant_to_connect.encode('utf-8')
        self._logger.debug('Connecting with tenant: %s', tenant_to_connect)
        new_tenant_name = '%s%s' % (self._reseller_prefix, tenant_to_connect)
        environ['PATH_INFO'] = environ['PATH_INFO'].replace(account,
                                                            new_tenant_name)
        return self._app(environ, start_response)


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return S3Token(app, conf)
    return auth_filter
