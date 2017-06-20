# Copyright (c) 2017 OpenStack Foundation.
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

"""
S3 Auth Middleware

Perform authentication by using a secret key set on the account metadata.

* Get a request from the swift3 middleware with a check_signature method.
* Retrieve secret key from account meta data called s3-secret.
* Verify request with check_signature method and secret.

"""

from swift.common.swob import wsgify
from swift.proxy.controllers.base import get_info

from swift3.response import AccessDenied, SignatureDoesNotMatch


class S3Auth(object):
    """Middleware that authenticates an S3 request with check_signature."""

    def __init__(self, app, conf):
        self.app = app

    @wsgify
    def __call__(self, request):
        if 'swift3.auth_details' in request.environ:
            auth_details = request.environ['swift3.auth_details']
            secret = get_info(
                self.app, request.environ,
                auth_details['access_key'])['meta'].get('s3-secret')
            if secret:
                if auth_details['check_signature'](secret):
                    request.environ['swift.authorize_override'] = True
                    request.environ['swift.authorize'] = lambda req: None
                else:
                    return SignatureDoesNotMatch()
            else:
                return AccessDenied()

        return self.app


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def s3auth_filter(app):
        return S3Auth(app, conf)
    return s3auth_filter
