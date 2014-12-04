# Copyright (c) 2010-2014 OpenStack Foundation.
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
The swift3 middleware will emulate the S3 REST api on top of swift.

The following operations are currently supported:

    * GET Service
    * DELETE Bucket
    * GET Bucket (List Objects)
    * PUT Bucket
    * DELETE Object
    * Delete Multiple Objects
    * GET Object
    * HEAD Object
    * PUT Object
    * PUT Object (Copy)

To add this middleware to your configuration, add the swift3 middleware
in front of the auth middleware, and before any other middleware that
look at swift requests (like rate limiting).

To set up your client, the access key will be the concatenation of the
account and user strings that should look like test:tester, and the
secret access key is the account password.  The host should also point
to the swift storage hostname.  It also will have to use the old style
calling format, and not the hostname based container format.

An example client using the python boto library might look like the
following for an SAIO setup::

    from boto.s3.connection import S3Connection
    connection = S3Connection(
        aws_access_key_id='test:tester',
        aws_secret_access_key='testing',
        port=8080,
        host='127.0.0.1',
        is_secure=False,
        calling_format=boto.s3.connection.OrdinaryCallingFormat())
"""

import re
from paste.deploy import loadwsgi

from swift.common.wsgi import PipelineWrapper, loadcontext

from swift3.exception import NotS3Request
from swift3.request import Request
from swift3.response import ErrorResponse, InternalError, MethodNotAllowed, \
    ResponseBase
from swift3.cfg import CONF
from swift3.utils import LOGGER
from swift.common.utils import get_logger

SLO_ENABLED = True

def validate_bucket_name(name):
    """
    Validates the name of the bucket against S3 criteria,
    http://docs.amazonwebservices.com/AmazonS3/latest/BucketRestrictions.html
    True if valid, False otherwise
    """

    if '_' in name or len(name) < 3 or len(name) > 63 or not \
            name[-1].isalnum():
        # Bucket names should not contain underscores (_)
        # Bucket names must end with a lowercase letter or number
        # Bucket names should be between 3 and 63 characters long
        return False
    elif '.-' in name or '-.' in name or '..' in name or not name[0].isalnum():
        # Bucket names cannot contain dashes next to periods
        # Bucket names cannot contain two adjacent periods
        # Bucket names Must start with a lowercase letter or a number
        return False
    elif re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}"
                  "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", name):
        # Bucket names cannot be formatted as an IP Address
        return False
    else:
        return True


class Swift3Middleware(object):
    """Swift3 S3 compatibility midleware"""
    def __init__(self, app, *args, **kwargs):
        self.app = app
        self.slo_enabled = SLO_ENABLED

    def __call__(self, env, start_response):
        try:
            env['slo_enabled'] = self.slo_enabled
            req = Request(env)
            resp = self.handle_request(req)
        except NotS3Request:
            resp = self.app
        except ErrorResponse as err_resp:
            if isinstance(err_resp, InternalError):
                LOGGER.exception(err_resp)
            resp = err_resp
        except Exception as e:
            LOGGER.exception(e)
            resp = InternalError(reason=e)

        if isinstance(resp, ResponseBase) and 'swift.trans_id' in env:
            resp.headers['x-amz-id-2'] = env['swift.trans_id']
            resp.headers['x-amz-request-id'] = env['swift.trans_id']

        return resp(env, start_response)

    def handle_request(self, req):
        LOGGER.debug('Calling Swift3 Middleware')
        LOGGER.debug(req.__dict__)

        controller = req.controller(self.app)

        if hasattr(controller, req.method):
            res = getattr(controller, req.method)(req)
        else:
            raise MethodNotAllowed(req.method,
                                   req.controller.resource_type())

        return res


def check_filter_order(pipeline, required_filters):
    """
    Check that required filters are present in order in the pipeline.
    """
    try:
        indexes = [pipeline.index(f) for f in required_filters]
    except ValueError as e:
        LOGGER.debug(e)
        return False

    return indexes == sorted(indexes)


def check_pipeline():
    """
    Check that proxy-server.conf has an appropriate pipeline for swift3.
    """
    ctx = loadcontext(loadwsgi.APP, CONF.__file__)
    pipeline = str(PipelineWrapper(ctx)).split(' ')

    # Add compatible with 3rd party middleware.
    if check_filter_order(pipeline, ['swift3', 'proxy-server']):

        auth_pipeline = pipeline[pipeline.index('swift3') + 1:
                                 pipeline.index('proxy-server')]

        # Check SLO middleware
        if 'slo' not in auth_pipeline:
            global SLO_ENABLED
            SLO_ENABLED = False
            LOGGER.debug('swift3 middleware is required SLO middleware '
                         'to support multi-part upload, please add it '
                         'in pipline (%d)'% SLO_ENABLED)

        if 'tempauth' in auth_pipeline:
            LOGGER.debug('Use tempauth middleware.')
            return
        elif 'keystoneauth' in auth_pipeline:
            if check_filter_order(auth_pipeline, ['s3token',
                                                  'authtoken',
                                                  'keystoneauth']):
                LOGGER.debug('Use keystone middleware.')
                return

        elif len(auth_pipeline):
            LOGGER.debug('Use third party(unknown) auth middleware.')
            return

    raise ValueError('Invalid proxy pipeline: %s' % pipeline)


def filter_factory(global_conf, **local_conf):
    """Standard filter factory to use the middleware with paste.deploy"""
    CONF.update(global_conf)
    CONF.update(local_conf)

    # Reassign config to logger
    global LOGGER
    LOGGER = get_logger(CONF, log_route='swift3')

    check_pipeline()

    return Swift3Middleware
