# Copyright (c) 2014 OpenStack Foundation.
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

import re
import uuid
import base64


from swift.common.utils import get_logger

# Need for check_path_header
from swift.common import utils
from swift.common.swob import HTTPPreconditionFailed
from urllib import unquote

from swift3.cfg import CONF

LOGGER = get_logger(CONF, log_route='swift3')
MULTIUPLOAD_SUFFIX = '+segments'


def sysmeta_prefix(resource):
    """
    Returns the system metadata prefix for given resource type.
    """
    if resource == 'object':
        return 'x-object-sysmeta-swift3-'
    else:
        return 'x-container-sysmeta-swift3-'


def sysmeta_header(resource, name):
    """
    Returns the system metadata header for given resource type and name.
    """
    return sysmeta_prefix(resource) + name


def camel_to_snake(camel):
    return re.sub('(.)([A-Z])', r'\1_\2', camel).lower()


def snake_to_camel(snake):
    return snake.title().replace('_', '')


def unique_id():
    return base64.urlsafe_b64encode(str(uuid.uuid4()))


def utf8encode(s):
    if isinstance(s, unicode):
        s = s.encode('utf8')
    return s


def utf8decode(s):
    if isinstance(s, str):
        s = s.decode('utf8')
    return s


def check_path_header(req, name, length, error_msg):
    # FIXME: replace swift.common.constraints check_path_header
    #        when swift3 supports swift 2.2 or later
    """
    Validate that the value of path-like header is
    well formatted. We assume the caller ensures that
    specific header is present in req.headers.

    :param req: HTTP request object
    :param name: header name
    :param length: length of path segment check
    :param error_msg: error message for client
    :returns: A tuple with path parts according to length
    :raise: HTTPPreconditionFailed if header value
            is not well formatted.
    """
    src_header = unquote(req.headers.get(name))
    if not src_header.startswith('/'):
        src_header = '/' + src_header
    try:
        return utils.split_path(src_header, length, length, True)
    except ValueError:
        raise HTTPPreconditionFailed(
            request=req,
            body=error_msg)


def validate_bucket_name(name):
        """
        Validates the name of the bucket against S3 criteria,
        http://docs.amazonwebservices.com/AmazonS3/latest/BucketRestrictions.html
        True is valid, False is invalid.
        TODO:
            - Create an option to follow which region's rule
        """

        if len(name) < 3 or len(name) > 63 or not name[-1].isalnum():
            # FIXME: Bucket names should not contain underscores (_)
            # Bucket names must end with a letter or number
            # Bucket names should be between 3 and 63 characters long
            return False
        elif '.-' in name or '-.' in name or '..' in name or '+' in name or \
                not name[0].isalnum():
            # Bucket names cannot contain dashes next to periods
            # Bucket names cannot contain two adjacent periods
            # Bucket names cannot contain plus character
            # Bucket names Must start with a lowercase letter or a number
            return False
        elif re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.)"
                      "{3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",
                      name):
            # Bucket names cannot be formatted as an IP Address
            return False
        else:
            return True
