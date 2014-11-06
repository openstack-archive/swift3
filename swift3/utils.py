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

from swift3.cfg import CONF

LOGGER = get_logger(CONF, log_route='swift3')

# We can use a larger value if Swift supports system metadata for objects.
MAX_META_VALUE_LENGTH = 256


def sysmeta_prefix(resource):
    """
    Returns the system metadata prefix for given resource type.
    """
    if resource == 'object':
        # TODO: Return object-sysmeta-swift3 after Swift supports system
        # metadata for objects.

        # There is no worry that the user will use the same prefix for object
        # metadata.  S3 forbids including square brackets in the metadata name.
        return 'x-object-meta-[swift3]-'
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
