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

from swift3.response import S3NotImplemented
from swift3.utils import camel_to_snake

class Controller(object):
    """
    Base WSGI controller class for the middleware
    """
    def __init__(self, app, **kwargs):
        self.app = app

    @classmethod
    def resource_type(cls):
        """
        Returns the target resource type of this controller.
        """
        name = cls.__name__[:-len('Controller')]
        return camel_to_snake(name).upper()


class UnsupportedController(Controller):
    """
    Handles unsupported requests.
    """
    def __init__(self, app, **kwargs):
        raise S3NotImplemented('The requested resource is not implemented')
