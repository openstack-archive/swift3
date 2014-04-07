# Copyright (c) 2012-2014 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Static Web Middleware for OpenStack Swift
"""
import pbr.version

__all__ = ['version_info', 'version']

# get version info using pbr.version.
# pbr version info is inferred from version in setup.cfg
# and and vcs information.
_version_info = pbr.version.VersionInfo('swift3')

#: Version string ``'major.minor.revision'``.
version = _version_info.version_string()

#: Version information ``(major, minor, revision)``.
version_info = version.split('.')
