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

from swift3.controllers.base import Controller
from swift3.etree import Element, SubElement, fromstring, tostring
from swift3.response import HTTPOk, S3NotImplemented, NoSuchKey, ErrorResponse


class MultiObjectDeleteController(Controller):
    """
    Handles Delete Multiple Objects, which is logged as a MULTI_OBJECT_DELETE
    operation in the S3 server log.
    """
    def POST(self, req):
        """
        Handles Delete Multiple Objects.
        """
        def object_key_iter(xml):
            elem = fromstring(xml)
            for obj in elem.iterchildren('Object'):
                key = obj.find('./Key').text
                version = obj.find('./VersionId')
                if version is not None:
                    version = version.text

                yield (key, version)

        elem = Element('DeleteResult')

        for key, version in object_key_iter(req.body):
            if version is not None:
                # TODO: delete the specific version of the object
                raise S3NotImplemented()

            req.object_name = key

            try:
                self.delete_object(req)
            except NoSuchKey:
                pass
            except ErrorResponse as e:
                error = SubElement(elem, 'Error')
                SubElement(error, 'Key').text = key
                SubElement(error, 'Code').text = e.__class__.__name__
                SubElement(error, 'Message').text = e._msg
                continue

            deleted = SubElement(elem, 'Deleted')
            SubElement(deleted, 'Key').text = key

        body = tostring(elem)

        return HTTPOk(body=body)
