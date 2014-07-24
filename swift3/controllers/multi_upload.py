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

from swift3.controllers.base import Controller, bucket_operation, \
    object_operation
from swift3.response import InvalidRequest


class PartController(Controller):
    """
    Handles the following APIs:

     - Upload Part
     - Upload Part - Copy

    Those APIs are logged as PART operations in the S3 server log.
    """
    @object_operation
    def PUT(self, req):
        """
        Handles Upload Part and Upload Part Copy.
        """
        # Pass it through, the s3multi upload helper will handle it.
        return req.get_response(self.app)


class UploadsController(Controller):
    """
    Handles the following APIs:

     - List Multipart Uploads
     - Initiate Multipart Upload

    Those APIs are logged as UPLOADS operations in the S3 server log.
    """
    @bucket_operation(err_resp=InvalidRequest,
                      err_msg="Key is not expected for the GET method "
                              "?uploads subresource")
    def GET(self, req):
        """
        Handles List Multipart Uploads
        """
        # Pass it through, the s3multi upload helper will handle it.
        return req.get_response(self.app)

    @object_operation
    def POST(self, req):
        """
        Handles Initiate Multipart Upload.
        """
        # Pass it through, the s3multi upload helper will handle it.
        return req.get_response(self.app)


class UploadController(Controller):
    """
    Handles the following APIs:

     - List Parts
     - Abort Multipart Upload
     - Complete Multipart Upload

    Those APIs are logged as UPLOAD operations in the S3 server log.
    """
    @object_operation
    def GET(self, req):
        """
        Handles List Parts.
        """
        # Pass it through, the s3multi upload helper will handle it.
        return req.get_response(self.app)

    @object_operation
    def DELETE(self, req):
        """
        Handles Abort Multipart Upload.
        """
        # Pass it through, the s3multi upload helper will handle it.
        return req.get_response(self.app)

    @object_operation
    def POST(self, req):
        """
        Handles Complete Multipart Upload.
        """
        # Pass it through, the s3multi upload helper will handle it.
        return req.get_response(self.app)
