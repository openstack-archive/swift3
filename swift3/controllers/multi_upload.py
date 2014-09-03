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
Implementation of S3 Multipart Upload.

This module implements S3 Multipart Upload APIs with the Swift SLO feature.
The following explains how swift3 uses swift container and objects to store S3
upload information:

 - [bucket]+segments

   A container to store upload information.  [bucket] is the original bucket
   where multipart upload is initiated.

 - [bucket]+segments/[upload_id]

   A object of the ongoing upload id.  The object is empty and used for
   checking the target upload status.  If the object exists, it means that the
   upload is initiated but not either completed or aborted.


 - [bucket]+segments/[upload_id]/1
   [bucket]+segments/[upload_id]/2
   [bucket]+segments/[upload_id]/3
     .
     .

   Uploaded part objects.  Those objects are directly used as segments of Swift
   Static Large Object.
"""

from simplejson import loads, dumps
import os

from swift.common.utils import split_path

from swift3.controllers.base import Controller, bucket_operation, \
    object_operation
from swift3.response import InvalidArgument, ErrorResponse, MalformedXML, \
    InvalidPart, BucketAlreadyExists, EntityTooSmall, InvalidPartOrder, \
    InvalidRequest, HTTPOk, HTTPNoContent, NoSuchKey, NoSuchUpload
from swift3.exception import BadSwiftRequest
from swift3.utils import LOGGER, unique_id
from swift3.etree import Element, SubElement, fromstring, tostring, \
    XMLSyntaxError, DocumentInvalid

DEFAULT_MAX_PARTS = 1000
DEFAULT_MAX_UPLOADS = 1000

MAX_COMPLETE_UPLOAD_BODY_SIZE = 2048 * 1024


def _check_upload_info(req, app, upload_id):
    container = req.container_name + '+segments'
    obj = '%s/%s' % (req.object_name, upload_id)

    try:
        req.get_response(app, 'HEAD', container=container, obj=obj)
    except NoSuchKey:
        raise NoSuchUpload(upload_id=upload_id)


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
        if 'uploadId' not in req.params:
            raise InvalidArgument('ResourceType', 'partNumber',
                                  'Unexpected query string parameter')

        upload_id = req.params['uploadId']

        try:
            # TODO: check the range of partNumber
            part_number = int(req.params['partNumber'])
        except Exception:
            err_msg = 'Part number must be an integer'
            raise InvalidArgument('partNumber', req.params['partNumber'],
                                  err_msg)

        _check_upload_info(req, self.app, upload_id)

        req.container_name += '+segments'
        req.object_name = '%s/%s/%d' % (req.object_name, upload_id,
                                        part_number)

        resp = req.get_response(self.app)

        # TODO: set xml body for copy requests.

        resp.status = 200
        return resp


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
        encoding_type = req.params.get('encoding-type')
        if encoding_type is not None and encoding_type != 'url':
            err_msg = 'Invalid Encoding Method specified in Request'
            raise InvalidArgument('encoding-type', encoding_type, err_msg)

        # TODO: add support for prefix, key-marker, upload-id-marker, and
        # max-uploads queries.
        query = {
            'format': 'json',
        }
        container = req.container_name + '+segments'
        resp = req.get_response(self.app, container=container, query=query)
        objects = loads(resp.body)

        uploads = []
        for o in objects:
            obj, upid = split_path('/' + o['name'], 1, 2, True)
            if '/' in upid:
                # This is a part object.
                continue

            uploads.append(
                {'key': obj,
                 'upload_id': upid,
                 'last_modified': o['last_modified']}
            )

        nextkeymarker = ''
        nextuploadmarker = ''
        if len(uploads) > 1:
            nextuploadmarker = uploads[-1]['upload_id']
            nextkeymarker = uploads[-1]['key']

        result_elem = Element('ListMultipartUploadsResult')
        SubElement(result_elem, 'Bucket').text = req.container_name
        SubElement(result_elem, 'KeyMarker').text = ''
        SubElement(result_elem, 'UploadIdMarker').text = ''
        SubElement(result_elem, 'NextKeyMarker').text = nextkeymarker
        SubElement(result_elem, 'NextUploadIdMarker').text = nextuploadmarker

        SubElement(result_elem, 'MaxUploads').text = str(DEFAULT_MAX_UPLOADS)

        if encoding_type is not None:
            SubElement(result_elem, 'EncodingType').text = encoding_type

        SubElement(result_elem, 'IsTruncated').text = 'false'

        # TODO: don't show uploads which are initiated before this bucket is
        # created.
        for u in uploads:
            upload_elem = SubElement(result_elem, 'Upload')
            SubElement(upload_elem, 'Key').text = u['key']
            SubElement(upload_elem, 'UploadId').text = u['upload_id']
            initiator_elem = SubElement(upload_elem, 'Initiator')
            SubElement(initiator_elem, 'ID').text = req.user_id
            SubElement(initiator_elem, 'DisplayName').text = req.user_id
            owner_elem = SubElement(upload_elem, 'Owner')
            SubElement(owner_elem, 'ID').text = req.user_id
            SubElement(owner_elem, 'DisplayName').text = req.user_id
            SubElement(upload_elem, 'StorageClass').text = 'STANDARD'
            SubElement(upload_elem, 'Initiated').text = \
                u['last_modified'][:-3] + 'Z'

        body = tostring(result_elem, encoding_type=encoding_type)

        return HTTPOk(body=body, content_type='application/xml')

    @object_operation
    def POST(self, req):
        """
        Handles Initiate Multipart Upload.
        """
        # Create a unique S3 upload id from UUID to avoid duplicates.
        upload_id = unique_id()

        container = req.container_name + '+segments'
        try:
            req.get_response(self.app, 'PUT', container, '')
        except BucketAlreadyExists:
            pass

        obj = '%s/%s' % (req.object_name, upload_id)

        req.get_response(self.app, 'PUT', container, obj, body='')

        result_elem = Element('InitiateMultipartUploadResult')
        SubElement(result_elem, 'Bucket').text = req.container_name
        SubElement(result_elem, 'Key').text = req.object_name
        SubElement(result_elem, 'UploadId').text = upload_id

        body = tostring(result_elem)

        return HTTPOk(body=body, content_type='application/xml')


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
        encoding_type = req.params.get('encoding-type')
        if encoding_type is not None and encoding_type != 'url':
            err_msg = 'Invalid Encoding Method specified in Request'
            raise InvalidArgument('encoding-type', encoding_type, err_msg)

        upload_id = req.params['uploadId']
        _check_upload_info(req, self.app, upload_id)

        part_num_marker = 0

        # TODO: add support for max-parts and part-number-marker queries.
        query = {
            'format': 'json',
            'prefix': '%s/%s/' % (req.object_name, upload_id),
            'delimiter': '/'
        }

        container = req.container_name + '+segments'
        resp = req.get_response(self.app, container=container, obj='',
                                query=query)
        objects = loads(resp.body)

        last_part = 0

        # pylint: disable-msg=E1103
        objects.sort(key=lambda o: int(o['name'].split('/')[-1]))

        if len(objects) > 0:
            o = objects[-1]
            last_part = os.path.basename(o['name'])

        result_elem = Element('ListPartsResult')
        SubElement(result_elem, 'Bucket').text = req.container_name
        SubElement(result_elem, 'Key').text = req.object_name
        SubElement(result_elem, 'UploadId').text = upload_id

        initiator_elem = SubElement(result_elem, 'Initiator')
        SubElement(initiator_elem, 'ID').text = req.user_id
        SubElement(initiator_elem, 'DisplayName').text = req.user_id
        owner_elem = SubElement(result_elem, 'Owner')
        SubElement(owner_elem, 'ID').text = req.user_id
        SubElement(owner_elem, 'DisplayName').text = req.user_id

        SubElement(result_elem, 'StorageClass').text = 'STANDARD'
        SubElement(result_elem, 'PartNumberMarker').text = str(part_num_marker)
        SubElement(result_elem, 'NextPartNumberMarker').text = str(last_part)
        SubElement(result_elem, 'MaxParts').text = str(DEFAULT_MAX_PARTS)
        # TODO: add support for EncodingType
        SubElement(result_elem, 'IsTruncated').text = 'false'

        for i in objects:
            part_elem = SubElement(result_elem, 'Part')
            SubElement(part_elem, 'PartNumber').text = i['name'].split('/')[-1]
            SubElement(part_elem, 'LastModified').text = \
                i['last_modified'][:-3] + 'Z'
            SubElement(part_elem, 'ETag').text = i['hash']
            SubElement(part_elem, 'Size').text = str(i['bytes'])

        body = tostring(result_elem, encoding_type=encoding_type)

        return HTTPOk(body=body, content_type='application/xml')

    @object_operation
    def DELETE(self, req):
        """
        Handles Abort Multipart Upload.
        """
        upload_id = req.params['uploadId']
        _check_upload_info(req, self.app, upload_id)

        # First check to see if this multi-part upload was already
        # completed.  Look in the primary container, if the object exists,
        # then it was completed and we return an error here.
        container = req.container_name + '+segments'
        obj = '%s/%s' % (req.object_name, upload_id)
        req.get_response(self.app, container=container, obj=obj)

        # The completed object was not found so this
        # must be a multipart upload abort.
        # We must delete any uploaded segments for this UploadID and then
        # delete the object in the main container as well
        query = {
            'format': 'json',
            'prefix': '%s/%s/' % (req.object_name, upload_id),
            'delimiter': '/',
        }

        resp = req.get_response(self.app, 'GET', container, '', query=query)

        #  Iterate over the segment objects and delete them individually
        objects = loads(resp.body)
        for o in objects:
            container = req.container_name + '+segments'
            req.get_response(self.app, container=container, obj=o['name'])

        return HTTPNoContent()

    @object_operation
    def POST(self, req):
        """
        Handles Complete Multipart Upload.
        """
        upload_id = req.params['uploadId']
        _check_upload_info(req, self.app, upload_id)

        # Query for the objects in the segments area to make sure it completed
        query = {
            'format': 'json',
            'prefix': '%s/%s/' % (req.object_name, upload_id),
            'delimiter': '/'
        }

        container = req.container_name + '+segments'
        resp = req.get_response(self.app, 'GET', container, '', query=query)
        objinfo = loads(resp.body)
        objtable = dict((o['name'],
                         {'path': '/'.join(['', container, o['name']]),
                          'etag': o['hash'],
                          'size_bytes': o['bytes']}) for o in objinfo)

        manifest = []
        previous_number = 0
        try:
            xml = req.xml(MAX_COMPLETE_UPLOAD_BODY_SIZE)
            complete_elem = fromstring(xml, 'CompleteMultipartUpload')
            for part_elem in complete_elem.iterchildren('Part'):
                part_number = int(part_elem.find('./PartNumber').text)

                if part_number <= previous_number:
                    raise InvalidPartOrder(upload_id=upload_id)
                previous_number = part_number

                etag = part_elem.find('./ETag').text
                if len(etag) >= 2 and etag[0] == '"' and etag[-1] == '"':
                    # strip double quotes
                    etag = etag[1:-1]

                info = objtable.get("%s/%s/%s" % (req.object_name, upload_id,
                                                  part_number))
                if info is None or info['etag'] != etag:
                    raise InvalidPart(upload_id=upload_id,
                                      part_number=part_number)

                manifest.append(info)
        except (XMLSyntaxError, DocumentInvalid):
            raise MalformedXML()
        except ErrorResponse:
            raise
        except Exception as e:
            LOGGER.error(e)
            raise

        try:
            # TODO: add support for versioning
            resp = req.get_response(self.app, 'PUT', body=dumps(manifest),
                                    query={'multipart-manifest': 'put'})
        except BadSwiftRequest as e:
            msg = str(e)
            if msg.startswith('Each segment, except the last, '
                              'must be at least '):
                # FIXME: AWS S3 allows a smaller object than 5 MB if there is
                # only one part.  Use a COPY request to copy the part object
                # from the segments container instead.
                raise EntityTooSmall(msg)
            else:
                raise

        obj = '%s/%s' % (req.object_name, upload_id)
        req.get_response(self.app, 'DELETE', container, obj)

        result_elem = Element('CompleteMultipartUploadResult')
        SubElement(result_elem, 'Location').text = req.host_url + req.path
        SubElement(result_elem, 'Bucket').text = req.container_name
        SubElement(result_elem, 'Key').text = req.object_name
        SubElement(result_elem, 'ETag').text = resp.etag

        resp.body = tostring(result_elem)
        resp.status = 200
        resp.content_type = "application/xml"

        return resp
