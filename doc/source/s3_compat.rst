S3/Swift REST API Comparison Matrix
===================================

General compatibility statement
-------------------------------

S3 is a product from Amazon, and as such, it includes "features" that
are  outside the scope of Swift itself. For example, Swift doesn't
have anything to do with billing, whereas S3 buckets can be tied to
Amazon's billing system. Similarly, log delivery is a service outside
of Swift. It's entirely possible for a Swift deployed to provide that
functionality, but it is not part of Swift itself. Likewise, a Swift
deployment can provide similar geographic availability as S3, but this
is tied to the deployer's willingness to build the infrastructure and
support systems to do so.

[Amazon S3 Object operations](http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketOps.html)
-------------------------------------------------------------------------------------------------------

+------------------------------------------------------------------------------------------------------------+------------------+--------------+
| S3 REST API method                                                                                         | Category         | Swift S3 API |
+============================================================================================================+==================+==============+
| [GET Object](http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTObjectGET.html)                     | Core-API         | Yes          |
+------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [HEAD Object](http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTObjectHEAD.html)                   | Core-API         | Yes          |
+------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [PUT Object](http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTObjectPUT.html)                     | Core-API         | Yes          |
+------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [PUT Object - Copy](http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTObjectCOPY.html)             | Core-API         | Yes          |
+------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [DELETE Object](http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTObjectDELETE.html)               | Core-API         | Yes          |
+------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [Initiate Multipart Upload](http://docs.amazonwebservices.com/AmazonS3/latest/API/mpUploadInitiate.html)   | Core-API         | Yes          |
+------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [Upload Part](http://docs.amazonwebservices.com/AmazonS3/latest/API/mpUploadUploadPart.html)               | Core-API         | Yes          |
+------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [Upload Part - Copy](http://docs.amazonwebservices.com/AmazonS3/latest/API/mpUploadUploadPartCopy.html)    | Core-API         | Yes          |
+------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [Complete Multipart Upload](http://docs.amazonwebservices.com/AmazonS3/latest/API/mpUploadComplete.html)   | Core-API         | Yes          |
+------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [Abort Multipart Upload](http://docs.amazonwebservices.com/AmazonS3/latest/API/mpUploadAbort.html)         | Core-API         | Yes          |
+------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [List Parts](http://docs.amazonwebservices.com/AmazonS3/latest/API/mpUploadListParts.html)                 | Core-API         | Yes          |
+------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [GET Object ACL](http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTObjectGETacl.html)              | ACLs             | Yes          |
+------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [PUT Object acl](http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTObjectPUTacl.html)              | ACLs             | Yes          |
+------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [POST Object](http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTObjectPOST.html)                   | Public Website   | No           |
+------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [Delete Multiple Objects](http://docs.amazonwebservices.com/AmazonS3/latest/API/multiobjectdeleteapi.html) | Advanced Feature | Yes          |
+------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [GET Object torrent](http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTObjectGETtorrent.html)      | Advanced Feature | No           |
+------------------------------------------------------------------------------------------------------------+------------------+--------------+

[Amazon S3 Bucket operations](http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketOps.html)
-------------------------------------------------------------------------------------------------------

+-------------------------------------------------------------------------------------------------------------------+------------------+--------------+
| S3 REST API method                                                                                                | Category         | Swift S3 API |
+===================================================================================================================+==================+==============+
| [DELETE Bucket](http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketDELETE.html)                      | Core-API         | Yes          |
+-------------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [GET Bucket (List Objects)](http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketGET.html)             | Core-API         | Yes          |
+-------------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [HEAD Bucket](http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketHEAD.html)                          | Core-API         | Yes          |
+-------------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [List Multipart Uploads](http://docs.amazonwebservices.com/AmazonS3/latest/API/mpUploadListMPUpload.html)         | Core-API         | Yes          |
+-------------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [PUT Bucket](http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketPUT.html)                            | Core-API         | Yes          |
+-------------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [GET Bucket acl](http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketGETacl.html)                     | ACLs             | Yes          |
+-------------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [PUT Bucket acl](http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketPUTacl.html)                     | ACLs             | Yes          |
+-------------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [GET Bucket Object versions](http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketGETVersion.html)     | Versioning       | No           |
+-------------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [GET Bucket versioning](http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketGETversioningStatus.html) | Versioning       | No           |
+-------------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [PUT Bucket versioning](http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketPUTVersioningStatus.html) | Versioning       | No           |
+-------------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [PUT Bucket website](http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketPUTwebsite.html)             | Public Website   | No           |
+-------------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [GET Bucket website](http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketGETwebsite.html)             | Public Website   | No           |
+-------------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [DELETE Bucket website](http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketDELETEwebsite.html)       | Public Website   | No           |
+-------------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [GET Bucket location](http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketGETlocation.html)           | Advanced Feature | Yes          |
+-------------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [PUT Bucket lifecycle](http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketPUTlifecycle.html)         | Advanced Feature | No           |
+-------------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [PUT Bucket policy](http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketPUTpolicy.html)               | Advanced Feature | No           |
+-------------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [PUT Bucket logging](http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketPUTlogging.html)             | Advanced Feature | No           |
+-------------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [PUT Bucket notification](http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketPUTnotification.html)   | Advanced Feature | No           |
+-------------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [PUT Bucket requestPayment](http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTrequestPaymentPUT.html)     | Advanced Feature | No           |
+-------------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [GET Bucket lifecycle](http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketGETlifecycle.html)         | Advanced Feature | No           |
+-------------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [GET Bucket policy](http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketGETpolicy.html)               | Advanced Feature | No           |
+-------------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [GET Bucket logging](http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketGETlogging.html)             | Advanced Feature | No           |
+-------------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [GET Bucket notification](http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketGETnotification.html)   | Advanced Feature | No           |
+-------------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [GET Bucket requestPayment](http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTrequestPaymentGET.html)     | Advanced Feature | No           |
+-------------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [DELETE Bucket lifecycle](http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketDELETElifecycle.html)   | Advanced Feature | No           |
+-------------------------------------------------------------------------------------------------------------------+------------------+--------------+
| [DELETE Bucket policy](http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketDELETEpolicy.html)         | Advanced Feature | No           |
+-------------------------------------------------------------------------------------------------------------------+------------------+--------------+
