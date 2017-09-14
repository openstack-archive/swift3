S3/Swift REST API Comparison Matrix
===================================

General compatibility statement
-------------------------------

S3 is a product from Amazon, and as such, it includes "features" that
are  outside the scope of Swift itself. For example, Swift doesn't
have anything to do with billing, whereas S3 buckets can be tied to
Amazon's billing system. Similarly, log delivery is a service outside
of Swift. It's entirely possible for a Swift deployment to provide that
functionality, but it is not part of Swift itself. Likewise, a Swift
deployment can provide similar geographic availability as S3, but this
is tied to the deployer's willingness to build the infrastructure and
support systems to do so.

`Amazon S3 Object operations`_
------------------------------

+----------------------------------+------------------+--------------+
| S3 REST API method               | Category         | Swift S3 API |
+==================================+==================+==============+
| `GET Object`_                    | Core-API         | Yes          |
+----------------------------------+------------------+--------------+
| `HEAD Object`_                   | Core-API         | Yes          |
+----------------------------------+------------------+--------------+
| `PUT Object`_                    | Core-API         | Yes          |
+----------------------------------+------------------+--------------+
| `OPTIONS Object`_                | Core-API         |              |
+----------------------------------+------------------+--------------+
| `PUT Object Copy`_               | Core-API         | Yes          |
+----------------------------------+------------------+--------------+
| `DELETE Object`_                 | Core-API         | Yes          |
+----------------------------------+------------------+--------------+
| `Initiate Multipart Upload`_     | Core-API         | Yes          |
+----------------------------------+------------------+--------------+
| `Upload Part`_                   | Core-API         | Yes          |
+----------------------------------+------------------+--------------+
| `Upload Part Copy`_              | Core-API         | Yes          |
+----------------------------------+------------------+--------------+
| `Complete Multipart Upload`_     | Core-API         | Yes          |
+----------------------------------+------------------+--------------+
| `Abort Multipart Upload`_        | Core-API         | Yes          |
+----------------------------------+------------------+--------------+
| `List Parts`_                    | Core-API         | Yes          |
+----------------------------------+------------------+--------------+
| `GET Object ACL`_                | ACLs             | Yes          |
+----------------------------------+------------------+--------------+
| `PUT Object ACL`_                | ACLs             | Yes          |
+----------------------------------+------------------+--------------+
| `POST Object via HTTP forms`_    | Public Website   | No           |
+----------------------------------+------------------+--------------+
| `POST Object restore`_           | Advanced Feature | No           |
+----------------------------------+------------------+--------------+
| `Delete Multiple Objects`_       | Advanced Feature | Yes          |
+----------------------------------+------------------+--------------+
| `GET Object torrent`_            | Advanced Feature | No           |
+----------------------------------+------------------+--------------+
| `PUT Object tagging`_            | Advanced Feature | No           |
+----------------------------------+------------------+--------------+
| `GET Object tagging`_            | Advanced Feature | No           |
+----------------------------------+------------------+--------------+
| `DELETE Object tagging`_         | Advanced Feature | No           |
+----------------------------------+------------------+--------------+

`Amazon S3 Bucket operations`_
------------------------------

+----------------------------------+------------------+--------------+
| S3 REST API method               | Category         | Swift S3 API |
+==================================+==================+==============+
| `PUT Bucket`_                    | Core-API         | Yes          |
+----------------------------------+------------------+--------------+
| `GET Bucket (List Objects)`_     | Core-API         | Yes          |
+----------------------------------+------------------+--------------+
| `HEAD Bucket`_                   | Core-API         | Yes          |
+----------------------------------+------------------+--------------+
| `DELETE Bucket`_                 | Core-API         | Yes          |
+----------------------------------+------------------+--------------+
| `List Multipart Uploads`_        | Core-API         | Yes          |
+----------------------------------+------------------+--------------+
| `GET Bucket acl`_                | ACLs             | Yes          |
+----------------------------------+------------------+--------------+
| `PUT Bucket acl`_                | ACLs             | Yes          |
+----------------------------------+------------------+--------------+
| `GET Bucket Object versions`_    | Versioning       | No           |
+----------------------------------+------------------+--------------+
| `GET Bucket versioning`_         | Versioning       | No           |
+----------------------------------+------------------+--------------+
| `PUT Bucket versioning`_         | Versioning       | No           |
+----------------------------------+------------------+--------------+
| `PUT Bucket website`_            | Public Website   | No           |
+----------------------------------+------------------+--------------+
| `GET Bucket website`_            | Public Website   | No           |
+----------------------------------+------------------+--------------+
| `DELETE Bucket website`_         | Public Website   | No           |
+----------------------------------+------------------+--------------+
| `PUT Bucket notification`_       | Notifications    | No           |
+----------------------------------+------------------+--------------+
| `GET Bucket notification`_       | Notifications    | No           |
+----------------------------------+------------------+--------------+
| `PUT Bucket lifecycle`_          | Bucket Lifecycle | No           |
+----------------------------------+------------------+--------------+
| `GET Bucket lifecycle`_          | Bucket Lifecycle | No           |
+----------------------------------+------------------+--------------+
| `DELETE Bucket lifecycle`_       | Bucket Lifecycle | No           |
+----------------------------------+------------------+--------------+
| `PUT Bucket policy`_             | Advanced ACLs    | No           |
+----------------------------------+------------------+--------------+
| `GET Bucket policy`_             | Advanced ACLs    | No           |
+----------------------------------+------------------+--------------+
| `DELETE Bucket policy`_          | Advanced ACLs    | No           |
+----------------------------------+------------------+--------------+
| `GET Bucket CORS`_               | Public Website   | No           |
+----------------------------------+------------------+--------------+
| `PUT Bucket CORS`_               | Public Website   | No           |
+----------------------------------+------------------+--------------+
| `DELETE Bucket CORS`_            | Public Website   | No           |
+----------------------------------+------------------+--------------+
| `GET Bucket location`_           | Advanced Feature | Yes          |
+----------------------------------+------------------+--------------+
| `PUT Bucket logging`_            | Advanced Feature | No           |
+----------------------------------+------------------+--------------+
| `GET Bucket logging`_            | Advanced Feature | No           |
+----------------------------------+------------------+--------------+
| `PUT Bucket requestPayment`_     | Advanced Feature | No           |
+----------------------------------+------------------+--------------+
| `GET Bucket requestPayment`_     | Advanced Feature | No           |
+----------------------------------+------------------+--------------+
| `GET Bucket accelerate`_         | Advanced Feature | No           |
+----------------------------------+------------------+--------------+
| `PUT Bucket accelerate`_         | Advanced Feature | No           |
+----------------------------------+------------------+--------------+
| `GET Bucket analytics`_          | Advanced Feature | No           |
+----------------------------------+------------------+--------------+
| `PUT Bucket analytics`_          | Advanced Feature | No           |
+----------------------------------+------------------+--------------+
| `DELETE Bucket analytics`_       | Advanced Feature | No           |
+----------------------------------+------------------+--------------+
| `GET Bucket inventory`_          | Advanced Feature | No           |
+----------------------------------+------------------+--------------+
| `PUT Bucket inventory`_          | Advanced Feature | No           |
+----------------------------------+------------------+--------------+
| `DELETE Bucket inventory`_       | Advanced Feature | No           |
+----------------------------------+------------------+--------------+
| `GET Bucket metrics`_            | Advanced Feature | No           |
+----------------------------------+------------------+--------------+
| `PUT Bucket metrics`_            | Advanced Feature | No           |
+----------------------------------+------------------+--------------+
| `DELETE Bucket metrics`_         | Advanced Feature | No           |
+----------------------------------+------------------+--------------+
| `GET Bucket replication`_        | Advanced Feature | No           |
+----------------------------------+------------------+--------------+
| `PUT Bucket replication`_        | Advanced Feature | No           |
+----------------------------------+------------------+--------------+
| `DELETE Bucket replication`_     | Advanced Feature | No           |
+----------------------------------+------------------+--------------+
| `GET Bucket tagging`_            | Advanced Feature | No           |
+----------------------------------+------------------+--------------+
| `PUT Bucket tagging`_            | Advanced Feature | No           |
+----------------------------------+------------------+--------------+
| `DELETE Bucket tagging`_         | Advanced Feature | No           |
+----------------------------------+------------------+--------------+

.. _Amazon S3 Object operations: http://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectOps.html
.. _GET Object: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTObjectGET.html
.. _HEAD Object: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTObjectHEAD.html
.. _PUT Object: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTObjectPUT.html
.. _OPTIONS Object: http://docs.aws.amazon.com/AmazonS3/latest/API/RESTOPTIONSobject.html
.. _PUT Object Copy: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTObjectCOPY.html
.. _DELETE Object: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTObjectDELETE.html
.. _Initiate Multipart Upload: http://docs.amazonwebservices.com/AmazonS3/latest/API/mpUploadInitiate.html
.. _Upload Part: http://docs.amazonwebservices.com/AmazonS3/latest/API/mpUploadUploadPart.html
.. _Upload Part Copy: http://docs.amazonwebservices.com/AmazonS3/latest/API/mpUploadUploadPartCopy.html
.. _Complete Multipart Upload: http://docs.amazonwebservices.com/AmazonS3/latest/API/mpUploadComplete.html
.. _Abort Multipart Upload: http://docs.amazonwebservices.com/AmazonS3/latest/API/mpUploadAbort.html
.. _List Parts: http://docs.amazonwebservices.com/AmazonS3/latest/API/mpUploadListParts.html
.. _GET Object ACL: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTObjectGETacl.html
.. _PUT Object ACL: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTObjectPUTacl.html
.. _POST Object via HTTP forms: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTObjectPOST.html
.. _POST Object restore: http://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectPOSTrestore.html
.. _Delete Multiple Objects: http://docs.amazonwebservices.com/AmazonS3/latest/API/multiobjectdeleteapi.html
.. _GET Object torrent: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTObjectGETtorrent.html
.. _PUT Object tagging: http://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectPUTtagging.html
.. _GET Object tagging: http://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectGETtagging.html
.. _DELETE Object tagging: http://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectDELETEtagging.html

.. _Amazon S3 Bucket operations: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketOps.html
.. _PUT Bucket: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketPUT.html
.. _GET Bucket List Objects: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketGET.html
.. _HEAD Bucket: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketHEAD.html
.. _DELETE Bucket: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketDELETE.html
.. _List Multipart Uploads: http://docs.amazonwebservices.com/AmazonS3/latest/API/mpUploadListMPUpload.html
.. _GET Bucket acl: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketGETacl.html
.. _PUT Bucket acl: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketPUTacl.html
.. _GET Bucket Object versions: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketGETVersion.html
.. _GET Bucket versioning: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketGETversioningStatus.html
.. _PUT Bucket versioning: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketPUTVersioningStatus.html
.. _PUT Bucket website: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketPUTwebsite.html
.. _GET Bucket website: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketGETwebsite.html
.. _DELETE Bucket website: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketDELETEwebsite.html
.. _PUT Bucket notification: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketPUTnotification.html
.. _GET Bucket notification: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketGETnotification.html
.. _PUT Bucket lifecycle: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketPUTlifecycle.html
.. _GET Bucket lifecycle: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketGETlifecycle.html
.. _DELETE Bucket lifecycle: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketDELETElifecycle.html
.. _PUT Bucket policy: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketPUTpolicy.html
.. _GET Bucket policy: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketGETpolicy.html
.. _DELETE Bucket policy: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketDELETEpolicy.html
.. _GET Bucket CORS: http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketGETcors.html
.. _PUT Bucket CORS: http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTcors.html
.. _DELETE Bucket CORS: http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketDELETEcors.html
.. _GET Bucket location: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketGETlocation.html
.. _PUT Bucket logging: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketPUTlogging.html
.. _GET Bucket logging: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketGETlogging.html
.. _PUT Bucket requestPayment: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTrequestPaymentPUT.html
.. _GET Bucket requestPayment: http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTrequestPaymentGET.html
.. _GET Bucket accelerate: http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketGETaccelerate.html
.. _PUT Bucket accelerate: http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTaccelerate.html
.. _GET Bucket analytics: http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketGETAnalyticsConfig.html
.. _PUT Bucket analytics: http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTAnalyticsConfig.html
.. _DELETE Bucket analytics: http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketDELETEAnalyticsConfig.html
.. _GET Bucket inventory: http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketGETInventoryConfig.html
.. _PUT Bucket inventory: http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTInventoryConfig.html
.. _DELETE Bucket inventory: http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketDELETEInventoryConfig.html
.. _GET Bucket metrics: http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketGETMetricConfiguration.html
.. _PUT Bucket metrics: http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTMetricConfiguration.html
.. _DELETE Bucket metrics: http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketDELETEMetricConfiguration.html
.. _GET Bucket replication: http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketGETreplication.html
.. _PUT Bucket replication: http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTreplication.html
.. _DELETE Bucket replication: http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketDELETEreplication.html
.. _GET Bucket tagging: http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketGETtagging.html
.. _PUT Bucket tagging: http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTtagging.html
.. _DELETE Bucket tagging: http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketDELETEtagging.html
