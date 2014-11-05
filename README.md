Swift3
------

Swift3 Middleware for OpenStack Swift, allowing access to OpenStack
swift via the Amazon S3 API.


Install
-------

1) Install Swift3 with ``sudo python setup.py install`` or ``sudo python
   setup.py develop`` or via whatever packaging system you may be using.

2) Alter your proxy-server.conf pipeline to have swift3:

If you use tempauth:

    Was::

        [pipeline:main]
        pipeline = catch_errors cache tempauth proxy-server

    Change To::

        [pipeline:main]
        pipeline = catch_errors cache swift3 tempauth proxy-server

If you use keystone:

    Was::

        [pipeline:main]
        pipeline = catch_errors cache authtoken keystone proxy-server

    Change To::

        [pipeline:main]
        pipeline = catch_errors cache swift3 s3token authtoken keystoneauth proxy-server

Note that swift3 explicitly checks that keystoneauth is in the pipeline.  You must use this name
in the pipeline statement and in [filter:keystoneauth] section header.

3) Add to your proxy-server.conf the section for the Swift3 WSGI filter::

    [filter:swift3]
    use = egg:swift3#swift3

You also need to add the following if you use keystone (adjust port, host, protocol configurations for your environment):

    [filter:s3token]
    paste.filter_factory = keystoneclient.middleware.s3_token:filter_factory
    auth_port = 35357
    auth_host = 127.0.0.1
    auth_protocol = http
