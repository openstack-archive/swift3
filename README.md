Swift3
------

Swift3 Middleware for OpenStack Swift, allowing access to OpenStack
swift via the Amazon S3 API.


Install
-------

1) Install Swift3 with ``sudo python setup.py install`` or ``sudo python
   setup.py develop`` or via whatever packaging system you may be using.

2) Alter your proxy-server.conf pipeline to have swift3:

    Was::

        [pipeline:main]
        pipeline = catch_errors cache tempauth proxy-server

    Change To::

        [pipeline:main]
        pipeline = catch_errors cache swift3 tempauth proxy-server

3) Add to your proxy-server.conf the section for the Swift3 WSGI filter::

    [filter:swift3]
    use = egg:swift3#swift3

