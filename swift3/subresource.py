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
from functools import partial
from itertools import count
from simplejson import loads, dumps

from swift3.response import InvalidArgument, MalformedACLError, \
    S3NotImplemented, InvalidRequest, AccessDenied
from swift3.etree import Element, SubElement
from swift3.utils import LOGGER, sysmeta_header, MAX_META_VALUE_LENGTH
from swift3.cfg import CONF
from swift3.exception import InvalidSubresource

XMLNS_XSI = 'http://www.w3.org/2001/XMLSchema-instance'

PERMISSIONS = ['FULL_CONTROL', 'READ', 'WRITE', 'READ_ACP', 'WRITE_ACP']

"""
An entry point of this approach is here.
We should understand what we have to design to achieve real S3 ACL.
S3's ACL Model is as follows:

AccessControlPolicy:
    Owner:
    AccessControlList:
        Grant[n]:
            (Grantee, Permission)

Each bucket or object has its own acl consists of Owner and
AcessControlList. AccessControlList can contain some Grants.
By default, AccessControlList has only one Grant to allow FULL
CONTROLL to owner. Each Grant includes single pair with Grantee,
Permission. Grantee is the user (or user group) allowed the given
permission.

If you wanna get more information about S3's ACL model in detail,
please see official documentation here,

http://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html

"""

XMLNS_XSI = 'http://www.w3.org/2001/XMLSchema-instance'

UNDEFINED_OWNER_VALUE = 'undefined'


def encode_acl(resource, acl):
    """
    Encode an ACL instance to Swift metadata.

    Given a resource type and an ACL instance, this method returns HTTP
    headers, which can be used for Swift metadata.
    """
    acl = dumps(acl.encode(), separators=(',', ':'))
    n = MAX_META_VALUE_LENGTH
    segs = [acl[i:i + n] for i in range(0, len(acl), n)]
    segs.append('')  # add a terminater

    headers = {}
    for i, value in enumerate(segs):
        if i == 0:
            key = sysmeta_header(resource, 'acl')
        else:
            key = sysmeta_header(resource, 'acl') + '-' + str(i)
        headers[key] = value

    return headers


def decode_acl(resource, headers):
    """
    Decode Swift metadata to an ACL instance.

    Given a resource type and HTTP headers, this method returns an ACL
    instance.
    """
    value = ''

    for i in count():
        if i == 0:
            key = sysmeta_header(resource, 'acl')
        else:
            key = sysmeta_header(resource, 'acl') + '-' + str(i)
        if key not in headers or not headers[key]:
            break
        value += headers[key]

    if value == '':
        id = UNDEFINED_OWNER_VALUE
        name = UNDEFINED_OWNER_VALUE
        return ACL(Owner(id, name), [])

    try:
        return ACL.from_list(loads(value))
    except Exception as e:
        LOGGER.debug(e)
        pass

    raise InvalidSubresource((resource, 'acl', value))


class Grantee(object):
    """
    Base class for grantee.

    :Definition (methods):
    init -> create a Grantee instance
    elem -> create an ElementTree from itself

    :Definition (static methods):
    from_header -> convert a grantee string in the HTTP header
                   to an Grantee instance.
    from_elem -> convert a ElementTree to an Grantee instance.

    TODO (not yet):
    NOTE: Needs confirmation whether we really need these methods or not.
    encode (method) -> create a JSON which includes whole own elements
    encode_from_elem (static method) -> convert from an ElementTree to a JSON
    elem_from_json (static method) -> convert from a JSON to an ElementTree
    from_json (static method) -> convert a Json string to an Grantee instance.
    """

    def __contains__(self, key):
        """
        The key argument is a S3 user id.  This method checks that the user id
        belongs to this class.
        """
        raise S3NotImplemented()

    def elem(self):
        """
        Get an etree element of this instance.
        """
        raise S3NotImplemented()

    @staticmethod
    def from_elem(elem):
        type = elem.get('{%s}type' % XMLNS_XSI)
        if type == 'CanonicalUser':
            value = elem.find('./ID').text
            return User(value)
        elif type == 'Group':
            value = elem.find('./URI').text
            subclass = get_group_subclass_from_uri(value)
            return subclass
        elif type == 'AmazonCustomerByEmail':
            raise S3NotImplemented()
        else:
            raise MalformedACLError()

    @staticmethod
    def from_header(grantee):
        """
        Convert a grantee string in the HTTP header to an Grantee instance.
        """
        type, value = grantee.split('=', 1)
        value = value.strip('"\'')
        if type == 'id':
            return User(value)
        elif type == 'emailAddress':
            raise S3NotImplemented()
        elif type == 'uri':
            # retrun a subclass instance of Group class
            subclass = get_group_subclass_from_uri(value)
            return subclass
        else:
            raise InvalidArgument(type, value,
                                  'Argument format not recognized')

    @classmethod
    def from_list(cls, grantee):
        for group in Group.__subclasses__():  # pylint: disable-msg=E1101
            if group.__name__ == grantee:
                return group()
        return User(grantee)

    def encode(self):
        """
        Represent this instance with String types.
        """
        raise S3NotImplemented()


class User(Grantee):
    """
    Canonical user class for S3 accounts.
    """
    type = 'CanonicalUser'

    def __init__(self, name):
        self.id = name
        self.display_name = name

    def __contains__(self, key):
        return key == self.id

    def elem(self):
        elem = Element('Grantee', nsmap={'xsi': XMLNS_XSI})
        elem.set('{%s}type' % XMLNS_XSI, self.type)
        SubElement(elem, 'ID').text = self.id
        SubElement(elem, 'DisplayName').text = self.display_name
        return elem

    def __str__(self):
        return self.display_name

    def encode(self):
        return self.id


class Owner(object):
    """
    Owner class for S3 accounts
    """
    def __init__(self, id, name):
        self.id = id
        self.name = name


def get_group_subclass_from_uri(uri):
    """
    Convert a URI to one of the predefined groups.
    """
    for group in Group.__subclasses__():  # pylint: disable-msg=E1101
        if group.uri == uri:
            return group()
    raise InvalidArgument('uri', uri, 'Invalid group uri')


class Group(Grantee):
    """
    Base class for Amazon S3 Predefined Groups
    """
    type = 'Group'
    uri = ''

    def __init__(self):
        # Initialize method to clarify this has nothing to do
        pass

    def elem(self):
        elem = Element('Grantee', nsmap={'xsi': XMLNS_XSI})
        elem.set('{%s}type' % XMLNS_XSI, self.type)
        SubElement(elem, 'URI').text = self.uri

        return elem

    def __str__(self):
        name = re.sub('(.)([A-Z])', r'\1 \2', self.__class__.__name__)
        return name + ' group'

    def encode(self):
        return self.__class__.__name__


def canned_acl_grantees(bucket_owner, object_owner=None):
    """
    A set of predefined grants supported by AWS S3.
    """
    owner = object_owner or bucket_owner

    return {
        'private': [
            ('FULL_CONTROL', User(owner.name)),
        ],
        'public-read': [
            ('READ', AllUsers()),
            ('FULL_CONTROL', User(owner.name)),
        ],
        'public-read-write': [
            ('READ', AllUsers()),
            ('WRITE', AllUsers()),
            ('FULL_CONTROL', User(owner.name)),
        ],
        'authenticated-read': [
            ('READ', AuthenticatedUsers()),
            ('FULL_CONTROL', User(owner.name)),
        ],
        'bucket-owner-read': [
            ('READ', User(bucket_owner.name)),
            ('FULL_CONTROL', User(owner.name)),
        ],
        'bucket-owner-full-control': [
            ('FULL_CONTROL', User(owner.name)),
            ('FULL_CONTROL', User(bucket_owner.name)),
        ],
        'log-delivery-write': [
            ('WRITE', LogDelivery()),
            ('READ_ACP', LogDelivery()),
            ('FULL_CONTROL', User(owner.name)),
        ],
    }


class AuthenticatedUsers(Group):
    """
    This group represents all AWS accounts.  Access permission to this group
    allows any AWS account to access the resource.  However, all requests must
    be signed (authenticated).
    """
    uri = 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'

    def __contains__(self, key):
        # Swift3 handles only signed requests.
        return True


class AllUsers(Group):
    """
    Access permission to this group allows anyone to access the resource.  The
    requests can be signed (authenticated) or unsigned (anonymous).  Unsigned
    requests omit the Authentication header in the request.

    Note: Swift3 regards unsigned requests as Swift API accesses, and bypasses
    them to Swift.  As a result, AllUsers behaves completely same as
    AuthenticatedUsers.
    """
    uri = 'http://acs.amazonaws.com/groups/global/AllUsers'

    def __contains__(self, key):
        return True


class LogDelivery(Group):
    """
    WRITE and READ_ACP permissions on a bucket enables this group to write
    server access logs to the bucket.
    """
    uri = 'http://acs.amazonaws.com/groups/s3/LogDelivery'

    def __contains__(self, key):
        if ':' in key:
            tenant, user = key.split(':', 1)
        else:
            user = key
        return user == CONF.log_delivery_user


class Grant(object):
    """
    Grant Class which includes both Grantee and Permission
    """

    def __init__(self, grantee, permission):
        """
        :param grantee: a grantee class or its subclass
        :param permission: string
        """
        if permission.upper() not in PERMISSIONS:
            raise S3NotImplemented()
        if not isinstance(grantee, Grantee):
            raise
        self.grantee = grantee
        self.permission = permission

    @classmethod
    def from_elem(cls, elem):
        """
        Convert an ElementTree to an ACL instance
        """
        grantee = Grantee.from_elem(elem.find('./Grantee'))
        permission = elem.find('./Permission').text
        return cls(grantee, permission)

    def elem(self):
        """
        Create an etree element.
        """
        elem = Element('Grant')
        elem.append(self.grantee.elem())
        SubElement(elem, 'Permission').text = self.permission

        return elem

    def allow(self, grantee, permission):
        return permission == self.permission and grantee in self.grantee

    @classmethod
    def from_list(cls, grantee, permission):
        grantee = Grantee.from_list(grantee)
        return cls(grantee, permission)

    def encode(self):
        """
        Represent this instance with List types.
        """
        return [self.grantee.encode(), self.permission]


class ACL(object):
    """
    S3 ACL class.

    Refs (S3 API - acl-overview:
          http://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html):

    The sample ACL includes an Owner element identifying the owner via the
    AWS account's canonical user ID. The Grant element identifies the grantee
    (either an AWS account or a predefined group), and the permission granted.
    This default ACL has one Grant element for the owner. You grant permissions
    by adding Grant elements, each grant identifying the grantee and the
    permission.
    """
    metadata_name = 'acl'
    root_tag = 'AccessControlPolicy'
    max_xml_length = 200 * 1024

    def __init__(self, owner, grants=[]):
        """
        :param owner: Owner Class for ACL instance
        """
        self.owner = owner
        self.grants = grants

    @classmethod
    def from_elem(cls, elem):
        """
        Convert an ElementTree to an ACL instance
        """
        id = elem.find('./Owner/ID').text
        name = elem.find('./Owner/DisplayName').text
        grants = [Grant.from_elem(e)
                  for e in elem.findall('./AccessControlList/Grant')]
        return cls(Owner(id, name), grants)

    def elem(self):
        """
        Decode the value to an ACL instance.
        """
        elem = Element(self.root_tag)

        owner = SubElement(elem, 'Owner')
        SubElement(owner, 'ID').text = self.owner.id
        SubElement(owner, 'DisplayName').text = self.owner.name

        SubElement(elem, 'AccessControlList').extend(
            g.elem() for g in self.grants
        )

        return elem

    def check_owner(self, user_id):
        """
        Check that the user is an owner.
        """
        if user_id != self.owner.id:
            raise AccessDenied()

    def check_permission(self, user_id, permission):
        """
        Check that the user has a permission.
        """
        try:
            # owners have full control permission
            self.check_owner(user_id)
            return
        except AccessDenied:
            pass

        for g in self.grants:
            if g.allow(user_id, 'FULL_CONTROL') or \
                    g.allow(user_id, permission):
                return

        raise AccessDenied()

    @classmethod
    def from_headers(cls, headers, bucket_owner, object_owner=None):
        """
        Convert HTTP headers to an ACL instance.
        """
        grants = []
        try:
            for key, value in headers.items():
                if key.lower().startswith('x-amz-grant-'):
                    permission = key[len('x-amz-grant-'):]
                    permission = permission.upper().replace('-', '_')
                    if permission not in PERMISSIONS:
                        continue
                    for grantee in value.split(','):
                        grants.append(
                            Grant(Grantee.from_header(grantee), permission))

            if 'x-amz-acl' in headers:
                acl = headers['x-amz-acl']
                if len(grants) > 0:
                    err_msg = 'Specifying both Canned ACLs and Header ' \
                        'Grants is not allowed'
                    raise InvalidRequest(err_msg)
                grantees = canned_acl_grantees(bucket_owner, object_owner)[acl]
                for permission, grantee in grantees:
                    grants.append(Grant(grantee, permission))
        except (KeyError, ValueError):
            raise InvalidRequest()

        if len(grants) == 0:
            # No ACL headers
            return None

        return cls(object_owner or bucket_owner, grants)

    @classmethod
    def from_list(cls, list):
        id = list[0]
        name = list[0]
        grants = []
        for grant in list[1:]:
            grantee = grant[0]
            permission = grant[1]
            grants.append(Grant.from_list(grantee, permission))
        return cls(Owner(id, name), grants)

    def encode(self):
        """
        Represent this instance with List types.
        """
        return [self.owner.id] + [g.encode() for g in self.grants]


class CannedACL(object):
    """
    A dict-like object that returns canned ACL.
    """
    def __getitem__(self, key):
        def acl(key, bucket_owner, object_owner=None):
            grants = []
            grantees = canned_acl_grantees(bucket_owner, object_owner)[key]
            for permission, grantee in grantees:
                grants.append(Grant(grantee, permission))
            return ACL(object_owner or bucket_owner, grants)

        return partial(acl, key)


canned_acl = CannedACL()

ACLPrivate = canned_acl['private']
ACLPublicRead = canned_acl['public-read']
ACLPublicReadWrite = canned_acl['public-read-write']
ACLAuthenticatedRead = canned_acl['authenticated-read']
ACLBucketOwnerRead = canned_acl['bucket-owner-read']
ACLBucketOwnerFullControl = canned_acl['bucket-owner-full-control']
ACLLogDeliveryWrite = canned_acl['log-delivery-write']
