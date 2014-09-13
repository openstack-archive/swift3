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
from memoize import mproperty

from swift3.response import InvalidArgument, MalformedACLError, \
    S3NotImplemented, InvalidRequest, AccessDenied, InternalError
from swift3.etree import Element, SubElement, fromstring, tostring, \
    XMLSyntaxError, DocumentInvalid
from swift3.utils import LOGGER

XMLNS_XSI = 'http://www.w3.org/2001/XMLSchema-instance'


class Grantee(object):
    """
    Base class for grantee.
    """
    def __contains__(self, key):
        """
        The key argument is a S3 user id.  This method checks that the user id
        belongs to this class.
        """
        raise S3NotImplemented()

    def encode(self):
        """
        Represent this instance with JSON serializable types.
        """
        raise S3NotImplemented()

    @classmethod
    def decode(cls, value):
        """
        Decode the value to an etree element.
        """
        raise S3NotImplemented()

    @mproperty
    def elem(self):
        """
        Get an etree element of this instance.
        """
        return self.decode(self.encode())

    @classmethod
    def from_header(cls, grantee):
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
            return Group.from_uri(value)
        else:
            raise InvalidArgument(type, value,
                                  'Argument format not recognized')


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

    def encode(self):
        return [self.id, self.display_name]

    @classmethod
    def decode(cls, value):
        elem = Element('Grantee', nsmap={'xsi': XMLNS_XSI})
        elem.set('{%s}type' % XMLNS_XSI, cls.type)
        SubElement(elem, 'ID').text = value[0]
        SubElement(elem, 'DisplayName').text = value[1]
        return elem

    def __str__(self):
        return self.display_name


def canned_acl_grant(bucket_owner, object_owner=None):
    """
    A set of predefined grants supported by AWS S3.
    """
    owner = object_owner or bucket_owner

    return {
        'private': [
            ('FULL_CONTROL', User(owner)),
        ],
        'public-read': [
            ('READ', AllUsers()),
            ('FULL_CONTROL', User(owner)),
        ],
        'public-read-write': [
            ('READ', AllUsers()),
            ('WRITE', AllUsers()),
            ('FULL_CONTROL', User(owner)),
        ],
        'authenticated-read': [
            ('READ', AuthenticatedUsers()),
            ('FULL_CONTROL', User(owner)),
        ],
        'bucket-owner-read': [
            ('READ', User(bucket_owner)),
            ('FULL_CONTROL', User(owner)),
        ],
        'bucket-owner-full-control': [
            ('FULL_CONTROL', User(owner)),
            ('FULL_CONTROL', User(bucket_owner)),
        ],
        'log-delivery-write': [
            ('WRITE', LogDelivery()),
            ('READ_ACP', LogDelivery()),
            ('FULL_CONTROL', User(owner)),
        ],
    }


class Group(Grantee):
    """
    Base class for Amazon S3 Predefined Groups
    """
    type = 'Group'
    uri = ''

    def encode(self):
        return self.__class__.__name__

    @classmethod
    def decode(cls, value):
        elem = Element('Grantee', nsmap={'xsi': XMLNS_XSI})
        elem.set('{%s}type' % XMLNS_XSI, cls.type)
        SubElement(elem, 'URI').text = cls.uri

        return elem

    @classmethod
    def from_uri(cls, uri):
        """
        Convert a URI to one of the predefined groups.
        """
        for group in Group.__subclasses__():  # pylint: disable-msg=E1101
            if group.uri == uri:
                return group()

        raise InvalidArgument('uri', uri, 'Invalid group uri')

    def __str__(self):
        name = re.sub('(.)([A-Z])', r'\1 \2', self.__class__.__name__)
        return name + ' group'


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
    # TODO: Add support for log delivery group.
    pass


class Grant(object):
    def __init__(self, elem):
        self.elem = elem

    def encode(self):
        """
        Represent this instance with JSON serializable types.
        """
        return [self.permission, self.grantee.encode()]

    @classmethod
    def decode(cls, value):
        """
        Decode the value to an etree element.
        """
        permission, grantee = value
        elem = Element('Grant')
        grantee_elem = None

        if isinstance(grantee, list):
            grantee_elem = User.decode(grantee)
        else:
            for group in Group.__subclasses__():  # pylint: disable-msg=E1101
                if group.__name__ == grantee:
                    grantee_elem = group.decode(grantee)
                    break

        if grantee_elem is None:
            raise InternalError(grantee)

        elem.append(grantee_elem)
        SubElement(elem, 'Permission').text = permission

        return elem

    @mproperty
    def permission(self):
        return self.elem.find('./Permission').text

    @mproperty
    def grantee(self):
        e = self.elem.find('./Grantee')
        type = e.get('{%s}type' % XMLNS_XSI)

        if type == Group.type:
            return Group.from_uri(e.find('./URI').text)
        elif type == User.type:
            return User(e.find('./ID').text)
        else:
            raise S3NotImplemented()

    def __iter__(self):
        yield self.permission
        yield self.grantee

    def allow(self, grantee, permission):
        return permission == self.permission and grantee in self.grantee


class ACL(object):
    """
    S3 ACL class.
    """
    metadata_name = 'acl'
    root_tag = 'AccessControlPolicy'
    max_xml_length = 200 * 1024

    def __init__(self, xml):
        try:
            self.elem = fromstring(xml, self.root_tag)
        except (XMLSyntaxError, DocumentInvalid):
            raise MalformedACLError()
        except Exception as e:
            LOGGER.error(e)
            raise

    @mproperty
    def xml(self):
        """
        Returns an XML representation of this instance.
        """
        return tostring(self.elem)

    def encode(self):
        """
        Represent this instance with JSON serializable types.
        """
        return [self.owner] + [g.encode() for g in self.grant]

    @classmethod
    def decode(cls, value):
        """
        Decode the value to an ACL instance.
        """
        elem = Element(cls.root_tag)

        owner = SubElement(elem, 'Owner')
        SubElement(owner, 'ID').text = value[0]
        SubElement(owner, 'DisplayName').text = value[0]

        SubElement(elem, 'AccessControlList').extend(
            Grant.decode(g) for g in value[1:]
        )

        return cls(tostring(elem))

    @mproperty
    def owner(self):
        return self.elem.find('./Owner/ID').text

    @mproperty
    def grant(self):
        return [Grant(e) for e in
                self.elem.findall('./AccessControlList/Grant')]

    def check_owner(self, user_id):
        """
        Check that the user is an owner.
        """
        if user_id != self.owner:
            raise AccessDenied()

    def check_permission(self, user_id, permission):
        """
        Check that the user has a permission.
        """
        try:
            self.check_owner(user_id)

            # owners have full control permission
            return
        except AccessDenied:
            pass

        for g in self.grant:
            if g.allow(user_id, 'FULL_CONTROL') or \
                    g.allow(user_id, permission):
                return

        raise AccessDenied()

    @classmethod
    def from_headers(cls, headers, bucket_owner, object_owner=None):
        """
        Convert HTTP headers to an ACL instance.
        """
        grant = []
        try:
            for key, value in headers.items():
                if key.lower().startswith('x-amz-grant-'):
                    permission = key[len('x-amz-grant-'):]
                    permission = permission.upper().replace('-', '_')
                    for grantee in value.split(','):
                        grant.append((permission,
                                      Grantee.from_header(grantee)))

            if 'x-amz-acl' in headers:
                acl = headers['x-amz-acl']
                if len(grant) > 0:
                    err_msg = 'Specifying both Canned ACLs and Header ' \
                        'Grants is not allowed'
                    raise InvalidRequest(err_msg)

                grant = canned_acl_grant(bucket_owner, object_owner)[acl]
        except (KeyError, ValueError):
            raise InvalidRequest()

        if len(grant) == 0:
            # No ACL headers
            return None

        return cls.from_grant(grant, bucket_owner, object_owner)

    @classmethod
    def from_grant(cls, grant, bucket_owner, object_owner=None):
        """
        Create an ACL instance based on the requested grant.
        """
        owner = object_owner or bucket_owner

        acp_elem = Element('AccessControlPolicy')
        owner_elem = SubElement(acp_elem, 'Owner')
        SubElement(owner_elem, 'ID').text = owner
        SubElement(owner_elem, 'DisplayName').text = owner

        acl_elem = SubElement(acp_elem, 'AccessControlList')
        for permission, grantee in grant:
            grant_elem = SubElement(acl_elem, 'Grant')
            grant_elem.append(grantee.elem)
            SubElement(grant_elem, 'Permission').text = permission

        return ACL(tostring(acp_elem))


class CannedACL(object):
    """
    A dict-like object that returns canned ACL.
    """
    def __getitem__(self, key):
        def acl(key, bucket_owner, object_owner=None):
            grant = canned_acl_grant(bucket_owner, object_owner)[key]

            return ACL.from_grant(grant, bucket_owner, object_owner)

        return partial(acl, key)

canned_acl = CannedACL()

ACLPrivate = canned_acl['private']
ACLPublicRead = canned_acl['public-read']
ACLPublicReadWrite = canned_acl['public-read-write']
ACLAuthenticatedRead = canned_acl['authenticated-read']
ACLBucketOwnerRead = canned_acl['bucket-owner-read']
ACLBucketOwnerFullControl = canned_acl['bucket-owner-full-control']
ACLLogDeliveryWrite = canned_acl['log-delivery-write']
