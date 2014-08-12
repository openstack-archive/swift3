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

import lxml.etree
from copy import deepcopy
from itertools import imap
from functools import partial
from pkg_resources import resource_stream

from swift3.exception import S3Exception
from swift3.utils import LOGGER, camel_to_snake, utf8encode, utf8decode

XMLNS_S3 = 'http://s3.amazonaws.com/doc/2006-03-01/'


class XMLSyntaxError(S3Exception):
    pass


class DocumentInvalid(S3Exception):
    pass


def patch(func):
    """
    A decorator to use swift3.etree.Element instead of lxml.etree._Element.  If
    func is callable, this translates its arguments into lxml.etree._Element
    instances, calls the function in lxml.etree._Element, and translates the
    return value into a swift3.etree.Element instance.  If func is not
    callable, this only wraps it with swift3.etree.Element.
    """
    def recursive_map(f, arg):
        """
        Apply f recursively to a nested list.
        """
        if isinstance(arg, (list, tuple)):
            return map(partial(recursive_map, f), arg)
        elif arg.__class__.__name__.lower().endswith('iterator') or \
                arg.__class__.__name__.lower().endswith('generator'):
            # XXX: The above check is not a generic way to find iterables but
            # works well for lxml.etree._Element instances.
            return imap(partial(recursive_map, f), arg)
        else:
            return f(arg)

    if callable(func):
        def _patch(*args, **kwargs):
            args = recursive_map(Element.unwraps, args)
            # XXX: kwargs doesn't contain swift3.etree.Element instances for
            # our use cases.
            return patch(func(*args, **kwargs))

        return _patch
    else:
        return recursive_map(Element.wraps, func)


def cleanup_namespaces(elem):
    def remove_ns(tag, ns):
        if tag.startswith('{%s}' % ns):
            tag = tag[len('{%s}' % ns):]
        return tag

    if not isinstance(elem.tag, basestring):
        # elem is a comment element.
        return

    # remove s3 namespace
    elem.tag = remove_ns(elem.tag, XMLNS_S3)

    # remove default namespace
    if elem.nsmap and None in elem.nsmap:
        elem.tag = remove_ns(elem.tag, elem.nsmap[None])

    for e in elem.iterchildren():
        cleanup_namespaces(e)


@patch
def fromstring(text, root_tag=None):
    try:
        elem = lxml.etree.fromstring(text)
    except lxml.etree.XMLSyntaxError as e:
        LOGGER.debug(e)
        raise XMLSyntaxError(e)

    cleanup_namespaces(elem)

    if root_tag is not None:
        # validate XML
        try:
            path = 'schema/%s.rng' % camel_to_snake(root_tag)
            rng = resource_stream(__name__, path)
            lxml.etree.RelaxNG(file=rng).assertValid(elem)
        except IOError as e:
            # Probably, the schema file doesn't exist.
            LOGGER.error(e)
            raise
        except lxml.etree.DocumentInvalid as e:
            LOGGER.debug(e)
            raise DocumentInvalid(e)

    return elem


@patch
def tostring(tree, use_s3ns=True):
    if use_s3ns:
        nsmap = tree.nsmap.copy()
        nsmap[None] = XMLNS_S3

        root = lxml.etree.Element(tree.tag, attrib=tree.attrib, nsmap=nsmap)
        root.text = tree.text
        root.extend(deepcopy(tree.getchildren()))
        tree = root

    return lxml.etree.tostring(tree, xml_declaration=True, encoding='UTF-8')


class Element(object):
    """
    A wrapper class for lxml.etree._Element.  We cannot override a method in
    lxml.etree._Element directly since it is not a pure python class.  Override
    a method in this class instead.
    """

    def __init__(self, tag, *args, **kwargs):
        if isinstance(tag, lxml.etree._Element):
            self._element = tag
        else:
            self._element = lxml.etree.Element(tag, *args, **kwargs)

    @classmethod
    def wraps(cls, element):
        """
        Wrap the element with swift3.etree.Element if it is instance of
        lxml.etree._Element.
        """
        if isinstance(element, lxml.etree._Element):
            return cls(element)
        else:
            return element

    @classmethod
    def unwraps(cls, element):
        """
        Unwrap the element if is is instance of swift3.etree.Element.
        """
        if isinstance(element, cls):
            return element._element
        else:
            return element

    # Inherit some fundamental attributes.
    __getattr__ = patch(lxml.etree._Element.__getattribute__)
    __item__ = patch(lxml.etree._Element.__iter__)
    __getitem__ = patch(lxml.etree._Element.__getitem__)

    @property
    def text(self):
        """
        Similar to lxml.etree._Element.text but this returns a utf8-encoded
        string always.
        """
        return utf8encode(self._element.text)

    @text.setter
    def text(self, value):
        """
        Sets a unicode string to lxml.etree._Element.text.
        """
        self._element.text = utf8decode(value)

SubElement = patch(lxml.etree.SubElement)
