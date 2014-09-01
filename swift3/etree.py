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
from pkg_resources import resource_stream

from swift3.exception import S3Exception
from swift3.utils import LOGGER, camel_to_snake

XMLNS_S3 = 'http://s3.amazonaws.com/doc/2006-03-01/'


class XMLSyntaxError(S3Exception):
    pass


class DocumentInvalid(S3Exception):
    pass


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


def fromstring(text, root_tag=None):
    try:
        elem = lxml.etree.fromstring(text, parser)
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


def tostring(tree, use_s3ns=True):
    if use_s3ns:
        nsmap = tree.nsmap.copy()
        nsmap[None] = XMLNS_S3

        root = Element(tree.tag, attrib=tree.attrib, nsmap=nsmap)
        root.text = tree.text
        root.extend(deepcopy(tree.getchildren()))
        tree = root

    return lxml.etree.tostring(tree, xml_declaration=True, encoding='UTF-8')


class _Element(lxml.etree.ElementBase):
    def __init__(self, *args, **kwargs):
        super(_Element, self).__init__(*args, **kwargs)

    @property
    def text(self):
        '''
        utf-8 wrapper property of lxml.etree.Element.text
        '''
        text = lxml.etree.ElementBase.text.__get__(self)
        if isinstance(text, unicode):
            text = text.encode('utf-8')
        return text

    @text.setter
    def text(self, value):
        if isinstance(value, str):
            value = value.decode('utf-8')
        lxml.etree.ElementBase.text.__set__(self, value)


parser_lookup = lxml.etree.ElementDefaultClassLookup(element=_Element)
parser = lxml.etree.XMLParser()
parser.set_element_class_lookup(parser_lookup)

Element = parser.makeelement
SubElement = lxml.etree.SubElement
