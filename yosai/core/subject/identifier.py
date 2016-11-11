"""
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
"""
import collections
import logging

from yosai.core import (
    serialize_abcs,
    subject_abcs,
)

logger = logging.getLogger(__name__)


class SimpleIdentifierCollection(subject_abcs.MutableIdentifierCollection,
                                 serialize_abcs.Serializable):
    """
    A collection of all identifying attributes associated with a corresponding
    Subject. An *identifier*, known in Shiro as a *principal*, is just a
    security term for an identifying attribute, such as a username or user id
    or social security number or anything else that can be considered an
    'identifying' attribute for a Subject.

    The source name that an identifier originates from as a Subject is first
    authenticated serves as key.

    To obtain the identifier for a specific Source, see the from_source method.
    You can also see which sources contributed to this SIC via the
    source_names attribute (property).

    Yosai simplifies the identifier for a realm, changing it from a set
    to a scalar value.
    """

    # yosai.core.re-ordered the argument list:
    def __init__(self, source_name=None, identifier=None,
                 identifier_collection=None):
        """
        :type source_name: String
        :type identifier: String or ?
        :type identifier_collection:  subject_abcs.IdentifierCollection
        """
        self.source_identifiers = collections.OrderedDict()
        self._primary_identifier = None

        if identifier_collection:
            self.add_collection(identifier_collection=identifier_collection)
        elif (source_name and identifier):
            self.add(source_name=source_name,
                     identifier=identifier)

    @property
    def primary_identifier(self):
        if (not self._primary_identifier):
            try:
                # obtains the first identifier added via authentication:
                identifiers = self.source_identifiers.values()
                primary_identifier = next(iter(identifiers))
            except (AttributeError, TypeError, StopIteration):
                msg = "Failed to obtain primary identifier"
                logger.warning(msg)
                return None
            self._primary_identifier = primary_identifier
            return primary_identifier
        return self._primary_identifier

    def add(self, source_name, identifier):
        """
        :type source_name: String
        :type identifiers: String
        """
        self.source_identifiers[source_name] = identifier

    def add_collection(self, identifier_collection):
        """
        :type identifier_collection: a SimpleIdentifierCollection
        """
        try:
            new_source_identifiers = identifier_collection.source_identifiers
            self.source_identifiers.update(new_source_identifiers)
        except AttributeError:
            msg = "Invalid identifier collection passed as argument"
            raise AttributeError(msg)

    # yosai.core.consolidates one_by_type with by_type:
    def by_type(self, identifier_class):
        """
        returns all unique instances of a type of identifier

        :param identifier_class: the class to match identifier with
        :returns: a tuple
        """
        myidentifiers = set()
        for identifier in self.source_identifiers.values():
            if (isinstance(identifier, identifier_class)):
                myidentifiers.update([identifier])
        return set(myidentifiers)

    def from_source(self, source_name):
        return self.source_identifiers.get(source_name)

    @property
    def source_names(self):
        return tuple(self.source_identifiers.keys())  # make immutable

    @property
    def is_empty(self):
        return (not self.source_identifiers.keys())

    def clear(self):
        self.source_identifiers = collections.OrderedDict()

    def __eq__(self, other):
        if self is other:
            return True
        if isinstance(other, subject_abcs.MutableIdentifierCollection):
            return self.source_identifiers == other.source_identifiers
        return False

    def __repr__(self):
        return "SimpleIdentifierCollection({0}, primary_identifier={1})".format(
                self.source_identifiers, self.primary_identifier)

    def __getstate__(self):
        return {
            'source_identifiers': [[key, value] for key, value in
                                   self.source_identifiers.items()],
            '_primary_identifier': self._primary_identifier
        }

    def __setstate__(self, state):
        self.source_identifiers =\
            collections.OrderedDict(state['source_identifiers'])
        self._primary_identifier = state['_primary_identifier']
