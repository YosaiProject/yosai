import pytest
from yosai import (
    SimpleIdentifierCollection,
)
import collections


def test_sic_primary_identifier_property(simple_identifier_collection):
    """
    unit tested:  primary_identifier

    test case:
    the primary identifier is initially lazy loaded
    """
    sic = simple_identifier_collection
    assert sic.primary_identifier == 'username'


def test_sic_primary_identifier_property_exists(simple_identifier_collection):
    """
    unit tested:  primary_identifier

    test case:
    the primary identifier is initially lazy loaded only if the
    _primary_identifier attribute isn't already set
    """
    sic = simple_identifier_collection
    sic._primary_identifier = 'primary1'
    assert sic.primary_identifier == 'primary1'


def test_sic_primary_identifier_property_raises(
        simple_identifier_collection, capsys, monkeypatch):
    """
    unit tested:  primary_identifier

    test case:
    the primary identifier is initially lazy loaded
    """
    sic = simple_identifier_collection
    monkeypatch.delattr(sic, 'realm_identifier_s')
    result = sic.primary_identifier
    out, err = capsys.readouterr()
    assert (result is None and
            "failed to arbitrarily obtain" in out)


@pytest.mark.parametrize('realm_name, identifier_s, collection',
                         [('realm1', 'identifier1', None),
                          ('realm1', {'identifier1', 'identifier2'}, None),
                          (None, None,
                           SimpleIdentifierCollection('realm2', 'identifier1'))
                          ])
def test_sic_add(realm_name, identifier_s, collection):
    """
    unit tested:  add

    test case:
    the add method accepts two forms of input:
    1) a realm_name/identifier pair
        - either a scalar identifier value or collection of identifier_s (set)
    2) an identifier collection object
    """
    sic = SimpleIdentifierCollection(realm_name, identifier_s, collection)
    if collection:
        assert sic.realm_identifier_s == collection.realm_identifier_s
    elif isinstance(identifier_s, set):
        assert sic.realm_identifier_s[realm_name] == identifier_s
    else:
        assert sic.realm_identifier_s[realm_name] == {identifier_s}


def test_sic_by_type():
    """
    unit tested:  by_type

    test case:
    returns all identifier_s of a requested type
    """
    DumbClass = type('DumbClass', (object,), {})
    dc1 = DumbClass()
    dc2 = DumbClass()
    identifier_s = {dc1, dc2, 'identifier3', 'id4'}
    sic = SimpleIdentifierCollection(realm_name='realm1',
                                     identifier_s=identifier_s)
    result = set(sic.by_type(DumbClass))  # convert to set to always match
    assert {dc1, dc2} == result


def test_sic_from_realm(simple_identifier_collection):
    """
    unit tested:  from_realm

    test case:
    returns identifier_s for realm of interest
    """
    sic = simple_identifier_collection
    result = sic.from_realm('realm1')
    assert result == {'username'}


def test_sic_realm_names(simple_identifier_collection):
    """
    unit tested:  realm_names

    test case:
    returns a tuple of realm names
    """
    sic = simple_identifier_collection
    result = sic.realm_names
    assert result == tuple(['realm1'])


def test_sic_is_empty(simple_identifier_collection):
    """
    unit tested:  is_empty property

    test case:
    returns a Boolean indicating whether the collection is empty
    """
    sic = simple_identifier_collection
    assert not sic.is_empty
    sic.realm_identifier_s = collections.defaultdict(set)  # clear()
    assert sic.is_empty


def test_sic_clear(simple_identifier_collection):
    """
    unit tested:  clear property

    test case:
    returns a Boolean indicating whether the collection is empty
    """
    sic = simple_identifier_collection
    sic.clear()
    assert sic.is_empty

sictest = SimpleIdentifierCollection('realm1', 'identifier1')


@pytest.mark.parametrize('myself,other,boolcheck',
                         [(SimpleIdentifierCollection('realm1', 'identifier1'),
                           SimpleIdentifierCollection('realm1', 'identifier1'),
                           True),
                          (SimpleIdentifierCollection('realm1', 'identifier1'),
                           SimpleIdentifierCollection('realm2', 'identifier1'),
                           False), (sictest, sictest, True)])
def test_sic_eq(simple_identifier_collection, myself, other, boolcheck):
    """
    unit tested:  __eq__
    """
    result = (myself == other)
    assert result == boolcheck


def test_sic_serialize(sic_serialized, simple_identifier_collection):
    """
    unit tested:  serialize

    test case:
    serializing a SIC results in a dict consisting of the serialized attributes
    """
    sic = simple_identifier_collection
    serialized = sic.serialize()
    assert sic_serialized == serialized


def test_sic_deserialize(sic_serialized, simple_identifier_collection):
    """
    unit tested:  deserialize

    test case:
    deserializing a serialized SIC results in a new SIC instance
    """

    sic = simple_identifier_collection
    deserialized = SimpleIdentifierCollection.deserialize(sic_serialized)
    assert deserialized.realm_identifier_s == sic.realm_identifier_s
