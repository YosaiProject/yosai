import pytest
from yosai.core import (
    SimpleIdentifierCollection,
)
import collections


def test_sic_primary_identifiers_property(simple_identifiers_collection):
    """
    unit tested:  primary_identifiers

    test case:
    the primary identifiers is initially lazy loaded
    """
    sic = simple_identifiers_collection
    assert sic.primary_identifiers == 'username'


def test_sic_primary_identifiers_property_exists(simple_identifiers_collection):
    """
    unit tested:  primary_identifiers

    test case:
    the primary identifiers is initially lazy loaded only if the
    _primary_identifiers attribute isn't already set
    """
    sic = simple_identifiers_collection
    sic._primary_identifiers = 'primary1'
    assert sic.primary_identifiers == 'primary1'


def test_sic_primary_identifiers_property_raises(
        simple_identifiers_collection, capsys, monkeypatch):
    """
    unit tested:  primary_identifiers

    test case:
    the primary identifiers is initially lazy loaded
    """
    sic = simple_identifiers_collection
    monkeypatch.delattr(sic, 'realm_identifiers')
    result = sic.primary_identifiers
    out, err = capsys.readouterr()
    assert (result is None and
            "failed to arbitrarily obtain" in out)


@pytest.mark.parametrize('realm_name, identifiers, collection',
                         [('realm1', 'identifiers1', None),
                          ('realm1', {'identifiers1', 'identifiers2'}, None),
                          (None, None,
                           SimpleIdentifierCollection('realm2', 'identifiers1'))
                          ])
def test_sic_add(realm_name, identifiers, collection):
    """
    unit tested:  add

    test case:
    the add method accepts two forms of input:
    1) a realm_name/identifiers pair
        - either a scalar identifiers value or collection of identifiers (set)
    2) an identifiers collection object
    """
    sic = SimpleIdentifierCollection(realm_name, identifiers, collection)
    if collection:
        assert sic.realm_identifiers == collection.realm_identifiers
    elif isinstance(identifiers, set):
        assert sic.realm_identifiers[realm_name] == identifiers
    else:
        assert sic.realm_identifiers[realm_name] == {identifiers}


def test_sic_by_type():
    """
    unit tested:  by_type

    test case:
    returns all identifiers of a requested type
    """
    DumbClass = type('DumbClass', (object,), {})
    dc1 = DumbClass()
    dc2 = DumbClass()
    identifiers = {dc1, dc2, 'identifiers3', 'id4'}
    sic = SimpleIdentifierCollection(realm_name='realm1',
                                     identifiers=identifiers)
    result = set(sic.by_type(DumbClass))  # convert to set to always match
    assert {dc1, dc2} == result


def test_sic_from_realm(simple_identifiers_collection):
    """
    unit tested:  from_realm

    test case:
    returns identifiers for realm of interest
    """
    sic = simple_identifiers_collection
    result = sic.from_realm('realm1')
    assert result == {'username'}


def test_sic_realm_names(simple_identifiers_collection):
    """
    unit tested:  realm_names

    test case:
    returns a tuple of realm names
    """
    sic = simple_identifiers_collection
    result = sic.realm_names
    assert result == tuple(['realm1'])


def test_sic_is_empty(simple_identifiers_collection):
    """
    unit tested:  is_empty property

    test case:
    returns a Boolean indicating whether the collection is empty
    """
    sic = simple_identifiers_collection
    assert not sic.is_empty
    sic.realm_identifiers = collections.defaultdict(set)  # clear()
    assert sic.is_empty


def test_sic_clear(simple_identifiers_collection):
    """
    unit tested:  clear property

    test case:
    returns a Boolean indicating whether the collection is empty
    """
    sic = simple_identifiers_collection
    sic.clear()
    assert sic.is_empty

sictest = SimpleIdentifierCollection('realm1', 'identifiers1')


@pytest.mark.parametrize('myself,other,boolcheck',
                         [(SimpleIdentifierCollection('realm1', 'identifiers1'),
                           SimpleIdentifierCollection('realm1', 'identifiers1'),
                           True),
                          (SimpleIdentifierCollection('realm1', 'identifiers1'),
                           SimpleIdentifierCollection('realm2', 'identifiers1'),
                           False), (sictest, sictest, True)])
def test_sic_eq(simple_identifiers_collection, myself, other, boolcheck):
    """
    unit tested:  __eq__
    """
    result = (myself == other)
    assert result == boolcheck


def test_sic_serialize(sic_serialized, simple_identifiers_collection):
    """
    unit tested:  serialize

    test case:
    serializing a SIC results in a dict consisting of the serialized attributes
    """
    sic = simple_identifiers_collection
    serialized = sic.serialize()
    assert sic_serialized == serialized


def test_sic_deserialize(sic_serialized, simple_identifiers_collection):
    """
    unit tested:  deserialize

    test case:
    deserializing a serialized SIC results in a new SIC instance
    """

    sic = simple_identifiers_collection
    deserialized = SimpleIdentifierCollection.deserialize(sic_serialized)
    assert deserialized.realm_identifiers == sic.realm_identifiers
