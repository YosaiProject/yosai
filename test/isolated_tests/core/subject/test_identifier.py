import pytest
from yosai.core import (
    SimpleIdentifierCollection,
)
import collections


def test_sic_primary_identifier_property(simple_identifiers_collection):
    """
    unit tested:  primary_identifier

    test case:
    the primary identifiers is initially lazy loaded
    """
    sic = simple_identifiers_collection
    assert sic.primary_identifier == 'username'


def test_sic_primary_identifier_property_exists(simple_identifiers_collection):
    """
    unit tested:  primary_identifier

    test case:
    the primary identifiers is initially lazy loaded only if the
    _primary_identifier attribute isn't already set
    """
    sic = simple_identifiers_collection
    sic._primary_identifier = 'primary1'
    assert sic.primary_identifier == 'primary1'


def test_sic_primary_identifier_property_raises(
        simple_identifiers_collection, capsys, monkeypatch):
    """
    unit tested:  primary_identifier

    test case:
    the primary identifiers is initially lazy loaded
    """
    sic = simple_identifiers_collection
    monkeypatch.delattr(sic, 'source_identifiers')
    result = sic.primary_identifier
    out, err = capsys.readouterr()
    assert result is None


@pytest.mark.parametrize('source_name, identifiers, collection',
                         [('realm1', 'identifiers1', None),
                          (None, None,
                           SimpleIdentifierCollection('realm2', 'identifiers1'))
                          ])
def test_sic_add(source_name, identifiers, collection):
    """
    unit tested:  add

    test case:
    the add method accepts two forms of input:
    1) a source_name/identifiers pair
        - either a scalar identifiers value or collection of identifiers (set)
    2) an identifiers collection object
    """
    sic = SimpleIdentifierCollection(source_name, identifiers, collection)
    if collection:
        assert sic.source_identifiers == collection.source_identifiers
    elif isinstance(identifiers, set):
        assert sic.source_identifiers[source_name] == identifiers
    else:
        assert sic.source_identifiers[source_name] == identifiers


def test_sic_by_type():
    """
    unit tested:  by_type

    test case:
    returns all identifiers of a requested type
    """
    sic = SimpleIdentifierCollection(source_name='realm1',
                                     identifier='identifier')
    result = set(sic.by_type(str))  # convert to set to always match
    assert result == set(['identifier'])


def test_sic_from_source(simple_identifiers_collection):
    """
    unit tested:  from_source

    test case:
    returns identifiers for realm of interest
    """
    sic = simple_identifiers_collection
    result = sic.from_source('realm1')
    assert result == 'username'


def test_sic_source_names(simple_identifiers_collection):
    """
    unit tested:  source_names

    test case:
    returns a tuple of realm names
    """
    sic = simple_identifiers_collection
    result = sic.source_names
    assert result == tuple(['realm1'])


def test_sic_is_empty(simple_identifiers_collection):
    """
    unit tested:  is_empty property

    test case:
    returns a Boolean indicating whether the collection is empty
    """
    sic = simple_identifiers_collection
    assert not sic.is_empty
    sic.source_identifiers = collections.defaultdict(set)  # clear()
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
