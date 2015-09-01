import pytest

from yosai import (
    DefaultSubjectContext,
    SimpleIdentifierCollection,
)


@pytest.fixture(scope='function')
def subject_context():
    mydict = {'attr1': 'attribute1'}
    return mydict


@pytest.fixture(scope='function')
def default_subject_context(subject_context):
    return DefaultSubjectContext(subject_context)


@pytest.fixture(scope='function')
def simple_identifier_collection():
    return SimpleIdentifierCollection(realm_name='realm1',
                                      identifier_s='username')
                                  
