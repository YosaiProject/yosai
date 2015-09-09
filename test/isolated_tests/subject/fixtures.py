import pytest
from collections import defaultdict

from yosai import (
    DefaultSubjectContext,
    DefaultSubjectSettings,
    SimpleIdentifierCollection,
)

@pytest.fixture(scope='function')
def default_subject_settings():
    return DefaultSubjectSettings()


@pytest.fixture(scope='function')
def subject_context(default_subject_settings):
    dss = default_subject_settings
    return dss.context


@pytest.fixture(scope='function')
def default_subject_context(subject_context):
    context = {value: 'value_'+value for key, value in subject_context.items()}
    return DefaultSubjectContext(context)


@pytest.fixture(scope='function')
def simple_identifier_collection():
    return SimpleIdentifierCollection(realm_name='realm1',
                                      identifier_s='username')


@pytest.fixture(scope='function')
def sic_serialized():
    return {'realm_identifiers': {'realm1': ['username']}}
