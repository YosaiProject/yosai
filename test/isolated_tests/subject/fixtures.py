import pytest
from collections import defaultdict

from yosai import (
    DefaultSubjectContext,
    DefaultSubjectSettings,
    DefaultSubjectStore,
    DelegatingSubject,
    SimpleIdentifierCollection,
    security_utils,
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
    return DefaultSubjectContext(security_utils, context)


@pytest.fixture(scope='function')
def simple_identifier_collection():
    return SimpleIdentifierCollection(realm_name='realm1',
                                      identifier_s='username')


@pytest.fixture(scope='function')
def sic_serialized():
    return {'realm_identifiers': {'realm1': ['username']}}


@pytest.fixture(scope='function')
def default_subject_store():
    return DefaultSubjectStore()

# mock_session and mock_security_manager obtained from ../conftest:
@pytest.fixture(scope='function')
def delegating_subject(
        mock_session, simple_identifier_collection, mock_security_manager):
    return DelegatingSubject(identifiers=simple_identifier_collection,
                             authenticated=False,
                             host='127.0.0.1',
                             session=mock_session,
                             session_creation_enabled=True,
                             security_manager=mock_security_manager)
