import pytest
from collections import defaultdict

from yosai import (
    DefaultSubjectContext,
    DefaultSubjectStore,
    DelegatingSubject,
    SimpleIdentifierCollection,
    security_utils,
)


@pytest.fixture(scope='function')
def subject_context():
    return {"SECURITY_MANAGER": "DefaultSubjectContext.SECURITY_MANAGER",
            "SESSION_ID": "DefaultSubjectContext.SESSION_ID",
            "AUTHENTICATION_TOKEN": "DefaultSubjectContext.AUTHENTICATION_TOKEN",
            "ACCOUNT": "DefaultSubjectContext.ACCOUNT",
            "SUBJECT": "DefaultSubjectContext.SUBJECT",
            "IDENTIFIERS": "DefaultSubjectContext.IDENTIFIERS",
            "SESSION": "DefaultSubjectContext.SESSION",
            "AUTHENTICATED": "DefaultSubjectContext.AUTHENTICATED",
            "HOST": "DefaultSubjectContext.HOST",
            "SESSION_CREATION_ENABLED": "DefaultSubjectContext.SESSION_CREATION_ENABLED",
            "IDENTIFIERS_SESSION_KEY": "DefaultSubjectContext_IDENTIFIERS_SESSION_KEY",
            "AUTHENTICATED_SESSION_KEY": "DefaultSubjectContext_AUTHENTICATED_SESSION_KEY"}


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
