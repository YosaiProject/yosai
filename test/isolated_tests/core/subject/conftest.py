import pytest

from yosai.core import (
    SubjectContext,
    SubjectStore,
    DelegatingSubject,
    SecurityManagerCreator,
    SimpleIdentifierCollection,
)


@pytest.fixture(scope='function')
def subject_context(yosai):
    return SubjectContext(yosai=yosai, security_manager=yosai.security_manager)


@pytest.fixture(scope='function')
def sic_serialized():
    return {'source_identifiers': [['realm1', 'username']],
            '_primary_identifier': None}


@pytest.fixture(scope='function')
def default_subject_store():
    return SubjectStore()

# mock_session and mock_security_manager obtained from ../conftest:
@pytest.fixture(scope='function')
def delegating_subject(
        mock_session, simple_identifiers_collection, mock_security_manager):
    return DelegatingSubject(identifiers=simple_identifiers_collection,
                             authenticated=False,
                             host='127.0.0.1',
                             session=mock_session,
                             session_creation_enabled=True,
                             security_manager=mock_security_manager)

# mock_session and mock_security_manager obtained from ../conftest:
@pytest.fixture(scope='function')
def subject_builder_context(
        simple_identifiers_collection, mock_session, mock_security_manager):
    return dict(security_manager=mock_security_manager,
                host='127.0.0.1',
                session_id='sessionid123',
                session=mock_session,
                identifiers=simple_identifiers_collection,
                session_creation_enabled=True,
                authenticated=True,
                attribute1='attribute1',
                attribute2='attribute2')


@pytest.fixture(scope='function')
def security_manager_creator():
    return SecurityManagerCreator()
