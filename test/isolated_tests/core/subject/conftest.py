import pytest

from yosai.core import (
    DefaultSubjectContext,
    DefaultSubjectFactory,
    DefaultSubjectStore,
    DelegatingSubject,
    SimpleIdentifierCollection,
    SubjectBuilder,
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
def default_subject_context(yosai, subject_context, 
                            full_mock_account, mock_session):
    csu = yosai
    context = {value: 'value_'+value for key, value in subject_context.items()}
    context["DefaultSubjectContext.ACCOUNT"] = full_mock_account
    context["DefaultSubjectContext.AUTHENTICATED"] = False
    return DefaultSubjectContext(security_utils=csu, context=context)


@pytest.fixture(scope='function')
def sic_serialized():
    return {'source_identifiers': [['realm1', 'username']],
            '_primary_identifier': None}


@pytest.fixture(scope='function')
def default_subject_store():
    return DefaultSubjectStore()

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
def subject_builder(subject_builder_context, yosai):
    return SubjectBuilder(security_utils=yosai,
                          **subject_builder_context)

@pytest.fixture(scope='function')
def default_subject_factory():
    return DefaultSubjectFactory()
