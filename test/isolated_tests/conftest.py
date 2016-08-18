import pytest
from unittest import mock

from yosai.core import (
    SessionEventHandler,
    SimpleIdentifierCollection,
)

from yosai.web import (
    CookieRememberMeManager,
    DefaultWebSessionStorageEvaluator,
    DefaultWebSubjectContext,
    DefaultWebSubjectFactory,
    WebCachingSessionStore,
    WebDelegatingSession,
    WebDelegatingSubject,
    WebProxiedSession,
    WebSecurityManager,
    WebSessionFactory,
    WebSessionHandler,
    WebSessionKey,
    WebSimpleSession,
    WebSubjectBuilder,
)


@pytest.fixture(scope='function')
def web_subject_factory():
    return DefaultWebSubjectFactory()


@pytest.fixture(scope='function')
def mock_web_delegating_session():
    return mock.create_autospec(WebDelegatingSession)


@pytest.fixture(scope='function')
def mock_web_stopping_aware_proxied_session():
    return mock.create_autospec(WebDelegatingSubject.StoppingAwareProxiedSession)


@pytest.fixture(scope='function')
def mock_web_delegating_subject(mock_web_registry):
    subject = mock.create_autospec(WebDelegatingSubject)
    subject.web_registry = mock_web_registry
    return subject


@pytest.fixture(scope='function')
def web_stopping_aware_proxied_session():
    return WebDelegatingSubject.StoppingAwareProxiedSession(mock_web_delegating_session,
                                                            mock_web_delegating_subject)


@pytest.fixture(scope='function')
def simple_identifiers_collection():
    return SimpleIdentifierCollection(source_name='realm1',
                                      identifier='username')


@pytest.fixture(scope='function')
def web_delegating_subject(
        mock_web_delegating_session, simple_identifiers_collection,
        mock_web_registry, web_yosai):
    return WebDelegatingSubject(identifiers=simple_identifiers_collection,
                                host='123.45.6789',
                                session=mock_web_delegating_session,
                                security_manager=web_yosai.security_manager,
                                web_registry=mock_web_registry)


@pytest.fixture(scope='function')
def web_security_manager(web_yosai, settings, attributes_schema,
                         account_store_realm, cache_handler, serialization_manager):
    realms = (account_store_realm,)
    return WebSecurityManager(web_yosai,
                              settings,
                              attributes_schema,
                              realms=realms,
                              cache_handler=cache_handler,
                              serialization_manager=serialization_manager)


@pytest.fixture(scope='function')
def web_subject_context(web_yosai, mock_web_registry):
    return DefaultWebSubjectContext(web_yosai,
                                    web_yosai.security_manager,
                                    mock_web_registry)


@pytest.fixture(scope='function')
def web_subject_builder(web_yosai):
    return WebSubjectBuilder(web_yosai, web_yosai.security_manager)


@pytest.fixture(scope='function')
def cookie_rmm(settings):
    return CookieRememberMeManager(settings)


@pytest.fixture(scope='function')
def web_simple_session(attributes_schema):
    return WebSimpleSession(csrf_token='csrftoken123',
                            absolute_timeout=1800000,
                            idle_timeout=600000,
                            attributes_schema=attributes_schema,
                            host='123.45.6789')


@pytest.fixture(scope='function')
def web_session_factory(attributes_schema, settings):
    return WebSessionFactory(attributes_schema, settings)


@pytest.fixture(scope='function')
def web_session_handler():
    mock_session_event_handler = mock.create_autospec(SessionEventHandler)
    return WebSessionHandler(mock_session_event_handler, True)


@pytest.fixture(scope='function')
def web_session_manager(attributes_schema, settings):
    return WebSessionFactory(attributes_schema, settings)


@pytest.fixture(scope='function')
def web_session_key(mock_web_registry):
    return WebSessionKey(session_id='sessionid123',
                         web_register=mock_web_registry)


@pytest.fixture(scope='function')
def web_delegating_session(web_session_manager, web_session_key):
    return WebDelegatingSession(web_session_manager, web_session_key)


@pytest.fixture(scope='function')
def web_proxied_session(web_delegating_session):
    return WebProxiedSession(web_delegating_session)


@pytest.fixture(scope='function')
def web_caching_session_store():
    return WebCachingSessionStore()


@pytest.fixture(scope='function')
def web_session_storage_evaluator():
    return DefaultWebSessionStorageEvaluator()
