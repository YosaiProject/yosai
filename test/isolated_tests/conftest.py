import pytest
from unittest import mock

from yosai.core import (
    SimpleIdentifierCollection,
)

from yosai.web import (
    CookieRememberMeManager,
    WebSessionManager,
    WebSessionStorageEvaluator,
    WebSubjectContext,
    WebDelegatingSession,
    WebDelegatingSubject,
    WebSecurityManager,
    WebSessionHandler,
    WebSessionKey,
    WebSimpleSession,
)


@pytest.fixture(scope='function')
def mock_web_delegating_session():
    wds = mock.create_autospec(WebDelegatingSession)
    wds.session_id = 'sessionid987'
    return wds


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
def web_security_manager(web_yosai, settings, account_store_realm,
                         cache_handler, serialization_manager):
    realms = (account_store_realm,)
    return WebSecurityManager(web_yosai,
                              settings,
                              realms=realms,
                              cache_handler=cache_handler,
                              serialization_manager=serialization_manager)


@pytest.fixture(scope='function')
def web_subject_context(web_yosai, mock_web_registry):
    return WebSubjectContext(web_yosai,
                                    web_yosai.security_manager,
                                    mock_web_registry)


@pytest.fixture(scope='function')
def cookie_rmm(settings):
    return CookieRememberMeManager(settings)


@pytest.fixture(scope='function')
def web_simple_session_state():
    internal_attributes = {'identifiers_session_key': 'identifiers_session_key',
                           'authenticated_session_key': 'authenticated_session_key',
                           'run_as_identifiers_session_key': 'run_as_identifiers_session_key',
                           'csrf_token': 'csrftoken123',
                           'flash_messages': {}}

    return {'absolute_timeout': 1800000,
            'idle_timeout': 600000,
            'host': '123.45.6789',
            'session_id': 'sessionid123',
            'start_timestamp': 1471552578153,
            'stop_timestamp': None,
            'last_access_time': 1471552659175,
            'is_expired': False,
            'internal_attributes': internal_attributes}


@pytest.fixture(scope='function')
def mock_web_simple_session():
    mss = mock.create_autospec(WebSimpleSession)
    mss.session_id = 'simplesessionid123'
    return mss


@pytest.fixture(scope='function')
def web_simple_session(web_simple_session_state):
    wss = WebSimpleSession(csrf_token='csrftoken123',
                           absolute_timeout=1800000,
                           idle_timeout=600000,
                           host='123.45.6789')

    wss.__dict__.update(web_simple_session_state)
    return wss


@pytest.fixture(scope='function')
def web_session_handler(event_bus):
    sh = WebSessionHandler(True)
    sh.event_bus = event_bus
    return sh


@pytest.fixture(scope='function')
def web_session_manager(settings):
    return WebSessionManager(settings)


@pytest.fixture(scope='function')
def web_session_key(mock_web_registry):
    return WebSessionKey(session_id='sessionid123',
                         web_registry=mock_web_registry)


@pytest.fixture(scope='function')
def web_delegating_session(web_session_manager, web_session_key):
    return WebDelegatingSession(web_session_manager, web_session_key)



@pytest.fixture(scope='function')
def web_session_storage_evaluator():
    return WebSessionStorageEvaluator()


@pytest.fixture(scope='function')
def mock_session_context(mock_web_registry):
    return {'host': '123.45.6789', 'web_registry': mock_web_registry}
