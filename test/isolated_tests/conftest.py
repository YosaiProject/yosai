import pytest
from unittest import mock

from yosai.core import (
    SimpleIdentifierCollection,
)

from yosai.web import (
    DefaultWebSubjectContext,
    WebDelegatingSession,
    WebDelegatingSubject,
    WebSubjectBuilder,
)


@pytest.fixture(scope='function')
def mock_web_delegating_session():
    return mock.create_autospec(WebDelegatingSession)


@pytest.fixture(scope='function')
def mock_web_stopping_aware_proxied_session():
    return mock.create_autospec(WebDelegatingSubject.StoppingAwareProxiedSession)


@pytest.fixture(scope='function')
def mock_web_delegating_subject():
    return mock.create_autospec(WebDelegatingSubject)


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
def web_subject_context(web_yosai, mock_web_registry):
    return DefaultWebSubjectContext(web_yosai,
                                    web_yosai.security_manager,
                                    mock_web_registry)


@pytest.fixture(scope='function')
def web_subject_builder(web_yosai):
    return WebSubjectBuilder(web_yosai, web_yosai.security_manager)
