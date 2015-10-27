from yosai import (
    DefaultSecurityManager,
)

import pytest

from .doubles import (
    MockRememberMeManager,
)

@pytest.fixture(scope='function')
def default_security_manager():
    return DefaultSecurityManager()

@pytest.fixture(scope='function')
def dependencies_for_injection(default_security_manager):
    dsm = default_security_manager
    return {dsm._event_bus, dsm._cache_manager, dsm.realms, 
            dsm.authenticator, dsm.authorizer,
            dsm.session_manager, dsm.subject_store,
            dsm.subject_factory}

@pytest.fixture(scope='function')
def mock_remember_me_manager():
    return MockRememberMeManager()

