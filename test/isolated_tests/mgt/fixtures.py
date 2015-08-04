from yosai import (
    DefaultSecurityManager,
)

import pytest


@pytest.fixture(scope='function')
def default_security_manager():
    return DefaultSecurityManager()

@pytest.fixture(scope='function')
def dependencies_for_injection(default_security_manager):
    dsm = default_security_manager
    return {dsm._event_bus, dsm._cache_manager, dsm.realms, 
            dsm.authenticator, dsm.authorizer,
            dsm.session_manager, dsm.subject_DAO,
            dsm.subject_factory}
