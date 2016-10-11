import pytest

from yosai.core import (
    DefaultAuthenticator,
)

import datetime


@pytest.fixture(scope='function')
def default_authenticator(account_store_realm, event_bus, settings):
    da = DefaultAuthenticator(settings)
    da.event_bus = event_bus
    da.init_realms((account_store_realm,))
    return da
