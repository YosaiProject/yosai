import pytest
from passlib.context import CryptContext

from yosai.core import (
    DefaultAuthenticator,
    UsernamePasswordToken,
    event_bus,
)

from yosai_alchemystore.models.models import (
    CredentialModel,
)

from yosai_alchemystore import (
    Session,
)

import datetime

@pytest.fixture(scope='module')
def clear_cached_credentials(cache_handler, request, thedude):
    def remove_credentials():
        nonlocal cache_handler
        cache_handler.delete(domain="credentials",
                             identifier=thedude.identifier)

    request.addfinalizer(remove_credentials)
    

@pytest.fixture(scope='module')
def thedude_credentials(request, thedude, clear_cached_credentials):
    password = "letsgobowling"
    cc = CryptContext(["bcrypt_sha256"])
    credentials = cc.encrypt(password)
    thirty_from_now = datetime.datetime.now() + datetime.timedelta(days=30)
    credential = CredentialModel(user_id=thedude.pk_id,
                                 credential=credentials,
                                 expiration_dt=thirty_from_now)

    session = Session()
    session.add(credential)
    session.commit()
    
    return credentials


@pytest.fixture(scope='module')
def valid_username_password_token(thedude, thedude_credentials):
    return UsernamePasswordToken(username=thedude.identifier,
                                 password='letsgobowling',
                                 remember_me=False,
                                 host='127.0.0.1')


@pytest.fixture(scope='module')
def invalid_username_password_token():
    return UsernamePasswordToken(username='thedude',
                                 password='never_use__password__',
                                 remember_me=False,
                                 host='127.0.0.1')


@pytest.fixture(scope='module')
def default_authenticator(account_store_realm, credential_resolver):
    da = DefaultAuthenticator()
    da.realms = (account_store_realm,)
    da.event_bus = event_bus
    da.credential_resolver = credential_resolver
    return da

