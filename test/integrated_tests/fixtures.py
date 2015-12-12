from yosai.core import (
    AccountStoreRealm,
    NativeSecurityManager,
    event_bus,
    UsernamePasswordToken,
    SecurityUtils,
    SimpleIdentifierCollection,
)

from yosai_alchemystore import (
    Base,
    engine,
)

from yosai_alchemystore.models.models import (
    UserModel,
    CredentialModel,
)

from yosai_alchemystore import (
    Session,
)
from yosai_dpcache.cache import DPCacheHandler
from yosai_alchemystore import AlchemyAccountStore
from passlib.context import CryptContext
import datetime
import pytest


@pytest.fixture(scope='module')
def test_db(request):
    Base.metadata.create_all(engine)

    def drop_all():
        Base.metadata.drop_all(engine)

    request.addfinalizer(drop_all)

@pytest.fixture(scope='module')
def cache_handler():
    return DPCacheHandler()


@pytest.fixture(scope='module')
def alchemy_store(test_db):
    return AlchemyAccountStore()


@pytest.fixture(scope='module')
def account_store_realm(cache_handler, alchemy_store):
    asr = AccountStoreRealm()

    asr.cache_handler = cache_handler
    asr.account_store = alchemy_store

    return asr


#def init_test_db():
# creates an in-memory sqlite instance
#    engine = create_engine('sqlite://')

@pytest.fixture(scope='module')
def thedude_identifier():
    return SimpleIdentifierCollection(source_name='AccountStoreRealm',
                                      identifiers={'thedude'})

@pytest.fixture(scope='module')
def thedude(cache_handler, request, thedude_identifier):
    thedude = UserModel(first_name='Jeffrey',
                        last_name='Lebowski',
                        identifier='thedude')

    session = Session()
    session.add(thedude)
    session.commit()

    return thedude


@pytest.fixture(scope='module')
def valid_username_password_token():
    return UsernamePasswordToken(username='thedude',
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
def clear_cached_credentials(cache_handler, request, thedude):
    def remove_credentials():
        nonlocal cache_handler
        cache_handler.delete(domain="credentials",
                             identifier=thedude.primary_identifier)

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
def native_security_manager(account_store_realm, cache_handler):
    nsm = NativeSecurityManager(realms=(account_store_realm,))
    nsm.cache_handler = cache_handler
    nsm.event_bus = event_bus
    return nsm


@pytest.fixture(scope='module')
def configured_securityutils(native_security_manager):
    SecurityUtils.security_manager = native_security_manager


@pytest.fixture(scope='module')
def new_subject(configured_securityutils):
    return SecurityUtils.get_subject()

