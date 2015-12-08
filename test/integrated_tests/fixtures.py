from yosai.core import (
    AccountStoreRealm,
)

from yosai_alchemystore import (
    Base,
    engine,
)

from yosai_alchemystore.models.models import (
    UserModel,
)

from yosai_alchemystore import (
    Session,
    meta,
)
from yosai_dpcache.cache import DPCacheHandler
from yosai_alchemystore import AlchemyAccountStore

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
def thedude(cache_handler, request):
    thedude = UserModel(first_name='Jeffrey',
                        last_name='Lebowski',
                        identifier='thedude')
    
    session = Session()
    session.add(thedude)
    session.commit()

    return thedude

