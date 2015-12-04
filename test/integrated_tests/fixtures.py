from yosai.core import (
    AccountStoreRealm,
)

from yosai_dpcache.cache import DPCacheHandler
from yosai_alchemystore import AlchemyAccountStore

import pytest


@pytest.fixture(scope='function')
def cache_handler():
    return DPCacheHandler()


@pytest.fixture(scope='function')
def alchemy_store():
    return AlchemyAccountStore()


@pytest.fixture(scope='function')
def account_store_realm(cache_handler, permission_resolver,
                        role_resolver, credential_resolver,
                        authz_info_resolver, alchemy_store):
    asr = AccountStoreRealm()

    asr.cache_handler = cache_handler
    asr.account_store = alchemy_store
    asr.permission_resolver = permission_resolver
    asr.credential_resolver = credential_resolver
    asr.authz_info_resolver = authz_info_resolver
    asr.role_resolver = role_resolver

    return asr
