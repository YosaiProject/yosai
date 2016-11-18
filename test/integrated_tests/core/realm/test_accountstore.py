from yosai.core import (
    SimpleIdentifierCollection,
)
import pytest


@pytest.mark.parametrize('identifier, expected_in, expected_out',
                         [('thedude', "Could not obtain cached", "No account"),
                          ('thedude', "get cached", "Could not obtain cached")])
def test_get_authc_info(identifier, expected_in, expected_out,
                        caplog, account_store_realm, cache_handler):

    """
    I) Obtains from account store, caches
    II) Obtains from cache
    III) Fails to obtain from any source
    """
    asr = account_store_realm

    if "Could not" in expected_in:
        keys = cache_handler.keys('*authentication*')
        for key in keys:
            cache_handler.cache_region.delete(key)

    asr.get_authentication_info(identifier=identifier)

    out = caplog.text

    assert (expected_in in out and expected_out not in out)


@pytest.mark.parametrize('identifiers, expected_in, expected_out',
                         [(SimpleIdentifierCollection(source_name='AccountStoreRealm',
                                                      identifier='thedude'),
                           "Could not obtain cached", "No account"),
                          (SimpleIdentifierCollection(source_name='AccountStoreRealm',
                                                      identifier='thedude'),
                           "get cached", "Could not obtain cached")])
def test_get_authzd_permissions(identifiers, expected_in, expected_out,
                                caplog, account_store_realm, cache_handler):
    """
    I) Obtains from account store, caches
    II) Obtains from cache
    III) Fails to obtain from any source
    """
    asr = account_store_realm

    if "Could not" in expected_in:
        keys = cache_handler.keys('*authorization*')
        for key in keys:
            cache_handler.cache_region.delete(key)

    asr.get_authzd_permissions('thedude', 'domain1')

    out = caplog.text
    assert (expected_in in out and
            expected_out not in out)


def test_do_clear_cache(account_store_realm):
    account_store_realm.do_clear_cache('thedude')
