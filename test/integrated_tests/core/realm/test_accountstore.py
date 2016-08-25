from yosai.core import (
    Account,
    IndexedAuthorizationInfo,
    SimpleIdentifierCollection,
    account_abcs,
    cache_abcs,
)
import pytest


@pytest.mark.parametrize('identifier, expected_in, expected_out, expected_class',
                         [('thedude',
                          "Could not obtain cached", "No account", Account),
                          ('thedude',
                           "get cached", "Could not obtain cached", Account)])
def test_get_credentials(identifier, expected_in, expected_out, expected_class,
                         caplog, account_store_realm, cache_handler):

    """
    I) Obtains from account store, caches
    II) Obtains from cache
    III) Fails to obtain from any source
    """
    asr = account_store_realm
    if "Could not" in expected_in:
        cache_handler.delete(domain="credentials", identifier='thedude')
    result = asr.get_credentials(identifier=identifier)

    out = caplog.text

    assert (expected_in in out and
            expected_out not in out)

    assert isinstance(result, expected_class)


@pytest.mark.parametrize('identifiers, expected_in, expected_out, expected_class',
                         [(SimpleIdentifierCollection(source_name='AccountStoreRealm',
                                                      identifier='thedude'),
                           "Could not obtain cached", "No account", Account),
                          (SimpleIdentifierCollection(source_name='AccountStoreRealm',
                                                      identifier='thedude'),
                           "get cached", "Could not obtain cached", Account),
                          (SimpleIdentifierCollection(source_name='AccountStoreRealm',
                                                      identifier='anonymous'),
                           "No account", "blabla", type(None))])
def test_get_authz_info(identifiers, expected_in, expected_out, expected_class,
                        caplog, account_store_realm, cache_handler):
    """
    I) Obtains from account store, caches
    II) Obtains from cache
    III) Fails to obtain from any source
    """
    asr = account_store_realm

    if "Could not" in expected_in:
        cache_handler.delete(domain="authz_info", identifier='thedude')

    result = asr.get_authorization_info(identifiers=identifiers)

    out = caplog.text
    assert (expected_in in out and
            expected_out not in out)

    assert isinstance(result, expected_class)


def test_do_clear_cache(account_store_realm):
    account_store_realm.do_clear_cache('thedude')
