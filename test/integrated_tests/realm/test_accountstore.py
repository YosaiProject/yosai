from yosai.core import (
    Account,
    IndexedAuthorizationInfo,
    account_abcs,
    cache_abcs,
)
import pytest


@pytest.mark.parametrize('identifiers, expected_in, expected_out, expected_class',
                         [('thedude', "Could not obtain cached", "No account", Account),
                          ('thedude', "get cached", "Could not obtain cached", Account),
                          ('anonymous', "No account", "blabla", type(None))])
def test_get_credentials(identifiers, expected_in, expected_out, expected_class,
                         capsys, account_store_realm):
    """
    I) Obtains from account store, caches
    II) Obtains from cache
    III) Fails to obtain from any source
    """
    asr = account_store_realm

    result = asr.get_credentials(identifiers=identifiers)

    out, err = capsys.readouterr()
    assert (expected_in in out and
            expected_out not in out)

    assert isinstance(result, expected_class)


@pytest.mark.parametrize('identifiers, expected_in, expected_out, expected_class',
                         [('thedude',
                           "Could not obtain cached", "No account",
                           IndexedAuthorizationInfo),
                          ('thedude', "get cached", "Could not obtain cached",
                           IndexedAuthorizationInfo),
                          ('anonymous', "No account", "blabla", type(None))])
def test_get_authz_info(identifiers, expected_in, expected_out, expected_class,
                        capsys, account_store_realm):
    """
    I) Obtains from account store, caches
    II) Obtains from cache
    III) Fails to obtain from any source
    """
    asr = account_store_realm

    result = asr.get_authorization_info(identifiers=identifiers)

    out, err = capsys.readouterr()
    assert (expected_in in out and
            expected_out not in out)

    assert isinstance(result, expected_class)


def test_do_clear_cache(account_store_realm):
    account_store_realm.do_clear_cache('thedude')
