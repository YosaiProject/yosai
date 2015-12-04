from yosai.core import (
    Account,
    account_abcs,
    cache_abcs,
)
import pytest


@pytest.mark.parametrize('identifier, expected_in, expected_out, expected_class',
                         [('thedude', "Could not obtain cached", "No account", Account),
                          ('thedude', "get cached", "Could not obtain cached", Account),
                          ('anonymous', "No account", "blabla", type(None))])
def test_get_credentials(identifier, expected_in, expected_out, expected_class,
                         capsys, account_store_realm):
    """
    I) Obtains from account store, caches
    II) Obtains from cache
    III) Fails to obtain from any source
    """
    asr = account_store_realm

    result = asr.get_credentials(identifier=identifier)

    out, err = capsys.readouterr()
    assert (expected_in in out and
            expected_out not in out)

    assert isinstance(result, expected_class)
