from yosai.authc import (
    DefaultCompositeAccountId,
    DefaultCompositeAccount,
)

# DefaultCompositeAccountId Tests
def test_dcaid_get_realm_account_exists(default_composite_accountid,
                                        default_realm_accountids,
                                        monkeypatch):
    monkeypatch.setattr(default_composite_accountid, 'realm_accountids',
                        default_realm_accountids)
    assert default_composite_accountid.get_realm_account_id('realm1')


def test_dcaid_get_realm_account_id_not_exists(default_composite_accountid,
                                               default_realm_accountids,
                                               monkeypatch):
    monkeypatch.setattr(default_composite_accountid, 'realm_accountids',
                        default_realm_accountids)
    result = default_composite_accountid.get_realm_account_id('realm3')
    assert (result is None)
    

def test_dcaid_set_realm_account_id(default_composite_accountid):
    default_composite_accountid.set_realm_account_id('realm3', 24680)
    result = default_composite_accountid.get_realm_account_id('realm3')
    assert (result == {24680})
     
def test_dcaid_inequality_check(default_composite_accountid):
    dcaid1 = default_composite_accountid
    dcaid2 = DefaultCompositeAccountId()

    dcaid1.set_realm_account_id('realm1', 12345)
    dcaid2.set_realm_account_id('realm1', 1234567890)

    assert (dcaid1 != dcaid2)

def test_dcaid_equality_check(default_composite_accountid):
    dcaid1 = default_composite_accountid
    dcaid2 = DefaultCompositeAccountId()

    dcaid1.set_realm_account_id('realm1', 12345)
    dcaid2.set_realm_account_id('realm1', 12345)

    assert (dcaid1 == dcaid2)

# DefaultCompositeAccount Tests
