import pytest

from yosai import (
    RealmAttributesException,
)

from yosai.authc import (
    DefaultCompositeAccountId,
    DefaultCompositeAccount,
)

# ----------------------------------------------------------------------------
# DefaultCompositeAccountId Tests
# ----------------------------------------------------------------------------
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

# ----------------------------------------------------------------------------
# DefaultCompositeAccount Tests
# ----------------------------------------------------------------------------

def test_append_realm_account_verify_dcaid(
        default_composite_account, full_mock_account):
    """ confirms that the DefaultCompositeAccountId adds the account id """ 
    dca = default_composite_account
    dca.append_realm_account('realm1', full_mock_account)
    assert dca.id.get_realm_account_id('realm1') == {full_mock_account.id}


def test_append_realm_account_with_attributes_no_overwrite_realmattrs_success(
        default_composite_account, full_mock_account):
    """ confirms that the realm_attrs is updated """
    dca = default_composite_account
    dca.overwrite = False
    dca.append_realm_account('realm1', full_mock_account)
    assert dca.get_realm_attributes('realm1') == full_mock_account.attributes

def test_append_realm_account_with_attributes_no_overwrite_merge_success(
        default_composite_account, full_mock_account):
    """ confirms that the merged_attrs is updated """
    dca = default_composite_account
    dca.overwrite = False
    dca.append_realm_account('realm1', full_mock_account)
    assert dca.attributes == full_mock_account.attributes

def test_append_realm_account_with_attributes_no_overwrite_nomerge_success(
        default_composite_account, full_mock_account):
    """ when merged_attrs already exit, they should not be overwritten when 
        overwrite=False
    """
    dca = default_composite_account
    dca.overwrite = False
    dca.append_realm_account('realm1', full_mock_account)
    attrs = {'attr4': 4, 'attr5': 5}
    full_mock_account.attributes.update(attrs)
    dca.append_realm_account('realm1', full_mock_account)  # with 5 attributes 
    assert len(dca.get_realm_attributes('realm1')) ==\
        len(full_mock_account.attributes)

def test_append_realm_account_with_attributes_overwrite_success(
        default_composite_account, full_mock_account):
    """ when merged_attrs already exit, they should be overwritten when 
        overwrite=True
    """
    dca = default_composite_account
    dca.overwrite = False
    dca.append_realm_account('realm1', full_mock_account)
    attrs = {'attr1': 'one', 'attr2': 'two', 'attr3': 'three'}
    full_mock_account.attributes.update(attrs)
    dca.append_realm_account('realm1', full_mock_account)  # with 5 attributes 
    assert dca.get_realm_attributes('realm1') == full_mock_account.attributes


def test_append_realm_account_with_attributes_update_fails(
        default_composite_account, full_mock_account, monkeypatch):
    """ realm attributes must be a dict, otherwrise an exception will raise """

    dca = default_composite_account
    monkeypatch.setattr(full_mock_account, '_attributes', (1, 2, 3, 4, 5))
    with pytest.raises(RealmAttributesException):
        dca.append_realm_account('realm1', full_mock_account)


def test_append_realm_account_without_attributes(
        default_composite_account, full_mock_account, monkeypatch):
    
    dca = default_composite_account
    monkeypatch.delattr(full_mock_account, '_attributes')
    dca.append_realm_account('realm1', full_mock_account)
    assert not dca.get_realm_attributes('realm1')
