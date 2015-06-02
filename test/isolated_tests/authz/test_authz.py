import pytest
from unittest import mock

from yosai import (
    IllegalStateException,
    ModularRealmAuthorizer,
    UnauthorizedException,
)

def test_mra_authorizing_realms(
        modular_realm_authorizer, authz_realms_collection, monkeypatch):
    """ 
    verify that only realms that implement IAuthorizer are returned in 
    the generator expression

    3 out of 5 of the mock realms in authz_realms_collection implement IAuthorizer
    """
    mra = modular_realm_authorizer
    monkeypatch.setattr(mra, '_realms', authz_realms_collection)
    
    result = list(mra.authorizing_realms)  # wrap the generator in a list
    assert len(result) == 3

def test_mra_pr_setter_succeeds(modular_realm_authorizer):
    """
    unit tested:  permission_resolver.setter 

    the property setter assigns the attribute and then calls the apply.. method
    """

    mra = modular_realm_authorizer

    with mock.patch.object(ModularRealmAuthorizer,
                           'apply_permission_resolver_to_realms') as apr:
        apr.return_value = None
        mra.permission_resolver = 'arbitrary value'
        assert apr.called 

def test_mra_aprtr_succeeds(
        modular_realm_authorizer, monkeypatch, authz_realms_collection):
    """
    unit tested:  apply_permission_resolver_to_realms

    to apply a permission resolver to realms, both the resolver and realms 
    attributes must be set in the ModularRealmAuthorizer and the realm 
    must implement the IPermissionResolverAware interface--  3 out of 5 realms
    in realms_collection do
    """
    mra = modular_realm_authorizer

    # testing only checks that the attributes are set, not what they are set to
    monkeypatch.setattr(mra, '_realms', authz_realms_collection) 
    monkeypatch.setattr(mra, '_permission_resolver', 'arbitrary value') 

    # no permission_resolver exists in each realm until this method is called: 
    mra.apply_permission_resolver_to_realms()
    
    configured_realms =\
        [realm for realm in mra.realms 
         if (getattr(realm, '_permission_resolver', None) == 'arbitrary value')]

    assert len(configured_realms) == 3

def test_mra_aprtr_fails(
        modular_realm_authorizer, monkeypatch, authz_realms_collection):
    """
    unit tested:  apply_permission_resolver_to_realms
    
    to apply a permission resolver to realms, both the resolver and realms 
    attributes must be set in the ModularRealmAuthorizer and the realm 
    must implement the IPermissionResolverAware interface

    """
    mra = modular_realm_authorizer
    monkeypatch.setattr(mra, '_realms', authz_realms_collection) 
    # not setting the resolver, so to exercise failed code path
    
    configured_realms =\
        [realm for realm in mra.realms 
         if (getattr(realm, '_permission_resolver', None) == 'arbitrary_value')]

    assert len(configured_realms) == 0

def test_mra_rpr_setter_succeeds(modular_realm_authorizer):
    """
    unit tested:  role_permission_resolver.setter 

    the property setter assigns the attribute and then calls the apply.. method
    """

    mra = modular_realm_authorizer

    with mock.patch.object(ModularRealmAuthorizer,
                           'apply_role_permission_resolver_to_realms') as arpr:
        arpr.return_value = None
        mra.role_permission_resolver = 'arbitrary value'
        assert arpr.called 


def test_mra_arprtr_succeeds(
        modular_realm_authorizer, monkeypatch, authz_realms_collection):
    """
    unit tested:  apply_role_permission_resolver_to_realms

    to apply a role permission resolver to realms, both the resolver and realms 
    attributes must be set in the ModularRealmAuthorizer and the realm 
    must implement the IRolePermissionResolverAware interface--  3 out of 5 realms
    in realms_collection do
    """
    mra = modular_realm_authorizer

    # testing only checks that the attributes are set, not what they are set to
    monkeypatch.setattr(mra, '_realms', authz_realms_collection) 
    monkeypatch.setattr(mra, '_role_permission_resolver', 'arbitrary value') 

    # no permission_resolver exists in each realm until this method is called: 
    mra.apply_role_permission_resolver_to_realms()
    
    configured_realms =\
        [realm for realm in mra.realms 
         if (getattr(realm, '_role_permission_resolver', None) == 'arbitrary value')]

    assert len(configured_realms) == 3

def test_mra_arprtr_fails(
        modular_realm_authorizer, monkeypatch, authz_realms_collection):
    """
    unit tested:  apply_role_permission_resolver_to_realms
    
    to apply a permission resolver to realms, both the resolver and realms 
    attributes must be set in the ModularRealmAuthorizer and the realm 
    must implement the IRolePermissionResolverAware interface

    """
    mra = modular_realm_authorizer
    monkeypatch.setattr(mra, '_realms', authz_realms_collection) 
    # not setting the resolver, so to exercise failed code path
    
    configured_realms =\
        [realm for realm in mra.realms 
         if (getattr(realm, '_role_permission_resolver', None) == 'arbitrary_value')]

    assert len(configured_realms) == 0

def test_mra_assert_realms_configured_success(
        modular_realm_authorizer, authz_realms_collection, monkeypatch):
    """
    unit tested:  assert_realms_configured 
    
    if the realms attribute isn't set, an exception raises
    """
    mra = modular_realm_authorizer
    monkeypatch.setattr(mra, '_realms', authz_realms_collection) 
    assert mra.assert_realms_configured() is None
    

def test_mra_assert_realms_configured_fail(modular_realm_authorizer):
    """
    unit tested:  assert_realms_configured 
    
    if the realms attribute isn't set, an exception raises
    """
    mra = modular_realm_authorizer
    with pytest.raises(IllegalStateException): 
        mra.assert_realms_configured()

def test_private_has_role_true
# def test_private_has_role_false
# def test_private_role_collection_yields
# def test_private_is_permitted_true
# def test_private_is_permitted_false
# def test_private_permit_collection_yields
# def test_is_permitted_collection_returns_truefalsefalse
# def test_is_permitted_single_permission_returns_true
# def test_is_permitted_single_permission_returns_false
# def test_is_permitted_all_collection_false
# def test_is_permitted_all_collection_true
# def test_is_permitted_all_single_true
# def test_is_permitted_all_single_false
# def test_check_permission_collection_false
# def test_check_permission_collection_true
# def test_has_role_collection_returns_truefalsefalse
# def test_has_role_single_role_returns_true
# def test_has_role_single_role_returns_false
# def test_has_all_roles_collection_false
# def test_has_all_roles_collection_true
# def test_has_all_roles_single_true
# def test_has_all_roles_single_false
# def test_check_role_collection_false
# def test_check_role_collection_true

