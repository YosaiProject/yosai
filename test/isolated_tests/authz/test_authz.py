import pytest
from unittest import mock

from yosai import (
    IllegalStateException,
    ModularRealmAuthorizer,
    UnauthorizedException,
)

# -----------------------------------------------------------------------------
# ModularRealmAuthorizer Tests
# -----------------------------------------------------------------------------

def test_mra_authorizing_realms(modular_realm_authorizer_fff):
    """ 
    unit tested:  authorizing_realms

    test case: 
    verify that only realms that implement IAuthorizer are returned in 
    the generator expression
    
    3 out of 5 of the mock realms in authz_realms_collection_fff implement IAuthorizer
    """
    mra = modular_realm_authorizer_fff
    
    result = list(mra.authorizing_realms)  # wrap the generator in a list
    assert len(result) == 3

def test_mra_pr_setter_succeeds(modular_realm_authorizer_fff):
    """
    unit tested:  permission_resolver.setter 

    test case: 
    the property setter assigns the attribute and then calls the apply.. method
    """

    mra = modular_realm_authorizer_fff

    with mock.patch.object(ModularRealmAuthorizer,
                           'apply_permission_resolver_to_realms') as apr:
        apr.return_value = None
        mra.permission_resolver = 'arbitrary value'
        assert apr.called 

def test_mra_aprtr_succeeds(modular_realm_authorizer_fff, monkeypatch):
    """
    unit tested:  apply_permission_resolver_to_realms

    test case: 
    to apply a permission resolver to realms, both the resolver and realms 
    attributes must be set in the ModularRealmAuthorizer and the realm 
    must implement the IPermissionResolverAware interface--  3 out of 5 realms
    in realms_collection do
    """
    mra = modular_realm_authorizer_fff

    # testing only checks that the attributes are set, not what they are set to
    monkeypatch.setattr(mra, '_permission_resolver', 'arbitrary value') 

    # no permission_resolver exists in each realm until this method is called: 
    mra.apply_permission_resolver_to_realms()
    
    configured_realms =\
        [realm for realm in mra.realms 
         if (getattr(realm, '_permission_resolver', None) == 'arbitrary value')]

    assert len(configured_realms) == 3

def test_mra_aprtr_fails(modular_realm_authorizer_fff):
    """
    unit tested:  apply_permission_resolver_to_realms

    test case: 
    to apply a permission resolver to realms, both the resolver and realms 
    attributes must be set in the ModularRealmAuthorizer and the realm 
    must implement the IPermissionResolverAware interface

    """
    mra = modular_realm_authorizer_fff
    # not setting the resolver, so to exercise failed code path
    
    configured_realms =\
        [realm for realm in mra.realms 
         if (getattr(realm, '_permission_resolver', None) == 'arbitrary_value')]

    assert len(configured_realms) == 0

def test_mra_rpr_setter_succeeds(modular_realm_authorizer_fff):
    """
    unit tested:  role_permission_resolver.setter 

    test case: 
    the property setter assigns the attribute and then calls the apply.. method
    """

    mra = modular_realm_authorizer_fff

    with mock.patch.object(ModularRealmAuthorizer,
                           'apply_role_permission_resolver_to_realms') as arpr:
        arpr.return_value = None
        mra.role_permission_resolver = 'arbitrary value'
        assert arpr.called 


def test_mra_arprtr_succeeds(modular_realm_authorizer_ftf, monkeypatch):
    """
    unit tested:  apply_role_permission_resolver_to_realms

    test case: 
    to apply a role permission resolver to realms, both the resolver and realms 
    attributes must be set in the ModularRealmAuthorizer and the realm 
    must implement the IRolePermissionResolverAware interface--  3 out of 5 realms
    in realms_collection do
    """
    mra = modular_realm_authorizer_ftf

    # testing only checks that the attributes are set, not what they are set to
    monkeypatch.setattr(mra, '_role_permission_resolver', 'arbitrary value') 

    # no permission_resolver exists in each realm until this method is called: 
    mra.apply_role_permission_resolver_to_realms()
    
    configured_realms =\
        [realm for realm in mra.realms 
         if (getattr(realm, '_role_permission_resolver', None) == 'arbitrary value')]

    assert len(configured_realms) == 3

def test_mra_arprtr_fails(modular_realm_authorizer_fff):
    """
    unit tested:  apply_role_permission_resolver_to_realms

    test case: 
    to apply a permission resolver to realms, both the resolver and realms 
    attributes must be set in the ModularRealmAuthorizer and the realm 
    must implement the IRolePermissionResolverAware interface

    """
    mra = modular_realm_authorizer_fff
    
    configured_realms =\
        [realm for realm in mra.realms 
         if (getattr(realm, '_role_permission_resolver', None) == 'arbitrary_value')]

    assert len(configured_realms) == 0

def test_mra_assert_realms_configured_success(modular_realm_authorizer_fff):
    """
    unit tested:  assert_realms_configured 
    
    test case: if the realms attribute isn't set, an exception raises
    """
    mra = modular_realm_authorizer_fff
    assert mra.assert_realms_configured() is None

def test_mra_assert_realms_configured_fail(
        modular_realm_authorizer_fff, monkeypatch):
    """
    unit tested:  assert_realms_configured 
    
    test case:  if the realms attribute isn't set, an exception raises
    """
    mra = modular_realm_authorizer_fff
    monkeypatch.setattr(mra, '_realms', None)
    with pytest.raises(IllegalStateException): 
        mra.assert_realms_configured()

def test_private_has_role_true(modular_realm_authorizer_ftf):
    """
    unit tested:  _has_role

    test case:  
    a realm confirming role assignment (a principal is assigned a role)
    """
    mra = modular_realm_authorizer_ftf
    result = mra._has_role('arbitrary_principals', 'arbitrary_roleid')
    assert result is True

def test_private_has_role_false(modular_realm_authorizer_fff):
    """
    unit tested:  _has_role

    test case:  
    a realm denies role affiliation 
    """
    mra = modular_realm_authorizer_fff
    result = mra._has_role('arbitrary_principals', 'arbitrary_roleid')
    assert result is False 

def test_private_role_collection_yields(modular_realm_authorizer_ftf):
    """
    unit tested:  _role_collection

    test case:  
    a collection of realms and their respective has_role Boolean is returned 
    as a generator expression
    """
    mra = modular_realm_authorizer_ftf
    result = [check for check in 
              mra._role_collection('arbitrary_principals', 
                                   ['roleid1', 'roleid2'])]
    assert all(x in result for x in [('roleid1', True), ('roleid2', True)])

def test_private_is_permitted_true(modular_realm_authorizer_ftf):
    """
    unit tested:  _is_permitted

    test case:  
    a realm confirming privilege (a principal IS granted permission)
    """
    mra = modular_realm_authorizer_ftf
    result = mra._is_permitted('arbitrary_principals', 'permission')
    assert result is True

def test_private_is_permitted_false(modular_realm_authorizer_fff):
    """
    unit tested:  _is_permitted

    test case:  
    permission is denied
    """
    mra = modular_realm_authorizer_fff
    result = mra._is_permitted('arbitrary_principals', 'permission')
    assert result is False 

def test_private_permit_collection_yields(modular_realm_authorizer_fff):
    """
    unit tested:  _permit_collection

    test case:  
    a collection of realms and their respective is_permitted Boolean is 
    returned as a generator expression
    """
    mra = modular_realm_authorizer_fff
    result = [check for check in 
              mra._permit_collection('arbitrary_principals', 
                                     ['perm1', 'perm2'])]
    assert all(x in result for x in [('perm1', False), ('perm2', False)])

def test_is_permitted_collection_returns_falsefalsefalse(
        modular_realm_authorizer_fff):
    """
    unit tested:  is_permitted

    when passed a list of permissions, returns a list of Tuples
    """
    mra = modular_realm_authorizer_fff
    result = mra.is_permitted('arbitrary', ['perm1', 'perm2', 'perm3'])
    assert all(x in result for x in [('perm1', False), ('perm2', False),
                                     ('perm3', False)])
    
def test_is_permitted_single_permission_returns_true(
        modular_realm_authorizer_ftf):
    """
    unit tested:  is_permitted

    test case:  
    a single permission argument receives a single Boolean response 
    """
    mra = modular_realm_authorizer_ftf
    result = mra.is_permitted('arbitrary_principals', 'permission')
    assert result[0][1] == True

def test_is_permitted_single_permission_returns_false(
        modular_realm_authorizer_fff):
    """
    unit tested:  is_permitted

    test case:  
    a single permission argument receives a single Boolean response 
    """
    mra = modular_realm_authorizer_fff
    result = mra.is_permitted('arbitrary_principals', 'permission')
    assert result[0][1] == False 

def test_is_permitted_all_collection_false(modular_realm_authorizer_fff):
    """
    unit tested:  is_permitted_all
    
    test case:  
    a collection of permissions receives a single Boolean
    """
    mra = modular_realm_authorizer_fff
    result = mra.is_permitted_all('arbitrary_principals', 
                                  ['perm1', 'perm2', 'perm3'])
    assert result is False 

def test_is_permitted_all_collection_true(
        modular_realm_authorizer_ftf):
    """
    unit tested:  is_permitted_all

    test case:  
    a collection of permissions receives a single Boolean
    """
    mra = modular_realm_authorizer_ftf
    result = mra.is_permitted_all('arbitrary_principals', 
                                  ['perm1', 'perm2', 'perm3'])
    assert result is True 

def test_is_permitted_all_single_true(modular_realm_authorizer_ftf):
    """
    unit tested:  is_permitted_all

    test case:  
    a single permission receives a single Boolean
    """
    mra = modular_realm_authorizer_ftf
    result = mra.is_permitted_all('arbitrary_principals', 'perm1')
    assert result is True 

def test_is_permitted_all_single_false(modular_realm_authorizer_fff):
    """
    unit tested:  is_permitted_all

    test case:  
    a single permission receives a single Boolean
    """
    mra = modular_realm_authorizer_fff
    result = mra.is_permitted_all('arbitrary_principals', 'perm1')
    assert result is False 

def test_check_permission_collection_raises(modular_realm_authorizer_fff):
    """
    unit tested:  check_permission

    test case:
    check_permission raises an exception if any permission isn't entitled
    """
    mra = modular_realm_authorizer_fff
    with pytest.raises(UnauthorizedException):
        mra.check_permission('arbitrary_principals', ['perm1', 'perm2'])

def test_check_permission_collection_succeeds(modular_realm_authorizer_ftf):
    """
    unit tested:  check_permission

    test case:
    check_permission raises an exception if any permission isn't entitled,
    and nothing returned if success 
    """
    mra = modular_realm_authorizer_ftf
    result = mra.check_permission('arbitrary_principals', ['perm1', 'perm2'])
    assert result is None

def test_has_role_collection_returns_truetruetrue(
        modular_realm_authorizer_ftf):
    """
    unit tested:  has_role 
        
    when passed a list of roleids, returns a list of Tuples
    """
    mra = modular_realm_authorizer_ftf
    result = mra.has_role('arbitrary', ['roleid1', 'roleid2', 'roleid3'])
    assert all(x in result for x in [('roleid1', True), ('roleid2', True),
                                     ('roleid3', True)])
    
def test_has_role_single_role_returns_true(modular_realm_authorizer_ftf):
    """
    unit tested:  has_role 

    test case:  
    when passed a single roleid, returns a list containing one Tuple
    """
    mra = modular_realm_authorizer_ftf
    result = mra.has_role('arbitrary_principals', 'roleid1')
    assert result[0][1] == True

def test_has_role_single_role_returns_false(modular_realm_authorizer_fff):
    """
    unit tested:  has_role 

    test case:  
    when passed a single roleid, returns a list containing one Tuple
    """
    mra = modular_realm_authorizer_fff
    result = mra.has_role('arbitrary_principals', 'roleid1')
    assert result[0][1] == False 

def test_has_all_roles_collection_false(
        modular_realm_authorizer_fff):
    """
    unit tested:  has_all_roles

    test case:  
    a collection of roleids receives a single Boolean
    """
    mra = modular_realm_authorizer_fff
    result = mra.has_all_roles('arbitrary_principals', 
                               ['roleid1', 'roleid2', 'roleid3'])
    assert result is False 

def test_has_all_roles_collection_true(modular_realm_authorizer_ftf):
    """
    unit tested:  has_all_roles

    test case:  
    a collection of roleids receives a single Boolean
    """
    mra = modular_realm_authorizer_ftf
    result = mra.has_all_roles('arbitrary_principals', 
                               ['roleid1', 'roleid2', 'roleid3'])
    assert result is True 

def test_has_all_roles_single_true(modular_realm_authorizer_ftf):
    """
    unit tested:  has_all_roles

    test case:  
    a single permission receives a single Boolean
    """
    mra = modular_realm_authorizer_ftf
    result = mra.is_permitted_all('arbitrary_principals', 'roleid1')
    assert result is True 

def test_has_all_roles_single_false(modular_realm_authorizer_fff):
    """
    unit tested:  has_all_roles
    
    test case:  
    a single permission receives a single Boolean
    """
    mra = modular_realm_authorizer_fff
    result = mra.has_all_roles('arbitrary_principals', 'roleid1')
    assert result is False 

def test_check_role_collection_false(modular_realm_authorizer_fff):
    """
    unit tested:  check_role 

    test case:
    check_role raises an exception if any permission isn't entitled,
    and nothing returned if success 
    """
    mra = modular_realm_authorizer_fff
    with pytest.raises(UnauthorizedException):
        mra.check_role('arbitrary_principals', ['roleid1', 'roleid2'])

def test_check_role_collection_true(modular_realm_authorizer_ftf):
    """
    unit tested:  check_role 

    test case:
    check_role raises an exception if any permission isn't entitled,
    and nothing returned if success 
    """
    mra = modular_realm_authorizer_ftf
    result = mra.check_role('arbitrary_principals', ['roleid1', 'roleid2'])
    assert result is None


# -----------------------------------------------------------------------------
# SimpleAuthorizationInfo Tests
# -----------------------------------------------------------------------------
def test_add_role_no_init_roles(simple_authz_info):
    """
    unit tested:  add_role

    test case:  
    adding a role when no prior roles have been defined results in the 
    creation of a new set and an update to the set with the role(s)
    """
    saz = simple_authz_info
    saz.add_role({'role1'})
    assert {'role1'} <= saz.roles 

def test_add_roles_with_init_roles(simple_authz_info, monkeypatch):
    """
    unit tested:  add_role

    test case:  
    adding roles when prior roles exists results in the 
    update to the set of roles with the new role(s)
    """
    saz = simple_authz_info
    monkeypatch.setattr(saz, 'roles', {'role1'})
    saz.add_role({'role2'})
    assert {'role1', 'role2'} <= saz.roles 

def test_add_string_permission_no_init_string_permission(simple_authz_info):
    """
    unit tested:

    test case:
    """
    saz = simple_authz_info
    saz.add_string_permission({'permission1'})
    assert {'permission1'} <= saz.string_permissions

def test_add_string_permissions_with_init_string_permission(
        simple_authz_info, monkeypatch):
    """
    unit tested:

    test case:
    """
    saz = simple_authz_info
    monkeypatch.setattr(saz, 'string_permissions', {'permission1'})
    saz.add_string_permission({'permission2'})
    assert {'permission1', 'permission2'} <= saz.string_permissions

def test_add_object_permission_no_init_object_permission(simple_authz_info):
    """
    unit tested:

    test case:
    """
    saz = simple_authz_info
    saz.add_object_permission({'permission1'})
    assert {'permission1'} <= saz.object_permissions

def test_add_object_permissions_with_init_object_permission(
        simple_authz_info, monkeypatch):
    """
    unit tested:

    test case:
    """
    saz = simple_authz_info
    monkeypatch.setattr(saz, 'object_permissions', {'permission1'})
    saz.add_object_permission({'permission2'})
    assert {'permission1', 'permission2'} <= saz.object_permissions


