import pytest
from unittest import mock

from yosai import (
    IllegalArgumentException,
    IllegalStateException,
    ModularRealmAuthorizer,
    OrderedSet,
    SimpleRole,
    UnauthorizedException,
    WildcardPermission,
    WildcardPermissionResolver,
)

from .doubles import (
    MockPermission,
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

def test_mra_private_has_role_true(modular_realm_authorizer_ftf):
    """
    unit tested:  _has_role

    test case:  
    a realm confirming role assignment (a principal is assigned a role)
    """
    mra = modular_realm_authorizer_ftf
    result = mra._has_role('arbitrary_principals', 'arbitrary_roleid')
    assert result is True

def test_mra_private_has_role_false(modular_realm_authorizer_fff):
    """
    unit tested:  _has_role

    test case:  
    a realm denies role affiliation 
    """
    mra = modular_realm_authorizer_fff
    result = mra._has_role('arbitrary_principals', 'arbitrary_roleid')
    assert result is False 

def test_mra_private_role_collection_yields(modular_realm_authorizer_ftf):
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

def test_mra_private_is_permitted_true(modular_realm_authorizer_ftf):
    """
    unit tested:  _is_permitted

    test case:  
    a realm confirming privilege (a principal IS granted permission)
    """
    mra = modular_realm_authorizer_ftf
    result = mra._is_permitted('arbitrary_principals', 'permission')
    assert result is True

def test_mra_private_is_permitted_false(modular_realm_authorizer_fff):
    """
    unit tested:  _is_permitted

    test case:  
    permission is denied
    """
    mra = modular_realm_authorizer_fff
    result = mra._is_permitted('arbitrary_principals', 'permission')
    assert result is False 

def test_mra_private_permit_collection_yields(modular_realm_authorizer_fff):
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

def test_mra_is_permitted_collection_returns_falsefalsefalse(
        modular_realm_authorizer_fff):
    """
    unit tested:  is_permitted

    when passed a list of permissions, returns a list of Tuples
    """
    mra = modular_realm_authorizer_fff
    result = mra.is_permitted('arbitrary', ['perm1', 'perm2', 'perm3'])
    assert all(x in result for x in [('perm1', False), ('perm2', False),
                                     ('perm3', False)])
    
def test_mra_is_permitted_single_permission_returns_true(
        modular_realm_authorizer_ftf):
    """
    unit tested:  is_permitted

    test case:  
    a single permission argument receives a single Boolean response 
    """
    mra = modular_realm_authorizer_ftf
    result = mra.is_permitted('arbitrary_principals', 'permission')
    assert result[0][1] == True

def test_mra_is_permitted_single_permission_returns_false(
        modular_realm_authorizer_fff):
    """
    unit tested:  is_permitted

    test case:  
    a single permission argument receives a single Boolean response 
    """
    mra = modular_realm_authorizer_fff
    result = mra.is_permitted('arbitrary_principals', 'permission')
    assert result[0][1] == False 

def test_mra_is_permitted_all_collection_false(modular_realm_authorizer_fff):
    """
    unit tested:  is_permitted_all
    
    test case:  
    a collection of permissions receives a single Boolean
    """
    mra = modular_realm_authorizer_fff
    result = mra.is_permitted_all('arbitrary_principals', 
                                  ['perm1', 'perm2', 'perm3'])
    assert result is False 

def test_mra_is_permitted_all_collection_true(
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

def test_mra_is_permitted_all_single_true(modular_realm_authorizer_ftf):
    """
    unit tested:  is_permitted_all

    test case:  
    a single permission receives a single Boolean
    """
    mra = modular_realm_authorizer_ftf
    result = mra.is_permitted_all('arbitrary_principals', 'perm1')
    assert result is True 

def test_mra_is_permitted_all_single_false(modular_realm_authorizer_fff):
    """
    unit tested:  is_permitted_all

    test case:  
    a single permission receives a single Boolean
    """
    mra = modular_realm_authorizer_fff
    result = mra.is_permitted_all('arbitrary_principals', 'perm1')
    assert result is False 

def test_mra_check_permission_collection_raises(modular_realm_authorizer_fff):
    """
    unit tested:  check_permission

    test case:
    check_permission raises an exception if any permission isn't entitled
    """
    mra = modular_realm_authorizer_fff
    with pytest.raises(UnauthorizedException):
        mra.check_permission('arbitrary_principals', ['perm1', 'perm2'])

def test_mra_check_permission_collection_succeeds(modular_realm_authorizer_ftf):
    """
    unit tested:  check_permission

    test case:
    check_permission raises an exception if any permission isn't entitled,
    and nothing returned if success 
    """
    mra = modular_realm_authorizer_ftf
    result = mra.check_permission('arbitrary_principals', ['perm1', 'perm2'])
    assert result is None

def test_mra_has_role_collection_returns_truetruetrue(
        modular_realm_authorizer_ftf):
    """
    unit tested:  has_role 
        
    when passed a list of roleids, returns a list of Tuples
    """
    mra = modular_realm_authorizer_ftf
    result = mra.has_role('arbitrary', ['roleid1', 'roleid2', 'roleid3'])
    assert all(x in result for x in [('roleid1', True), ('roleid2', True),
                                     ('roleid3', True)])
    
def test_mra_has_role_single_role_returns_true(modular_realm_authorizer_ftf):
    """
    unit tested:  has_role 

    test case:  
    when passed a single roleid, returns a list containing one Tuple
    """
    mra = modular_realm_authorizer_ftf
    result = mra.has_role('arbitrary_principals', 'roleid1')
    assert result[0][1] == True

def test_mra_has_role_single_role_returns_false(modular_realm_authorizer_fff):
    """
    unit tested:  has_role 

    test case:  
    when passed a single roleid, returns a list containing one Tuple
    """
    mra = modular_realm_authorizer_fff
    result = mra.has_role('arbitrary_principals', 'roleid1')
    assert result[0][1] == False 

def test_mra_has_all_roles_collection_false(
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

def test_mra_has_all_roles_collection_true(modular_realm_authorizer_ftf):
    """
    unit tested:  has_all_roles

    test case:  
    a collection of roleids receives a single Boolean
    """
    mra = modular_realm_authorizer_ftf
    result = mra.has_all_roles('arbitrary_principals', 
                               ['roleid1', 'roleid2', 'roleid3'])
    assert result is True 

def test_mra_has_all_roles_single_true(modular_realm_authorizer_ftf):
    """
    unit tested:  has_all_roles

    test case:  
    a single permission receives a single Boolean
    """
    mra = modular_realm_authorizer_ftf
    result = mra.is_permitted_all('arbitrary_principals', 'roleid1')
    assert result is True 

def test_mra_has_all_roles_single_false(modular_realm_authorizer_fff):
    """
    unit tested:  has_all_roles
    
    test case:  
    a single permission receives a single Boolean
    """
    mra = modular_realm_authorizer_fff
    result = mra.has_all_roles('arbitrary_principals', 'roleid1')
    assert result is False 

def test_mra_check_role_collection_false(modular_realm_authorizer_fff):
    """
    unit tested:  check_role 

    test case:
    check_role raises an exception if any permission isn't entitled,
    and nothing returned if success 
    """
    mra = modular_realm_authorizer_fff
    with pytest.raises(UnauthorizedException):
        mra.check_role('arbitrary_principals', ['roleid1', 'roleid2'])

def test_mra_check_role_collection_true(modular_realm_authorizer_ftf):
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
def test_sa_add_role_no_init_roles(simple_authz_info):
    """
    unit tested:  add_role

    test case:  
    adding a role when no prior roles have been defined results in the 
    creation of a new set and an update to the set with the role(s)
    """
    saz = simple_authz_info
    saz.add_role({'role1'})
    assert OrderedSet(['role1']) <= saz.roles 

def test_sa_add_roles_with_init_roles(simple_authz_info, monkeypatch):
    """
    unit tested:  add_role

    test case:  
    adding roles when prior roles exists results in the 
    update to the set of roles with the new role(s)
    """
    saz = simple_authz_info
    monkeypatch.setattr(saz, 'roles', {'role1'})
    saz.add_role({'role2'})
    assert OrderedSet(['role1', 'role2']) <= saz.roles 

def test_sa_add_string_permission_no_init_string_permission(simple_authz_info):
    """
    unit tested:  add_string_permission

    test case:
    """
    saz = simple_authz_info
    saz.add_string_permission({'permission1'})
    assert OrderedSet(['permission1']) <= saz.string_permissions

def test_sa_add_string_permissions_with_init_string_permission(
        simple_authz_info, monkeypatch):
    """
    unit tested:  add_string_permission

    test case:
    """
    saz = simple_authz_info
    monkeypatch.setattr(saz, 'string_permissions', {'permission1'})
    saz.add_string_permission({'permission2'})
    assert OrderedSet(['permission1', 'permission2']) <= saz.string_permissions

def test_sa_add_object_permission_no_init_object_permission(simple_authz_info):
    """
    unit tested:  add_object_permission

    test case:
    """
    saz = simple_authz_info
    saz.add_object_permission({'permission1'})
    assert OrderedSet(['permission1']) <= saz.object_permissions

def test_sa_add_object_permissions_with_init_object_permission(
        simple_authz_info, monkeypatch):
    """
    unit tested:  add_object_permission

    test case:
    """
    saz = simple_authz_info
    monkeypatch.setattr(saz, 'object_permissions', {'permission1'})
    saz.add_object_permission({'permission2'})
    assert OrderedSet(['permission1', 'permission2']) <= saz.object_permissions


# -----------------------------------------------------------------------------
# SimpleRole Tests
# -----------------------------------------------------------------------------
def test_simple_role_add_with_existing_permissions(populated_simple_role):
    """
    unit tested:  add

    test case:
    adding to an existing permissions attribute
    """
    psr = populated_simple_role
    psr.add('permissionZ')
    assert 'permissionZ' in psr.permissions

def test_simple_role_add_without_existing_permissions(
        populated_simple_role, monkeypatch):
    """
    unit tested:  add

    test case:
    creates a new permissions attribute, adds to it
    """
    psr = populated_simple_role
    monkeypatch.setattr(psr, 'permissions', None)
    psr.add('permissionX')
    assert 'permissionX' in psr.permissions

def test_simple_role_add_all_with_existing_permissions(populated_simple_role):
    """
    unit tested:  add_all

    test case:
    adding to an existing permissions attribute
    """
    psr = populated_simple_role
    test_set = OrderedSet(['permission4', 'permission5', 'permission6'])
    psr.add_all(test_set)
    assert all(x in psr.permissions for x in test_set)

def test_simple_role_add_all_without_existing_permissions(
        populated_simple_role, monkeypatch):
    """
    unit tested:  add_all

    test case:
    creates a new permissions attribute, adds to it
    """
    psr = populated_simple_role
    monkeypatch.setattr(psr, 'permissions', None)
    test_set = OrderedSet(['permission4', 'permission5', 'permission6'])
    psr.add_all(test_set)
    assert all(x in psr.permissions for x in test_set)

def test_simple_role_is_permitted_with_existing_permissions(
        populated_simple_role):
    """
    unit tested:  is_permitted

    test case:
    a Permission that implies another returns True

    there is one permission in the sample set that always returns True
    """
    psr = populated_simple_role
    new_permission = MockPermission(True)
    assert psr.is_permitted(new_permission)

def test_simple_role_is_NOT_permitted_with_existing_permissions(
        populated_simple_role, monkeypatch):
    """
    unit tested:  is_permitted

    test case:
    when no permissions assigned to the role imply the permission of interest
    """
    psr = populated_simple_role
    existing_permissions = OrderedSet([MockPermission(False),
                                       MockPermission(False)])
    monkeypatch.setattr(psr, 'permissions', existing_permissions)
    new_permission = MockPermission(True)
    assert psr.is_permitted(new_permission) is False

def test_simple_role_is_permitted_without_existing_permissions(
        populated_simple_role, monkeypatch):
    """
    unit tested:  is_permitted

    test case:
    when no permissions reside in the role, returns False 
    """
    psr = populated_simple_role
    monkeypatch.setattr(psr, 'permissions', None)
    new_permission = MockPermission(True)
    assert psr.is_permitted(new_permission) is False

def test_simple_role_hash_code_with_name(populated_simple_role):
    psr = populated_simple_role
    assert id(psr.name) == psr.hash_code()

def test_simple_role_hash_code_without_name(
        populated_simple_role, monkeypatch):
    psr = populated_simple_role
    monkeypatch.setattr(psr, 'name', None)
    assert psr.hash_code() == 0

def test_simple_role_equals_other(populated_simple_role):
    psr = populated_simple_role
    name = 'SimpleRole123'
    permissions = OrderedSet([MockPermission(False), 
                              MockPermission(False),
                              MockPermission(True)])
    testrole = SimpleRole(name=name, permissions=permissions)

    assert psr == testrole

def test_simple_role_not_equals_other(populated_simple_role):
    psr = populated_simple_role
    name = 'SimpleRole1234567'
    permissions = OrderedSet([MockPermission(False), 
                              MockPermission(False),
                              MockPermission(True)])
    testrole = SimpleRole(name=name, permissions=permissions)

    assert psr != testrole

# -----------------------------------------------------------------------------
# WildcardPermission Tests
# -----------------------------------------------------------------------------

def test_wcp_init_with_wildcard_string(monkeypatch):
    """
    unit tested:  __init__

    test case:
    control flow depending on whether a wildcard_string is passed
    """
    with mock.patch.object(WildcardPermission, 'set_parts') as wp_sp:
        wp_sp.return_value = None 
        wcs = WildcardPermission(wildcard_string='DOMAIN:ACTION:INSTANCE')
        assert wcs.set_parts.called

def test_wcp_init_without_wildcard_string(monkeypatch):
    """
    unit tested:  __init__

    test case:
    control flow depending on whether a wildcard_string is passed
    """
    with mock.patch.object(WildcardPermission, 'set_parts') as wp_sp:
        wp_sp.return_value = None 
        wcs = WildcardPermission()
        assert not wcs.set_parts.called

@pytest.mark.parametrize("wildcardstring", [None, '', "  ", ":::", "A:,,:C:D"])
def test_wcp_set_parts_raises_illegalargumentexception(
        default_wildcard_permission, wildcardstring):
    """
    unit tested:  set_parts

    test case:
    wilcard_string must be populated with parts, else an exception raises
    """

    wcp = default_wildcard_permission

    with pytest.raises(IllegalArgumentException):
        wcp.set_parts(wildcard_string=wildcardstring)

def test_wcp_set_parts_casesensitive(
        default_wildcard_permission, monkeypatch):
    """
    unit tested:  set_parts

    test case:
    case_sensitive parts remain as-is
    """
    wcp = default_wildcard_permission
    monkeypatch.setattr(wcp, 'case_sensitive', True)
    wildcardstring = "One,Two,Three:Four,Five,Six:Seven,Eight"
    wcp.set_parts(wildcard_string=wildcardstring)
    expected_parts = [OrderedSet(['One', 'Two', 'Three']),
                      OrderedSet(['Four', 'Five', 'Six']),
                      OrderedSet(['Seven', 'Eight'])]
    assert expected_parts == wcp.parts

def test_wcp_set_parts(default_wildcard_permission, monkeypatch):
    """
    unit tested:  set_parts

    test case:
    verify normal, successful activity
    """
    wcp = default_wildcard_permission
    monkeypatch.setattr(wcp, 'case_sensitive', True)
    wildcardstring = "one,two,three:four,five,six:seven,eight"
    wcp.set_parts(wildcard_string=wildcardstring)
    expected_parts = [OrderedSet(['one', 'two', 'three']),
                      OrderedSet(['four', 'five', 'six']),
                      OrderedSet(['seven', 'eight'])]
    assert expected_parts == wcp.parts

def test_wcp_implies_nonwildcardpermission(default_wildcard_permission):
    """
    unit tested:  implies

    test case:
    implies currently only supports instances of WildcardPermission
    """
    wcp = default_wildcard_permission
    otherpermission = type('OtherPermission', (object,), {})
    result = wcp.implies(otherpermission())
    assert result is False 

@pytest.mark.parametrize("wildcardstring1,wildcardstring2",
                         [("something", "SOMETHING"),
                          ("SOMETHING", "something"),
                          ("something", "something")]) 
def test_wcp_implies_caseinsensitive_returns_true(
        wildcardstring1, wildcardstring2):
    """
    unit tested:  implies

    test case:
    Case insensitive, single-name permission, returns True
    """
    p1 = WildcardPermission(wildcardstring1)
    p2 = WildcardPermission(wildcardstring2)
    assert p1.implies(p2)

@pytest.mark.parametrize("wildcardstring1,wildcardstring2",
                         [("something", "SOMETHINGELSEENTIRELY"),
                          ("SOMETHINGELSE", "somethingAGAIN")])
def test_wcp_implies_caseinsensitive_returns_false(
        wildcardstring1, wildcardstring2):
    """
    unit tested:  implies

    test case:
    Case insensitive, single-name permission, returns False 
    """
    p1 = WildcardPermission(wildcardstring1)
    p2 = WildcardPermission(wildcardstring2)
    assert not p1.implies(p2)

@pytest.mark.parametrize("wildcardstring1,wildcardstring2",
                         [("something", "something")]) 
def test_wcp_implies_casesensitive_returns_true(
        wildcardstring1, wildcardstring2):
    """
    unit tested:  implies

    test case:
    Case sensitive, single-name permission,returns True
    """
    p1 = WildcardPermission(wildcard_string=wildcardstring1, 
                            case_sensitive=True)
    p2 = WildcardPermission(wildcard_string=wildcardstring2,
                            case_sensitive=True)
    assert p1.implies(p2)

@pytest.mark.parametrize("wildcardstring1,wildcardstring2",
                         [("Something", "someThing"),
                          ("diFFerent", "reallyDifferent")]) 
def test_wcp_implies_casesensitive_returns_false(
        wildcardstring1, wildcardstring2):
    """
    unit tested:  implies

    test case:
    Case sensitive, single-name permission, returns False 
    """
    p1 = WildcardPermission(wildcard_string=wildcardstring1, 
                            case_sensitive=True)
    p2 = WildcardPermission(wildcard_string=wildcardstring2,
                            case_sensitive=True)
    assert not p1.implies(p2)

@pytest.mark.parametrize("wildcardstring1,wildcardstring2",
                         [("one,two", "one"),
                          ("one,two,three", "one,three"),
                          ("one,two:one,two,three", "one:three"),
                          ("one,two:one,two,three", "one:two,three"),
                          ("one:two,three", "one:three"),
                          ("one,two,three:one,two,three:one,two", 
                           "one:three:two"),
                          ("one", "one:two,three,four"),
                          ("one", "one:two,three,four:five:six:seven"),
                          ("one:two,three,four",
                           "one:two,three,four:five:six:seven")])
def test_wcp_implies_caseinsensitive_lists(
        wildcardstring1, wildcardstring2):
    """
    unit tested:  implies

    test case:
    Case insensitive, list-based permission, retrns True and the opposite False
    """

    p1 = WildcardPermission(wildcard_string=wildcardstring1) 
    p2 = WildcardPermission(wildcard_string=wildcardstring2)
    
    assert p1.implies(p2) and not p2.implies(p1)


@pytest.mark.parametrize("wildcardstring1,wildcardstring2",
                         [("*", "one"),
                          ("*", "one:two"),
                          ("*", "one,two:three,four"),
                          ("*", "one,two:three,four,five:six:seven,eight"),
                          ("newsletter:*", "newsletter:read"),
                          ("newsletter:*", "newsletter:read,write"),
                          ("newsletter:*", "newsletter:*"),
                          ("newsletter:*", "newsletter:*:*"),
                          ("newsletter:*", "newsletter:*:read"),
                          ("newsletter:*", "newsletter:write:*"),
                          ("newsletter:*", "newsletter:read,write:*"),
                          ("newsletter:*:*", "newsletter:read"),
                          ("newsletter:*:*", "newsletter:read,write"),
                          ("newsletter:*:*", "newsletter:*"),
                          ("newsletter:*:*", "newsletter:*:*"),
                          ("newsletter:*:*", "newsletter:*:read"),
                          ("newsletter:*:*", "newsletter:write:*"),
                          ("newsletter:*:*", "newsletter:read,write:*"),
                          ("newsletter:*:*:*", "newsletter:read"),
                          ("newsletter:*:*:*", "newsletter:read,write"),
                          ("newsletter:*:*:*", "newsletter:*"),
                          ("newsletter:*:*:*", "newsletter:*:*"),
                          ("newsletter:*:*:*", "newsletter:*:read"),
                          ("newsletter:*:*:*", "newsletter:write:*"),
                          ("newsletter:*:*:*", "newsletter:read,write:*"),
                          ("newsletter:*:read", "newsletter:123:read"),
                          ("newsletter:*:read", "newsletter:123:read:write"),
                          ("newsletter:*:read:*", "newsletter:123:read"),
                          ("newsletter:*:read:*", "newsletter:123:read:write")])
def test_wcp_implies_caseinsensitive_wildcards_true(
        wildcardstring1, wildcardstring2):
    """
    unit tested:  implies

    test case:
    Case insensitive, wildcard-based permission, retrns True
    """
    p1 = WildcardPermission(wildcard_string=wildcardstring1) 
    p2 = WildcardPermission(wildcard_string=wildcardstring2)
    
    assert p1.implies(p2)


@pytest.mark.parametrize("wildcardstring1,wildcardstring2",
                         [("newsletter:*:read", "newsletter:123,456:read,write"),
                          ("newsletter:*:read", "newsletter:read"),
                          ("newsletter:*:read", "newsletter:read,write")])
def test_wcp_implies_caseinsensitive_wildcards_false(
        wildcardstring1, wildcardstring2):
    """
    unit tested:  implies

    test case:
    Case insensitive, wildcard-based permission, retrns False 
    """
    p1 = WildcardPermission(wildcard_string=wildcardstring1) 
    p2 = WildcardPermission(wildcard_string=wildcardstring2)
    
    assert not p1.implies(p2)

def test_wcp_equals():
    wildcard_string = 'somestring'
    p1 = WildcardPermission(wildcard_string)
    p2 = WildcardPermission(wildcard_string)

    assert p1 == p2

def test_wcp_not_equals_bad_type():
    wildcard_string = 'somestring'
    p1 = WildcardPermission(wildcard_string)
    othertype = type('OtherPermissionType', (object,), {})
    p2 = othertype()

    assert not p1 == p2


# -----------------------------------------------------------------------------
# WildcardPermissionResolver Tests
# -----------------------------------------------------------------------------
def test_wcpr_returns_wcp():
    wcp = WildcardPermissionResolver.resolve_permission('testing123')
    assert isinstance(wcp, WildcardPermission)

