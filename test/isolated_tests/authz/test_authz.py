import pytest
import collections
from unittest import mock

from yosai import (
    DefaultPermission,
    DefaultPermissionResolver,
    IllegalArgumentException,
    IllegalStateException,
    IndexedAuthorizationInfo,
    IndexedPermissionVerifier,
    ModularRealmAuthorizer,
    PermissionIndexingException,
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

def test_mra_realms_setter(modular_realm_authorizer_patched):
    """
    unit tested:  realms.setter

    test case:
    setting the realms attribute in turn calls two other methods
    """
    mra = modular_realm_authorizer_patched
    with mock.patch.object(mra, 'apply_permission_resolver_to_realms') as aprtr:
        aprtr.return_value = False
        mra.realms = 'something'
        assert aprtr.called

def test_mra_authorizing_realms(modular_realm_authorizer_patched):
    """
    unit tested:  authorizing_realms

    test case:
    verify that only realms that implement IAuthorizer are returned in
    the generator expression

    3 out of 5 of the mock realms in authz_realms_collection_fff implement IAuthorizer
    """
    mra = modular_realm_authorizer_patched

    result = list(mra.authorizing_realms)  # wrap the generator in a list
    assert len(result) == 3


def test_mra_pr_setter_succeeds(modular_realm_authorizer_patched):
    """
    unit tested:  permission_resolver.setter

    test case:
    the property setter assigns the attribute and then calls the apply.. method
    """

    mra = modular_realm_authorizer_patched

    with mock.patch.object(ModularRealmAuthorizer,
                           'apply_permission_resolver_to_realms') as apr:
        apr.return_value = None
        mra.permission_resolver = 'arbitrary value'
        assert apr.called

def test_mra_aprtr_succeeds(modular_realm_authorizer_patched, monkeypatch):
    """
    unit tested:  apply_permission_resolver_to_realms

    test case:
    to apply a permission resolver to realms, both the resolver and realms
    attributes must be set in the ModularRealmAuthorizer and the realm
    must implement the IPermissionResolverAware interface--  3 out of 5 realms
    in realms_collection do
    """
    mra = modular_realm_authorizer_patched

    # testing only checks that the attributes are set, not what they are set to
    monkeypatch.setattr(mra, '_permission_resolver', 'arbitrary value')

    # no permission_resolver exists in each realm until this method is called:
    mra.apply_permission_resolver_to_realms()

    configured_realms =\
        [realm for realm in mra.realms
         if (getattr(realm, '_permission_resolver', None) == 'arbitrary value')]

    print('realms is:', mra.realms)
    assert len(configured_realms) == 3

def test_mra_aprtr_fails(modular_realm_authorizer_patched):
    """
    unit tested:  apply_permission_resolver_to_realms

    test case:
    to apply a permission resolver to realms, both the resolver and realms
    attributes must be set in the ModularRealmAuthorizer and the realm
    must implement the IPermissionResolverAware interface

    """
    mra = modular_realm_authorizer_patched
    # not setting the resolver, so to exercise failed code path

    configured_realms =\
        [realm for realm in mra.realms
         if (getattr(realm, '_permission_resolver', None) == 'arbitrary_value')]

    assert len(configured_realms) == 0

def test_mra_assert_realms_configured_success(modular_realm_authorizer_patched):
    """
    unit tested:  assert_realms_configured

    test case: if the realms attribute isn't set, an exception raises
    """
    mra = modular_realm_authorizer_patched
    assert mra.assert_realms_configured() is None

def test_mra_assert_realms_configured_fail(
        modular_realm_authorizer_patched, monkeypatch):
    """
    unit tested:  assert_realms_configured

    test case:  if the realms attribute isn't set, an exception raises
    """
    mra = modular_realm_authorizer_patched
    monkeypatch.setattr(mra, '_realms', None)
    with pytest.raises(IllegalStateException):
        mra.assert_realms_configured()

def test_mra_private_has_role_true_and_false(
        modular_realm_authorizer_patched, monkeypatch):
    """
    unit tested:  _has_role

    test case:
    confirms that _has_role iterates over the authorizing realms and yields
    a value from each realm consisting of a tuple(roleid, Boolean)
    """
    mra = modular_realm_authorizer_patched

    def has_role_yields_true(identifiers, roleid_s):
        for x in roleid_s:
            yield (x, True)

    def has_role_yields_false(identifiers, roleid_s):
        for x in roleid_s:
            yield (x, False)

    # there are three realms set for this fixture:
    monkeypatch.setattr(mra.realms[0], 'has_role', has_role_yields_false)
    monkeypatch.setattr(mra.realms[1], 'has_role', has_role_yields_false)
    monkeypatch.setattr(mra.realms[2], 'has_role', has_role_yields_true)

    result = {(roleid, hasrole) for roleid, hasrole in
              mra._has_role('identifiers', {'roleid123'})}
    assert result == {('roleid123', False), ('roleid123', True)}


def test_mra_private_is_permitted_true_and_false(
        modular_realm_authorizer_patched, monkeypatch):
    """
    unit tested:  _is_permitted

    test case:
    confirms that _is_permitted iterates over the authorizing realms and yields
    a value from each realm consisting of a tuple(Permission, Boolean)
    """
    mra = modular_realm_authorizer_patched

    def is_permitted_yields_true(identifiers, permission_s):
        for x in permission_s:
            yield (x, True)

    def is_permitted_yields_false(identifiers, permission_s):
        for x in permission_s:
            yield (x, False)

    # there are three realms set for this fixture:
    monkeypatch.setattr(mra.realms[0], 'is_permitted', is_permitted_yields_false)
    monkeypatch.setattr(mra.realms[1], 'is_permitted', is_permitted_yields_false)
    monkeypatch.setattr(mra.realms[2], 'is_permitted', is_permitted_yields_true)

    result = {(permission, ispermitted) for permission, ispermitted in
              mra._is_permitted('identifiers', {'permission1'})}
    assert result == {('permission1', False), ('permission1', True)}

def test_mra_is_permitted_succeeds(modular_realm_authorizer_patched, monkeypatch):
    """
    unit tested:  is_permitted

    test case:
    - for each permission passed, passes the permission to the private _is_permitted
      method
    - every authorizing realms is consulted for each permission and only one realm needs
      to return true in order for the permission to be granted
    """
    mra = modular_realm_authorizer_patched

    def is_permitted_yields_true(identifiers, permission_s):
        for x in permission_s:
            yield (x, True)

    def is_permitted_yields_false(identifiers, permission_s):
        for x in permission_s:
            yield (x, False)

    # there are three realms set for this fixture:
    monkeypatch.setattr(mra.realms[0], 'is_permitted', is_permitted_yields_false)
    monkeypatch.setattr(mra.realms[1], 'is_permitted', is_permitted_yields_false)
    monkeypatch.setattr(mra.realms[2], 'is_permitted', is_permitted_yields_true)

    with mock.patch.object(mra, 'assert_realms_configured') as mra_arc:
        mra_arc.return_value = None

        results = mra.is_permitted('identifiers', {'permission1', 'permission2'})

        mra_arc.assert_called_once_with()
        assert results == frozenset([('permission1', True), ('permission2', True)])


def test_mra_is_permitted_fails(modular_realm_authorizer_patched, monkeypatch):
    """
    unit tested:  is_permitted

    test case:
    - for each permission passed, passes the permission to the private _is_permitted
      method
    - every authorizing realms is consulted for each permission and only one realm needs
      to return true in order for the permission to be granted
    """
    mra = modular_realm_authorizer_patched

    def is_permitted_yields_false(identifiers, permission_s):
        for x in permission_s:
            yield (x, False)

    # there are three realms set for this fixture:
    monkeypatch.setattr(mra.realms[0], 'is_permitted', is_permitted_yields_false)
    monkeypatch.setattr(mra.realms[1], 'is_permitted', is_permitted_yields_false)
    monkeypatch.setattr(mra.realms[2], 'is_permitted', is_permitted_yields_false)

    with mock.patch.object(mra, 'assert_realms_configured') as mra_arc:
        mra_arc.return_value = None

        results = mra.is_permitted('identifiers', {'permission1', 'permission2'})

        mra_arc.assert_called_once_with()
        assert results == frozenset([('permission1', False), ('permission2', False)])


@pytest.mark.parametrize('mock_results, expected',
                         [({('permission1', True), ('permission2', True)}, True),
                          ({('permission1', True), ('permission2', False)}, False),
                          ({('permission1', False), ('permission2', False)}, False)])
def test_mra_is_permitted_all(
        modular_realm_authorizer_patched, monkeypatch, mock_results, expected):
    """
    unit tested:  is_permitted_all

    test case:
    a collection of permissions receives a single Boolean
    """
    mra = modular_realm_authorizer_patched
    monkeypatch.setattr(mra, 'is_permitted', lambda x,y: mock_results)
    with mock.patch.object(mra, 'assert_realms_configured') as mra_arc:
        mra_arc.return_value = None
        results = mra.is_permitted_all({'identifiers'}, ['perm1', 'perm2'])
        mra_arc.assert_called_once_with()
        assert results == expected

def test_mra_check_permission_collection_raises(
        modular_realm_authorizer_patched, monkeypatch):
    """
    unit tested:  check_permission

    test case:
    check_permission raises an exception if any permission isn't entitled
    """
    mra = modular_realm_authorizer_patched
    monkeypatch.setattr(mra, 'is_permitted_all', lambda x,y: False)
    with mock.patch.object(mra, 'assert_realms_configured') as mra_arc:
        mra_arc.return_value = None

        with pytest.raises(UnauthorizedException):
            mra.check_permission('arbitrary_identifiers', ['perm1', 'perm2'])
            mra_arc.assert_called_once_with()

def test_mra_check_permission_collection_succeeds(
        modular_realm_authorizer_patched, monkeypatch):
    """
    unit tested:  check_permission

    test case:
    check_permission raises an exception if any permission isn't entitled,
    and nothing returned if success
    """
    mra = modular_realm_authorizer_patched
    monkeypatch.setattr(mra, 'is_permitted_all', lambda x,y: True)

    with mock.patch.object(mra, 'assert_realms_configured') as mra_arc:
        mra_arc.return_value = None

        mra.check_permission('arbitrary_identifiers', ['perm1', 'perm2'])
        mra_arc.assert_called_once_with()


def test_mra_has_role_succeeds(modular_realm_authorizer_patched, monkeypatch):
    """
    unit tested:  has_role

    test case:
    - for each roleid passed, passes the roleid to the private _has_role
      method
    - every authorizing realm is consulted for each roleid and only one realm needs
      to return true in order for the has_role request to be granted
    """
    mra = modular_realm_authorizer_patched

    def has_role_yields_true(identifiers, roleid_s):
        for x in roleid_s:
            yield (x, True)

    def has_role_yields_false(identifiers, roleid_s):
        for x in roleid_s:
            yield (x, False)

    # there are three realms set for this fixture:
    monkeypatch.setattr(mra.realms[0], 'has_role', has_role_yields_false)
    monkeypatch.setattr(mra.realms[1], 'has_role', has_role_yields_false)
    monkeypatch.setattr(mra.realms[2], 'has_role', has_role_yields_true)

    with mock.patch.object(mra, 'assert_realms_configured') as mra_arc:
        mra_arc.return_value = None

        results = mra.has_role('identifiers', {'roleid1', 'roleid2'})

        mra_arc.assert_called_once_with()
        assert results == frozenset([('roleid1', True), ('roleid2', True)])


def test_mra_has_role_fails(modular_realm_authorizer_patched, monkeypatch):
    """
    unit tested:  has_role

    test case:
    - for each roleid passed, passes the roleid to the private _has_role
      method
    - every authorizing realm is consulted for each roleid and only one realm needs
      to return true in order for the has_role request to be granted
    """
    mra = modular_realm_authorizer_patched

    def has_role_yields_false(identifiers, roleid_s):
        for x in roleid_s:
            yield (x, False)

    # there are three realms set for this fixture:
    monkeypatch.setattr(mra.realms[0], 'has_role', has_role_yields_false)
    monkeypatch.setattr(mra.realms[1], 'has_role', has_role_yields_false)
    monkeypatch.setattr(mra.realms[2], 'has_role', has_role_yields_false)

    with mock.patch.object(mra, 'assert_realms_configured') as mra_arc:
        mra_arc.return_value = None

        results = mra.has_role('identifiers', {'roleid1', 'roleid2'})

        mra_arc.assert_called_once_with()
        assert results == frozenset([('roleid1', False), ('roleid2', False)])


@pytest.mark.parametrize('param1, param2, expected',
                         [(False, True, True),
                          (True, True, True),
                          (True, False, True)])
def test_mra_has_all_roles(
        modular_realm_authorizer_patched, monkeypatch, param1, param2, expected):
    """
    unit tested:  has_all_roles

    test case:
    a collection of roleids receives a single Boolean
    """
    mra = modular_realm_authorizer_patched

    monkeypatch.setattr(mra.realms[0], 'has_all_roles', lambda x, y: param1)
    monkeypatch.setattr(mra.realms[1], 'has_all_roles', lambda x, y: param1)
    monkeypatch.setattr(mra.realms[2], 'has_all_roles', lambda x, y: param2)

    with mock.patch.object(ModularRealmAuthorizer, 'assert_realms_configured') as arc:
        arc.return_value = None
        result = mra.has_all_roles('arbitrary_identifiers', {'roleid1', 'roleid2'})

        arc.assert_called_once_with()
        assert result == expected


def test_mra_check_role_collection_raises(
        modular_realm_authorizer_patched, monkeypatch):
    """
    unit tested:  check_role

    test case:
    check_role raises an exception if any permission isn't entitled,
    and nothing returned if success
    """
    mra = modular_realm_authorizer_patched
    monkeypatch.setattr(mra, 'has_all_roles', lambda x,y: None)
    with mock.patch.object(ModularRealmAuthorizer, 'assert_realms_configured') as arc:
        arc.return_value = None
        with pytest.raises(UnauthorizedException):
            mra.check_role('arbitrary_identifiers', ['roleid1', 'roleid2'])

            arc.assert_called_once_with()

def test_mra_check_role_collection_true(
        modular_realm_authorizer_patched, monkeypatch):
    """
    unit tested:  check_role

    test case:
    check_role raises an exception if any permission isn't entitled,
    and nothing returned if success
    """

    mra = modular_realm_authorizer_patched
    monkeypatch.setattr(mra, 'has_all_roles', lambda x,y: {'role1'})
    with mock.patch.object(ModularRealmAuthorizer, 'assert_realms_configured') as arc:
        arc.return_value = None

        mra.check_role('identifiers', 'roleid_s')
        arc.assert_called_once_with()

# -----------------------------------------------------------------------------
# IndexedAuthorizationInfo Tests
# -----------------------------------------------------------------------------

def test_iai_roleids_isset(indexed_authz_info, monkeypatch):
    """
    unit tested:  roleids.getter

    test case:
    roleids is a property that returns a set of the role identifiers from each
    role in roles
    """
    info = indexed_authz_info
    results = info.roleids
    assert results == {'role1', 'role2', 'role3'}


def test_iai_permissions_isset(
        indexed_authz_info, monkeypatch, permission_collection):
    """
    unit tested:  permissions (property)

    test case:
    permissions returns a complete set of every indexed Permission
    """
    info = indexed_authz_info
    assert info.permissions == permission_collection


def test_iai_permissions_setter(indexed_authz_info):
    """
    unit tested:  permissions.setter

    test case:
    clears the existing permissions index and then indexes the new set of perms
    """
    info = indexed_authz_info
    with mock.patch.object(IndexedAuthorizationInfo, 'index_permission') as ip:
        ip.return_value = None

        testperm = DefaultPermission('domain1:action1')
        info.permissions = {testperm}
        ip.assert_called_once_with({testperm})

        # _permissions will be empty since index_permission was mocked
        assert not info._permissions


def test_iai_add_role(indexed_authz_info):
    """
    unit tested:  add_role

    test case:
    updates the set, roles, with the new role(s)
    """
    info = indexed_authz_info
    roles = {SimpleRole(role_identifier='roleA'),
             SimpleRole(role_identifier='roleB')}
    info.add_role(roles)
    assert roles <= info.roles

def test_iai_add_permission(indexed_authz_info, test_permission_collection):
    """
    unit tested:  add_permission

    test case:
    adds new permission(s) to the index
    """
    info = indexed_authz_info
    tpc = test_permission_collection

    with mock.patch.object(IndexedAuthorizationInfo, 'index_permission') as ip:
        ip.return_value = None

        info.add_permission(tpc)

        ip.assert_called_once_with(tpc)


def test_iai_index_permission(indexed_authz_info, test_permission_collection):
    """
    unit tested:  index_permission

    test case:
    permissions are indexed by domain and then the indexing is validated
    """
    info = indexed_authz_info
    tpc = test_permission_collection

    with mock.patch.object(IndexedAuthorizationInfo,
                           'assert_permissions_indexed') as api:
        api.return_value = None

        info.index_permission(permission_s=tpc)

        api.assert_called_once_with(tpc)

        for permission in tpc:
            domain = next(iter(permission.domain))
            assert {permission} <= info._permissions[domain]


@pytest.mark.parametrize('domain, expected',
                         [('domain1', {DefaultPermission('domain1:action1')}),
                          ('domainQ', set())])
def test_iai_get_permission(indexed_authz_info, domain, expected):
    """
    unit tested:  get_permission

    test case:
    returns the permissions for a specified domain or an empty set if there arent
    any

                           {DefaultPermission('domain4:action1,action2'),
                            DefaultPermission('domain4:action3:target1')}),
    """
    info = indexed_authz_info

    result = info.get_permission(domain)
    assert result == expected

def test_iai_assert_permissions_indexed_raises(
        indexed_authz_info, test_permission_collection):
    """
    unit tested: assert_permissions_indexed_raises

    test case:
    when permissions expected to be indexed aren't, an exception is raised
    """
    info = indexed_authz_info
    with pytest.raises(PermissionIndexingException):
        info.assert_permissions_indexed(test_permission_collection)

def test_iai_length(indexed_authz_info, permission_collection, role_collection):
    """
    unit tested:  __len__

    test case:
    an IndexedAuthorizationInfo object's length is measured by its number of
    roles and permissions collected, and therefore an empty one is such that
    it has no roles nor permissions assigned
    """
    info = indexed_authz_info
    assert len(info) == len(permission_collection) + len(role_collection)
    info._permissions.clear()
    assert len(info) == len(role_collection)
    info._roles = set()
    assert len(info) == 0

# -----------------------------------------------------------------------------
# SimpleRole Tests
# -----------------------------------------------------------------------------

def test_simple_role_equals_other(populated_simple_role):
    psr = populated_simple_role
    testrole = SimpleRole(role_identifier='role1')
    assert psr == testrole

def test_simple_role_not_equals_other(populated_simple_role):
    psr = populated_simple_role
    testrole = SimpleRole(role_identifier='role2')
    assert psr != testrole


# -----------------------------------------------------------------------------
# IndexedPermissionVerifier Tests
# -----------------------------------------------------------------------------

def test_ipv_resolve_permission_strings(
        indexed_permission_verifier, monkeypatch):
    """
    unit tested:  resolve permission

    test case:
    - a list of string-formatted permissions is passed in as an argument
    - strings are converted to permission objects
    - a set of permission objects is returned
    """
    ipv = indexed_permission_verifier
    ipv.permission_resolver = DefaultPermissionResolver()

    permstring1 = 'domain1:action1'
    permstring2 = 'domain2:action1,action2'
    permstring3 = 'domain3:*:*'
    result = ipv.resolve_permission([permstring1, permstring2, permstring3])
    assert result == {DefaultPermission(wildcard_string=permstring1),
                      DefaultPermission(wildcard_string=permstring2),
                      DefaultPermission(wildcard_string=permstring3)}

def test_ipv_resolve_permission_strings_raises_wo_resolver(
        indexed_permission_verifier, monkeypatch, capsys):
    """
    unit tested:  resolve permission

    test case:
    when the resolver isn't set, a warning is logged and empty set returned
    """
    ipv = indexed_permission_verifier

    result = ipv.resolve_permission(['domain1:action1'])
    out, err = capsys.readouterr()
    assert 'Permission Resolver is not set' in out and result == set()

def test_ipv_resolve_permission_permissionobjects(
        indexed_permission_verifier, monkeypatch):
    """
    unit tested:  resolve permission

    test case:
    when a collection of permission objects is passed as an argument, they
    are returned immediately
    """
    ipv = indexed_permission_verifier
    ipv.permission_resolver = DefaultPermissionResolver()

    permstring1 = 'domain1:action1'
    permstring2 = 'domain2:action1,action2'
    permstring3 = 'domain3:*:*'
    perms = [DefaultPermission(wildcard_string=permstring1),
             DefaultPermission(wildcard_string=permstring2),
             DefaultPermission(wildcard_string=permstring3)]

    result = ipv.resolve_permission(perms)
    assert result == perms

def test_ipv_get_authzd_permissions(
        indexed_permission_verifier, monkeypatch, indexed_authz_info):
    """
    unit tested:  get_authzd_permissions

    test case:
    returns the permissions from the authzinfo that are relevant to the
    permission argument
    """
    ipv = indexed_permission_verifier
    perm = DefaultPermission('domain4:action4')

    domainperms = frozenset([DefaultPermission(domain={'domain4'},
                                               action={'action1', 'action2'}),
                             DefaultPermission(domain={'domain4'},
                                               action={'action3'},
                                               target={'target1'})])

    monkeypatch.setattr(indexed_authz_info, 'get_permission',
                        lambda x: domainperms)

    result = ipv.get_authzd_permissions(indexed_authz_info, perm)

    assert domainperms == result


def test_ipv_is_permitted(
        indexed_permission_verifier, monkeypatch, indexed_authz_info):
    """
    unit tested:  get_authzd_permissions

    test case:
    - gets authorized permissions based on the requested permission
    - for each permission requested, confirm whether the related authorized
      permissions implies permission
    - yield the results as a tuple
    """
    ipv = indexed_permission_verifier

    dp1 = DefaultPermission('domain6:action1')
    monkeypatch.setattr(dp1, 'implies', lambda x: False)
    dp2 = DefaultPermission('domain7:action1')
    monkeypatch.setattr(dp2, 'implies', lambda x: True)
    authz_perms = frozenset([dp1, dp2])
    monkeypatch.setattr(ipv, 'get_authzd_permissions', lambda x,y: authz_perms)

    perm1 = DefaultPermission('domain1:action1')
    perm2 = DefaultPermission('domain2:action1')

    with mock.patch.object(IndexedPermissionVerifier,
                           'resolve_permission') as ipv_rp:
        ipv_rp.return_value = [perm1, perm2]

        result = list(ipv.is_permitted('authz_info', [perm1, perm2]))

        ipv_rp.assert_called_once_with([perm1, perm2])
        assert result == [(perm1, True), (perm2, True)]

# -----------------------------------------------------------------------------
# SimpleRoleVerifier Tests
# -----------------------------------------------------------------------------
