import pytest
import collections
from unittest import mock

from yosai.core import (
    AccountStoreRealm,
    AuthorizationEventException,
    DefaultPermission,
    DefaultEventBus,
    IllegalStateException,
    IndexedAuthorizationInfo,
    IndexedPermissionVerifier,
    ModularRealmAuthorizer,
    PermissionIndexingException,
    PermissionResolver,
    SimpleRole,
    UnauthorizedException,
    Yosai,
)

from ..doubles import (
    MockSubject,
)
# -----------------------------------------------------------------------------
# ModularRealmAuthorizer Tests
# -----------------------------------------------------------------------------

def test_mra_realms_setter(
        modular_realm_authorizer_patched, default_accountstorerealm):
    """
    unit tested:  realms.setter

    test case:
    setting the realms attribute in turn calls two other methods
    """
    mra = modular_realm_authorizer_patched

    asr = default_accountstorerealm
    faux_realm = type('FauxRealm', (object,), {})
    test_realms = (asr, faux_realm)

    with mock.patch.object(ModularRealmAuthorizer,
                           'register_cache_clear_listener') as rccl:
        rccl.return_value = None

        mra.realms = test_realms

        rccl.assert_called_once_with()
        assert mra.realms == (asr,)


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

        with mock.patch.object(mra, 'notify_results') as mra_nr:
            mra_nr.return_value = None

            results = mra.is_permitted('identifiers', ['permission1', 'permission2'], False)

            mra_arc.assert_called_once_with()

            assert set(results) == set([('permission1', True), ('permission2', True)])


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

        results = mra.is_permitted('identifiers', {'permission1', 'permission2'}, False)

        mra_arc.assert_called_once_with()
        assert set(results) == set([('permission1', False), ('permission2', False)])


@pytest.mark.parametrize('mock_results, logical_operator, expected',
                         [({('permission1', True), ('permission2', True)}, all, True),
                          ({('permission1', True), ('permission2', False)}, all, False),
                          ({('permission1', False), ('permission2', False)}, all, False),
                          ({('permission1', True), ('permission2', True)}, any, True),
                          ({('permission1', True), ('permission2', False)}, any, True),
                          ({('permission1', False), ('permission2', False)}, any, False)])
def test_mra_is_permitted_collective(
        modular_realm_authorizer_patched, monkeypatch, mock_results,
        logical_operator, expected):
    """
    unit tested:  is_permitted_collective

    test case:
    a collection of permissions receives a single Boolean
    """
    mra = modular_realm_authorizer_patched
    monkeypatch.setattr(mra, 'is_permitted', lambda x,y,log_results: mock_results)
    with mock.patch.object(mra, 'assert_realms_configured') as mra_arc:
        mra_arc.return_value = None
        with mock.patch.object(mra, 'notify_success') as mra_ns:
            mra_ns.return_value = None
            with mock.patch.object(mra, 'notify_failure') as mra_nf:
                mra_nf.return_value = None

                results = mra.is_permitted_collective({'identifiers'},
                                                      ['perm1', 'perm2'],
                                                      logical_operator)
                mra_arc.assert_called_once_with()
                assert results == expected
                if expected is True:
                    mra_ns.assert_called_once_with({'identifiers'},
                                                   ['perm1', 'perm2'],
                                                   logical_operator)
                else:
                    mra_nf.assert_called_once_with({'identifiers'},
                                                   ['perm1', 'perm2'],
                                                   logical_operator)


def test_mra_check_permission_collection_raises(
        modular_realm_authorizer_patched, monkeypatch):
    """
    unit tested:  check_permission

    test case:
    check_permission raises an exception if any permission isn't entitled
    """
    mra = modular_realm_authorizer_patched
    monkeypatch.setattr(mra, 'is_permitted_collective', lambda x,y,z: False)
    with mock.patch.object(mra, 'assert_realms_configured') as mra_arc:
        mra_arc.return_value = None

        with pytest.raises(UnauthorizedException):
            mra.check_permission('arbitrary_identifiers', ['perm1', 'perm2'], all)
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
    monkeypatch.setattr(mra, 'is_permitted_collective', lambda x,y,z: True)

    with mock.patch.object(mra, 'assert_realms_configured') as mra_arc:
        mra_arc.return_value = None

        mra.check_permission('arbitrary_identifiers', ['perm1', 'perm2'], all)
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

        with mock.patch.object(mra, 'notify_results') as mra_nr:
            mra_nr.return_value = None

            results = mra.has_role('identifiers', {'roleid1', 'roleid2'})

            mra_arc.assert_called_once_with()

            assert set(results) == set([('roleid1', True), ('roleid2', True)])


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

        with mock.patch.object(mra, 'notify_results') as mock_nr:
            mock_nr.return_value = None

            results = mra.has_role('identifiers', {'roleid1', 'roleid2'})

            mra_arc.assert_called_once_with()
            assert set(results) == set([('roleid1', False), ('roleid2', False)])


@pytest.mark.parametrize('param1, param2, logical_operator, expected',
                         [({('roleid1', False)}, {('roleid2', True)}, all, False),
                          ({('roleid1', True)}, {('roleid2', True)}, all, True),
                          ({('roleid1', True)}, {('roleid2', False)}, all, False),
                          ({('roleid1', False)}, {('roleid2', True)}, any, True),
                          ({('roleid1', True)}, {('roleid2', True)}, any, True),
                          ({('roleid1', True)}, {('roleid2', False)}, any, True)])
def test_mra_has_role_collective(
        modular_realm_authorizer_patched, monkeypatch, param1, param2,
        logical_operator, expected):
    """
    unit tested:  has_role_collective

    test case:
    a collection of roleids receives a single Boolean
    """
    mra = modular_realm_authorizer_patched

    monkeypatch.setattr(mra.realms[0], 'has_role', lambda x, y: param1)
    monkeypatch.setattr(mra.realms[1], 'has_role', lambda x, y: param1)
    monkeypatch.setattr(mra.realms[2], 'has_role', lambda x, y: param2)

    with mock.patch.object(ModularRealmAuthorizer, 'assert_realms_configured') as arc:
        arc.return_value = None

        with mock.patch.object(mra, 'notify_success') as mra_ns:
            mra_ns.return_value = None
            with mock.patch.object(mra, 'notify_failure') as mra_nf:
                mra_nf.return_value = None

                result = mra.has_role_collective('arbitrary_identifiers',
                                                 {'roleid1', 'roleid2'},
                                                 logical_operator)

                if expected is True:
                    mra_ns.assert_called_once_with('arbitrary_identifiers',
                                                   {'roleid1', 'roleid2'},
                                                   logical_operator)
                else:
                    mra_nf.assert_called_once_with('arbitrary_identifiers',
                                                   {'roleid1', 'roleid2'},
                                                   logical_operator)

                assert result == expected and arc.called


def test_mra_check_role_raises(
        modular_realm_authorizer_patched, monkeypatch):
    """
    unit tested:  check_role

    test case:
    check_role raises an exception if any permission isn't entitled,
    and nothing returned if success
    """
    mra = modular_realm_authorizer_patched
    monkeypatch.setattr(mra, 'has_role_collective', lambda x,y,z: False)
    with mock.patch.object(ModularRealmAuthorizer, 'assert_realms_configured') as arc:
        arc.return_value = None
        with pytest.raises(UnauthorizedException):
            mra.check_role('arbitrary_identifiers', ['roleid1', 'roleid2'], all)

            arc.assert_called_once_with()


def test_mra_check_role_true(
        modular_realm_authorizer_patched, monkeypatch):
    """
    unit tested:  check_role

    test case:
    check_role raises an exception if any permission isn't entitled,
    and nothing returned if success
    """

    mra = modular_realm_authorizer_patched
    monkeypatch.setattr(mra, 'has_role_collective', lambda x,y,z: True)
    with mock.patch.object(ModularRealmAuthorizer, 'assert_realms_configured') as arc:
        arc.return_value = None

        mra.check_role('identifiers', 'roleid_s', all)
        arc.assert_called_once_with()


def test_mraa_session_clears_cache(
        modular_realm_authorizer_patched, simple_identifier_collection,
        full_mock_account, monkeypatch, default_accountstorerealm):
    sic = simple_identifier_collection
    mra = modular_realm_authorizer_patched
    monkeypatch.setattr(mra, '_realms', (default_accountstorerealm,))

    session_tuple = collections.namedtuple(
        'session_tuple', ['identifiers', 'session_key'])
    st = session_tuple(sic, 'sessionkey123')

    with mock.patch.object(AccountStoreRealm, 'clear_cached_authorization_info') as ccc:
        ccc.return_value = None

        mra.session_clears_cache(items=st)

        ccc.assert_called_once_with(sic.from_source('AccountStoreRealm'))


def test_mraa_authc_clears_cache(
        modular_realm_authorizer_patched, simple_identifier_collection,
        full_mock_account, monkeypatch, default_accountstorerealm):
    sic = simple_identifier_collection
    mra = modular_realm_authorizer_patched
    monkeypatch.setattr(mra, '_realms', (default_accountstorerealm,))

    with mock.patch.object(AccountStoreRealm, 'clear_cached_authorization_info') as ccc:
        ccc.return_value = None

        mra.authc_clears_cache(identifiers=sic)

        ccc.assert_called_once_with(sic.from_source('AccountStoreRealm'))


def test_mra_register_cache_clear_listener(modular_realm_authorizer_patched, event_bus):
    mra = modular_realm_authorizer_patched

    with mock.patch.object(event_bus, 'register') as eb_r:
        eb_r.return_value = None
        with mock.patch.object(event_bus, 'is_registered') as eb_ir:
            eb_ir.return_value = None

            mra.register_cache_clear_listener()

            calls = [mock.call(mra.session_clears_cache, 'SESSION.STOP'),
                     mock.call(mra.session_clears_cache, 'SESSION.EXPIRE'),
                     mock.call(mra.authc_clears_cache, 'AUTHENTICATION.SUCCEEDED')]

            eb_r.assert_has_calls(calls)
            eb_ir.assert_has_calls(calls)


def test_mra_notify_results(modular_realm_authorizer_patched):
    """
    unit tested:  notify_results

    test case:
    creates an Event and publishes it to the event_bus
    """
    mra = modular_realm_authorizer_patched
    items = [('permission1', True)]

    topic = 'AUTHORIZATION.RESULTS'

    with mock.patch.object(DefaultEventBus, 'publish') as eb_pub:
        eb_pub.return_value = None

        mra.notify_results('identifiers', items)

        assert eb_pub.call_args == mock.call(topic, identifiers='identifiers',
                                             items=items)


def test_mra_notify_results_raises(
        modular_realm_authorizer_patched, monkeypatch):
    """
    unit tested:  notify_results

    test case:
    creates an Event, tries publishes it to the event_bus,
    but fails and so raises an exception
    """
    mra = modular_realm_authorizer_patched
    monkeypatch.setattr(mra, '_event_bus', None)

    with pytest.raises(AuthorizationEventException):
        mra.notify_results('identifiers', 'result')


def test_mra_notify_success(modular_realm_authorizer_patched):
    """
    unit tested:  notify_success

    test case:
    creates an Event and publishes it to the event_bus
    """
    mra = modular_realm_authorizer_patched
    permission_s = ['domain1:action1']

    topic = 'AUTHORIZATION.GRANTED'

    with mock.patch.object(DefaultEventBus, 'publish') as eb_pub:
        eb_pub.return_value = None

        mra.notify_success('identifiers', permission_s, any)

        assert eb_pub.call_args == mock.call(topic,
                                             identifiers='identifiers',
                                             items=permission_s,
                                             logical_operator=any)


def test_mra_notify_success_raises(
        modular_realm_authorizer_patched, monkeypatch):
    """
    unit tested:  notify_success

    test case:
    creates an Event, tries publishes it to the event_bus,
    but fails and so raises an exception
    """
    mra = modular_realm_authorizer_patched
    monkeypatch.setattr(mra, '_event_bus', None)

    with pytest.raises(AuthorizationEventException):
        mra.notify_success('identifiers', 'result', any)


def test_mra_notify_failure(modular_realm_authorizer_patched):
    """
    unit tested:  notify_failure

    test case:
    creates an Event and publishes it to the event_bus
    """
    mra = modular_realm_authorizer_patched
    permission_s = ['domain1:action1']

    topic = 'AUTHORIZATION.DENIED'

    with mock.patch.object(DefaultEventBus, 'publish') as eb_pub:
        eb_pub.return_value = None

        mra.notify_failure('identifiers', permission_s, any)

        assert eb_pub.call_args == mock.call(topic,
                                             identifiers='identifiers',
                                             items=permission_s,
                                             logical_operator=any)


def test_mra_notify_failure_raises(
        modular_realm_authorizer_patched, monkeypatch):
    """
    unit tested:  notify_failure

    test case:
    creates an Event, tries publishes it to the event_bus,
    but fails and so raises an exception
    """
    mra = modular_realm_authorizer_patched
    monkeypatch.setattr(mra, '_event_bus', None)

    with pytest.raises(AuthorizationEventException):
        mra.notify_failure('identifiers', 'result', any)


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
    roles = {SimpleRole('roleA'),
             SimpleRole('roleB')}
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
    testrole = SimpleRole('role1')
    assert psr == testrole

def test_simple_role_not_equals_other(populated_simple_role):
    psr = populated_simple_role
    testrole = SimpleRole('role2')
    assert psr != testrole


# -----------------------------------------------------------------------------
# IndexedPermissionVerifier Tests
# -----------------------------------------------------------------------------

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

    result = list(ipv.is_permitted('authz_info', [perm1, perm2]))

    assert result == [(perm1, True), (perm2, True)]

# -----------------------------------------------------------------------------
# SimpleRoleVerifier Tests
# -----------------------------------------------------------------------------

def test_srv_has_role(simple_role_verifier, indexed_authz_info):
    """
    unit tested:  has_role

    test case:
    for each role requested, yield whether has role
    """
    srv = simple_role_verifier
    test_roleids = {'role1', 'role10'}

    result = list(srv.has_role(indexed_authz_info, test_roleids))
    assert set(result) == set([('role1', True), ('role10', False)])
