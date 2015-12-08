from yosai.core import (
    UnauthorizedException,
    event_bus,
)
import pytest


def test_is_permitted(permission_resolver, modular_realm_authorizer,
                      thedude_authz_info):
    """
    get a frozenset of tuple(s), containing the Permission and a Boolean
    indicating whether the permission is granted
    """
    mra = modular_realm_authorizer
    perm1 = permission_resolver('money:write:bankcheck_19911109069')
    perm2 = permission_resolver('money:withdrawal')
    perm3 = permission_resolver('leatherduffelbag:transport:theringer')
    perm4 = permission_resolver('leatherduffelbag:access:theringer')

    perms = [perm1, perm2, perm3, perm4]

    expected_results = frozenset([(perm1, True), (perm2, False),
                                  (perm3, True), (perm4, False)])

    event_detected = None

    def event_listener(event):
        nonlocal event_detected
        event_detected = event
    event_bus.register(event_listener, 'AUTHORIZATION.RESULTS')

    results = mra.is_permitted('thedude', perms)
    assert (expected_results == results and
            event_detected.results == results)


def test_is_permitted_collective(
        permission_resolver, modular_realm_authorizer, thedude_authz_info):

    mra = modular_realm_authorizer
    perm1 = permission_resolver('money:write:bankcheck_19911109069')
    perm2 = permission_resolver('money:withdrawal')
    perm3 = permission_resolver('leatherduffelbag:transport:theringer')
    perm4 = permission_resolver('leatherduffelbag:access:theringer')

    perms = [perm1, perm2, perm3, perm4]

    assert ((mra.is_permitted_collective('thedude', perms, any) is True) and
            (mra.is_permitted_collective('thedude', perms, all) is False))


def test_check_permission_succeeds(
        permission_resolver, modular_realm_authorizer, thedude_authz_info):

    mra = modular_realm_authorizer
    perm1 = permission_resolver('money:write:bankcheck_19911109069')
    perm2 = permission_resolver('money:withdrawal')
    perm3 = permission_resolver('leatherduffelbag:transport:theringer')
    perm4 = permission_resolver('leatherduffelbag:access:theringer')

    perms = [perm1, perm2, perm3, perm4]

    event_detected = None

    def event_listener(event):
        nonlocal event_detected
        event_detected = event
    event_bus.register(event_listener, 'AUTHORIZATION.GRANTED')

    assert (mra.check_permission('thedude', perms, any) is None and
            event_detected.items == perms)


def test_check_permission_raises(
        permission_resolver, modular_realm_authorizer, thedude_authz_info):

    mra = modular_realm_authorizer
    perm1 = permission_resolver('money:write:bankcheck_19911109069')
    perm2 = permission_resolver('money:withdrawal')
    perm3 = permission_resolver('leatherduffelbag:transport:theringer')
    perm4 = permission_resolver('leatherduffelbag:access:theringer')

    perms = [perm1, perm2, perm3, perm4]

    event_detected = None

    def event_listener(event):
        nonlocal event_detected
        event_detected = event
    event_bus.register(event_listener, 'AUTHORIZATION.DENIED')

    with pytest.raises(UnauthorizedException):
        mra.check_permission('thedude', perms, all)
        assert event_detected.items == perms


def test_has_role(modular_realm_authorizer):

    mra = modular_realm_authorizer

    roles = {'bankcustomer', 'courier', 'thief'}

    expected_results = frozenset([('bankcustomer', True),
                                  ('courier', True),
                                  ('thief', False)])

    event_detected = None

    def event_listener(event):
        nonlocal event_detected
        event_detected = event
    event_bus.register(event_listener, 'AUTHORIZATION.RESULTS')

    result = mra.has_role('thedude', roles)

    assert (expected_results == result and
            event_detected.results == result)

def test_has_role_collective(modular_realm_authorizer):

    mra = modular_realm_authorizer

    roles = {'bankcustomer', 'courier', 'thief'}

    assert ((mra.has_role_collective('thedude', roles, all) is False) and
            (mra.has_role_collective('thedude', roles, any) is True))


def test_check_role_succeeds(modular_realm_authorizer):

    mra = modular_realm_authorizer
    roles = {'bankcustomer', 'courier', 'thief'}

    event_detected = None

    def event_listener(event):
        nonlocal event_detected
        event_detected = event
    event_bus.register(event_listener, 'AUTHORIZATION.GRANTED')

    assert (mra.check_role('thedude', roles, any) is None and
            event_detected.items == roles)


def test_check_role_raises(modular_realm_authorizer):

    mra = modular_realm_authorizer
    roles = {'bankcustomer', 'courier', 'thief'}

    event_detected = None

    def event_listener(event):
        nonlocal event_detected
        event_detected = event
    event_bus.register(event_listener, 'AUTHORIZATION.DENIED')

    with pytest.raises(UnauthorizedException):
        mra.check_role('thedude', roles, all)

        assert event_detected.items == roles
