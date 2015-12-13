import pytest
from yosai.core import (
    AuthenticationException,
    IdentifiersNotSetException,
    UnauthorizedException,
    UnauthenticatedException,
    event_bus,
)


def test_subject_invalid_login(new_subject, invalid_username_password_token,
                               thedude, thedude_credentials):
    with pytest.raises(AuthenticationException):
        new_subject.login(invalid_username_password_token)


def test_authenticated_subject_session_attribute_logout(
        new_subject, valid_username_password_token, thedude, thedude_credentials):

    new_subject.login(valid_username_password_token)
    session = new_subject.get_session()
    session.set_attribute('name', 'nametest')
    session.set_attribute('unknown', 'unknown')
    assert (session.get_attribute('name') == 'nametest' and
            session.get_attribute('unknown') is None)
    new_subject.logout()


def test_authenticated_subject_is_permitted(
        new_subject, valid_username_password_token,
        thedude_credentials, thedude_authz_info, thedude_testpermissions):

    tp = thedude_testpermissions

    new_subject.login(valid_username_password_token)

    results = new_subject.is_permitted(tp['perms'])
    assert results == tp['expected_results']

    new_subject.logout()

    with pytest.raises(IdentifiersNotSetException):
        new_subject.is_permitted(tp['perms'])


def test_authenticated_subject_is_permitted_collective(
        new_subject, valid_username_password_token,
        thedude_credentials, thedude_authz_info, thedude_testpermissions):

    tp = thedude_testpermissions

    new_subject.login(valid_username_password_token)

    assert ((new_subject.is_permitted_collective(tp['perms'], any) is True) and
            (new_subject.is_permitted_collective(tp['perms'], all) is False))

    new_subject.logout()

    with pytest.raises(IdentifiersNotSetException):
        new_subject.is_permitted_collective(tp['perms'], any)


def test_authenticated_subject_check_permission_succeeds(
        thedude_authz_info, thedude_testpermissions, new_subject,
        valid_username_password_token):

    tp = thedude_testpermissions
    event_detected = None

    def event_listener(event):
        nonlocal event_detected
        event_detected = event
    event_bus.register(event_listener, 'AUTHORIZATION.GRANTED')

    new_subject.login(valid_username_password_token)

    check = new_subject.check_permission(tp['perms'], any)
    assert (check is None and event_detected.items == tp['perms'])

    new_subject.logout()

    with pytest.raises(UnauthenticatedException):
        new_subject.check_permission(tp['perms'], any)


def test_check_permission_raises(
        permission_resolver, thedude_authz_info, thedude_testpermissions,
        new_subject, valid_username_password_token):

    tp = thedude_testpermissions

    event_detected = None

    def event_listener(event):
        nonlocal event_detected
        event_detected = event
    event_bus.register(event_listener, 'AUTHORIZATION.DENIED')

    new_subject.login(valid_username_password_token)

    with pytest.raises(UnauthorizedException):
        new_subject.check_permission(tp['perms'], all)
        assert event_detected.items == tp['perms']


def test_has_role(valid_username_password_token, thedude_permissions,
    new_subject):

    roles = {'bankcustomer', 'courier', 'thief'}

    expected_results = frozenset([('bankcustomer', True),
                                  ('courier', True),
                                  ('thief', False)])

    event_detected = None

    def event_listener(event):
        nonlocal event_detected
        event_detected = event
    event_bus.register(event_listener, 'AUTHORIZATION.RESULTS')

    result = mra.has_role(thedude_identifier, roles)

    assert (expected_results == result and
            event_detected.results == result)
