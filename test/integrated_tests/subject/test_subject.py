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
        thedude_credentials, authz_info, thedude_testpermissions):

    tp = thedude_testpermissions

    new_subject.login(valid_username_password_token)

    results = new_subject.is_permitted(tp['perms'])
    assert results == tp['expected_results']

    new_subject.logout()

    with pytest.raises(IdentifiersNotSetException):
        new_subject.is_permitted(tp['perms'])


def test_authenticated_subject_is_permitted_collective(
        new_subject, valid_username_password_token,
        thedude_credentials, authz_info, thedude_testpermissions):

    tp = thedude_testpermissions

    new_subject.login(valid_username_password_token)

    assert ((new_subject.is_permitted_collective(tp['perms'], any) is True) and
            (new_subject.is_permitted_collective(tp['perms'], all) is False))

    new_subject.logout()

    with pytest.raises(IdentifiersNotSetException):
        new_subject.is_permitted_collective(tp['perms'], any)


def test_authenticated_subject_check_permission_succeeds(
        authz_info, thedude_testpermissions, new_subject,
        valid_username_password_token, thedude_credentials):

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
        permission_resolver, authz_info, thedude_testpermissions,
        new_subject, valid_username_password_token, thedude_credentials):

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

        new_subject.logout()

def test_has_role(valid_username_password_token, thedude_testroles,
                  new_subject, authz_info, thedude_credentials):

    tr = thedude_testroles
    event_detected = None

    def event_listener(event):
        nonlocal event_detected
        event_detected = event
    event_bus.register(event_listener, 'AUTHORIZATION.RESULTS')

    new_subject.login(valid_username_password_token)
    result = new_subject.has_role(tr['roles'])

    assert (tr['expected_results'] == result and
            event_detected.results == result)

    new_subject.logout()

def test_authenticated_subject_has_role_collective(
        authz_info, new_subject, thedude_testroles,
        valid_username_password_token, thedude_credentials):

    tr = thedude_testroles

    new_subject.login(valid_username_password_token)

    assert ((new_subject.has_role_collective(tr['roles'], all) is False) and
            (new_subject.has_role_collective(tr['roles'], any) is True))

    new_subject.logout()


def test_check_role_succeeds(
        authz_info, new_subject, thedude_testroles,
        valid_username_password_token, thedude_credentials):

    tr = thedude_testroles

    event_detected = None

    def event_listener(event):
        nonlocal event_detected
        event_detected = event
    event_bus.register(event_listener, 'AUTHORIZATION.GRANTED')

    new_subject.login(valid_username_password_token)
    assert (new_subject.check_role(tr['roles'], any) is None and
            event_detected.items == tr['roles'])

    new_subject.logout()


def test_check_role_raises(
        authz_info, new_subject, thedude_testroles,
        valid_username_password_token, thedude_credentials):

    tr = thedude_testroles

    event_detected = None

    def event_listener(event):
        nonlocal event_detected
        event_detected = event
    event_bus.register(event_listener, 'AUTHORIZATION.DENIED')

    new_subject.login(valid_username_password_token)
    with pytest.raises(UnauthorizedException):
        new_subject.check_role(tr['roles'], all)

        assert event_detected.items == tr['roles']

        new_subject.logout()


def test_run_as(new_subject, walter_identifier, jackie_identifier,
                jackie, walter, thedude_credentials, thedude, authz_info,
                jackie_testpermissions, walter_testpermissions,
                valid_username_password_token):

    jp = jackie_testpermissions
    wp = walter_testpermissions

    new_subject.login(valid_username_password_token)

    new_subject.run_as(jackie_identifier)
    jackieresults = new_subject.is_permitted(jp['perms'])
    assert jackieresults == jp['expected_results']

    new_subject.run_as(walter_identifier)
    walterresults = new_subject.is_permitted(wp['perms'])
    assert walterresults == wp['expected_results']

    new_subject.logout()


def test_session_logout_clears_cache(
    new_subject, thedude_credentials, thedude, authz_info, thedude_identifier,
        valid_username_password_token, thedude_testpermissions, capsys):

    tp = thedude_testpermissions

    new_subject.login(valid_username_password_token)  # caches credentials
    new_subject.is_permitted(tp['perms'])  # caches authz_info

    session = new_subject.get_session()
    session.stop()

    out, err = capsys.readouterr()
    
    assert ('Clearing cached credentials for [thedude]' in out and
            'Clearing cached authz_info for [thedude]' in out)
