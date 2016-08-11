import pytest
from yosai.core import (
    AuthenticationException,
    ExpiredSessionException,
    IdentifiersNotSetException,
    IllegalStateException,
    UnauthorizedException,
    UnauthenticatedException,
    UnknownSessionException,
    event_bus,
)
import datetime


def test_subject_invalid_login(new_web_subject, invalid_username_password_token,
                               thedude, thedude_credentials):
    with pytest.raises(AuthenticationException):
        new_web_subject.login(invalid_username_password_token)


def test_authenticated_subject_session_attribute_logout(
        new_web_subject, valid_username_password_token, thedude, thedude_credentials):

    new_web_subject.login(valid_username_password_token)
    session = new_web_subject.get_session()
    session.set_attribute('name', 'nametest')
    session.set_attribute('unknown', 'unknown')
    assert (session.get_attribute('name') == 'nametest' and
            session.get_attribute('unknown') is None)
    new_web_subject.logout()


def test_authenticated_subject_is_permitted(
        new_web_subject, valid_username_password_token,
        thedude_credentials, authz_info, thedude_testpermissions):

    tp = thedude_testpermissions

    new_web_subject.login(valid_username_password_token)

    results = new_web_subject.is_permitted(tp['perms'])
    assert results == tp['expected_results']

    new_web_subject.logout()

    with pytest.raises(IdentifiersNotSetException):
        new_web_subject.is_permitted(tp['perms'])


def test_authenticated_subject_is_permitted_collective(
        new_web_subject, valid_username_password_token,
        thedude_credentials, authz_info, thedude_testpermissions):

    tp = thedude_testpermissions

    new_web_subject.login(valid_username_password_token)

    assert ((new_web_subject.is_permitted_collective(tp['perms'], any) is True) and
            (new_web_subject.is_permitted_collective(tp['perms'], all) is False))

    new_web_subject.logout()

    with pytest.raises(IdentifiersNotSetException):
        new_web_subject.is_permitted_collective(tp['perms'], any)


def test_authenticated_subject_check_permission_succeeds(
        authz_info, thedude_testpermissions, new_web_subject,
        valid_username_password_token, thedude_credentials):

    tp = thedude_testpermissions
    event_detected = None

    def event_listener(identifiers=None, items=None, logical_operator=None):
        nonlocal event_detected
        event_detected = items
    event_bus.register(event_listener, 'AUTHORIZATION.GRANTED')

    new_web_subject.login(valid_username_password_token)

    check = new_web_subject.check_permission(tp['perms'], any)
    assert (check is None and event_detected == tp['perms'])

    new_web_subject.logout()

    with pytest.raises(UnauthenticatedException):
        new_web_subject.check_permission(tp['perms'], any)


def test_check_permission_raises(
        permission_resolver, authz_info, thedude_testpermissions,
        new_web_subject, valid_username_password_token, thedude_credentials):

    tp = thedude_testpermissions

    event_detected = None

    def event_listener(identifiers=None, items=None, logical_operator=None):
        nonlocal event_detected
        event_detected = items
    event_bus.register(event_listener, 'AUTHORIZATION.DENIED')

    new_web_subject.login(valid_username_password_token)

    with pytest.raises(UnauthorizedException):
        new_web_subject.check_permission(tp['perms'], all)
        assert event_detected == tp['perms']

        new_web_subject.logout()


def test_has_role(valid_username_password_token, thedude_testroles,
                  new_web_subject, authz_info, thedude_credentials):

    tr = thedude_testroles
    event_detected = None

    def event_listener(identifiers=None, items=None):
        nonlocal event_detected
        event_detected = items
    event_bus.register(event_listener, 'AUTHORIZATION.RESULTS')

    new_web_subject.login(valid_username_password_token)
    result = new_web_subject.has_role(tr['roles'])

    assert (tr['expected_results'] == result and
            frozenset(event_detected) == result)

    new_web_subject.logout()


def test_authenticated_subject_has_role_collective(
        authz_info, new_web_subject, thedude_testroles,
        valid_username_password_token, thedude_credentials):

    tr = thedude_testroles

    new_web_subject.login(valid_username_password_token)

    assert ((new_web_subject.has_role_collective(tr['roles'], all) is False) and
            (new_web_subject.has_role_collective(tr['roles'], any) is True))

    new_web_subject.logout()


def test_check_role_succeeds(
        authz_info, new_web_subject, thedude_testroles,
        valid_username_password_token, thedude_credentials):

    tr = thedude_testroles

    event_detected = None

    def event_listener(identifiers=None, items=None, logical_operator=None):
        nonlocal event_detected
        event_detected = items
    event_bus.register(event_listener, 'AUTHORIZATION.GRANTED')

    new_web_subject.login(valid_username_password_token)
    assert (new_web_subject.check_role(tr['roles'], any) is None and
            event_detected == tr['roles'])

    new_web_subject.logout()


def test_check_role_raises(
        authz_info, new_web_subject, thedude_testroles,
        valid_username_password_token, thedude_credentials):

    tr = thedude_testroles

    event_detected = None

    def event_listener(identifiers=None, items=None, logical_operator=None):
        nonlocal event_detected
        event_detected = items
    event_bus.register(event_listener, 'AUTHORIZATION.DENIED')

    new_web_subject.login(valid_username_password_token)
    with pytest.raises(UnauthorizedException):
        new_web_subject.check_role(tr['roles'], all)

        assert event_detected == tr['roles']
        new_web_subject.logout()


def test_run_as_raises(new_web_subject, walter, walter_identifier):
    # a login is required , so this should raise:
    new_web_subject.logout()
    with pytest.raises(IllegalStateException):
        new_web_subject.run_as(walter_identifier)


def test_run_as_pop(new_web_subject, walter_identifier, jackie_identifier,
                    jackie, walter, thedude_credentials, thedude, authz_info,
                    jackie_testpermissions, walter_testpermissions,
                    valid_username_password_token):

    jp = jackie_testpermissions
    wp = walter_testpermissions

    new_web_subject.login(valid_username_password_token)

    new_web_subject.run_as(jackie_identifier)
    jackieresults = new_web_subject.is_permitted(jp['perms'])
    assert jackieresults == jp['expected_results']

    new_web_subject.run_as(walter_identifier)
    walterresults = new_web_subject.is_permitted(wp['perms'])
    assert walterresults == wp['expected_results']

    new_web_subject.pop_identity()
    assert new_web_subject.identifiers == jackie_identifier

    new_web_subject.logout()


def test_logout_clears_cache(
    new_web_subject, thedude_credentials, thedude, authz_info, thedude_identifier,
        valid_username_password_token, thedude_testpermissions, caplog):

    tp = thedude_testpermissions

    new_web_subject.login(valid_username_password_token)  # caches credentials
    new_web_subject.is_permitted(tp['perms'])  # caches authz_info

    new_web_subject.logout()

    out = caplog.text

    assert ('Clearing cached credentials for [thedude]' in out and
            'Clearing cached authz_info for [thedude]' in out)


def test_session_stop_clears_cache(
    new_web_subject, thedude_credentials, thedude, authz_info, thedude_identifier,
        valid_username_password_token, thedude_testpermissions, caplog):

    tp = thedude_testpermissions

    new_web_subject.login(valid_username_password_token)  # caches credentials
    new_web_subject.is_permitted(tp['perms'])  # caches authz_info

    session = new_web_subject.get_session()
    session.stop(None)

    out = caplog.text

    assert ('Clearing cached credentials for [thedude]' in out and
            'Clearing cached authz_info for [thedude]' in out)


def test_login_clears_cache(
    new_web_subject, thedude_credentials, thedude, authz_info, thedude_identifier,
        valid_username_password_token, caplog):

    new_web_subject.login(valid_username_password_token)  # caches credentials

    out = caplog.text

    assert 'Clearing cached authz_info for [thedude]' in out
    new_web_subject.logout()


def test_session_idle_expiration_clears_cache(
    new_web_subject, thedude_credentials, thedude, authz_info, thedude_identifier,
        valid_username_password_token, thedude_testpermissions, caplog,
        cache_handler):

    tp = thedude_testpermissions

    new_web_subject.login(valid_username_password_token)  # caches credentials
    new_web_subject.is_permitted(tp['perms'])  # caches authz_info

    session = new_web_subject.get_session()
    session = cache_handler.get('session', identifier=session.session_id)

    twenty_ago = datetime.timedelta(minutes=30)
    session.last_access_time = session.last_access_time - twenty_ago
    cache_handler.set('session', session.session_id, session)
    session = cache_handler.get('session', identifier=session.session_id)

    session = new_web_subject.get_session()

    with pytest.raises(ExpiredSessionException):
        session.last_access_time  # this triggers the expiration

        out = caplot.text
        assert ('Clearing cached credentials for [thedude]' in out and
                'Clearing cached authz_info for [thedude]' in out)

        new_web_subject.logout()


def test_absolute_expired_session(
        new_web_subject, valid_username_password_token,
        thedude_credentials, authz_info, thedude_testpermissions,
        cache_handler):

    tp = thedude_testpermissions

    new_web_subject.login(valid_username_password_token)
    session = new_web_subject.get_session()
    results = new_web_subject.is_permitted(tp['perms'])
    assert results == tp['expected_results']

    # when time has reached the TTL, the cache entry is removed:
    cache_handler.delete('session', identifier=session.session_id)

    with pytest.raises(UnknownSessionException):
        new_web_subject.is_permitted(tp['perms'])
        new_web_subject.logout()


def test_requires_permission_succeeds(
        configured_securityutils, authz_info, new_web_subject,
        valid_username_password_token, thedude_credentials):

    status = None

    @requires_permission(['money:write:bankcheck_19911109069'])
    def do_something():
        nonlocal status
        status = True

    yosai = configured_securityutils

    with yosai:
        new_web_subject.login(valid_username_password_token)
        do_something()
        new_web_subject.logout()
        assert status


def test_requires_permission_fails(
        configured_securityutils, authz_info,
        valid_username_password_token, thedude_credentials):

    status = None

    @requires_permission(['money:write:bankcheck_12345'])
    def do_something():
        nonlocal status
        status = True

    yosai = configured_securityutils

    with yosai:
        new_web_subject = yosai.subject
        new_web_subject.login(valid_username_password_token)
        try:
            do_something()
        except UnauthorizedException:
            assert status is None
            new_web_subject.logout()
        else:
            raise Exception('failed to raise')

def test_requires_dynamic_permission_succeeds(
        configured_securityutils, authz_info,
        valid_username_password_token, thedude_credentials):

    class BankCheck:
        def __init__(self):
            self.bankcheck_id = 'bankcheck_19911109069'

    status = None

    @requires_dynamic_permission(['money:write:{bankcheck.bankcheck_id}'])
    def do_something(bankcheck):
        nonlocal status
        status = True

    yosai = configured_securityutils

    with yosai:
        new_web_subject = yosai.subject
        new_web_subject.login(valid_username_password_token)
        do_something(bankcheck=BankCheck())
        new_web_subject.logout()
        assert status


def test_requires_dynamic_permission_fails(
        configured_securityutils, authz_info,
        valid_username_password_token, thedude_credentials):

    class BankCheck:
        def __init__(self):
            self.bankcheck_id = 'bankcheck_12345'

    status = None

    @requires_dynamic_permission(['money:write:{bankcheck.bankcheck_id}'])
    def do_something(bankcheck):
        nonlocal status
        status = True

    yosai = configured_securityutils

    with yosai:
        new_web_subject = yosai.subject
        new_web_subject.login(valid_username_password_token)
        try:
            do_something(bankcheck=BankCheck())
        except UnauthorizedException:
            new_web_subject.logout()
            assert status is None
        else:
            raise Exception('failed to raise')


def test_requires_role_succeeds(
        configured_securityutils, authz_info,
        valid_username_password_token, thedude_credentials):

    status = None

    @requires_role(['courier'])
    def do_something():
        nonlocal status
        status = True

    yosai = configured_securityutils

    with yosai:
        new_web_subject = yosai.subject
        new_web_subject.login(valid_username_password_token)
        do_something()
        assert status
        new_web_subject.logout()


def test_requires_role_fails(
        configured_securityutils, authz_info,
        valid_username_password_token, thedude_credentials):

    status = None

    @requires_role(['thief'])
    def do_something():
        nonlocal status
        status = True

    yosai = configured_securityutils

    with yosai:
        new_web_subject = yosai.subject
        new_web_subject.login(valid_username_password_token)
        try:
            do_something()
        except UnauthorizedException:
            assert status is None
            new_web_subject.logout()
