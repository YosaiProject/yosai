import pytest
from yosai.core import (
    AuthenticationException,
    ExpiredSessionException,
    IdentifiersNotSetException,
    IllegalStateException,
    UnauthorizedException,
    UnauthenticatedException,
    UnknownSessionException,
    Yosai,
    event_bus,
)
import datetime


def test_subject_invalid_login(invalid_username_password_token, yosai):

    with Yosai.context(yosai):
        new_subject = Yosai.get_current_subject()

        with pytest.raises(AuthenticationException):
            new_subject.login(invalid_username_password_token)


def test_authenticated_subject_session_attribute_logout(
        valid_username_password_token, yosai):
    with Yosai.context(yosai):
        new_subject = Yosai.get_current_subject()
        new_subject.login(valid_username_password_token)
        session = new_subject.get_session()
        session.set_attribute('attribute1', 'attr1')
        session.set_attribute('attribute2', 'attr2')
        assert (session.get_attribute('attribute1') == 'attr1' and
                session.get_attribute('attribute2') == 'attr2')
        new_subject.logout()


def test_authenticated_subject_is_permitted(
        valid_username_password_token, thedude_testpermissions, yosai):
    tp = thedude_testpermissions
    with Yosai.context(yosai):
        new_subject = Yosai.get_current_subject()

        new_subject.login(valid_username_password_token)

        results = new_subject.is_permitted(tp['perms'])
        assert results == tp['expected_results']

        new_subject.logout()

        with pytest.raises(IdentifiersNotSetException):
            new_subject.is_permitted(tp['perms'])


def test_authenticated_subject_is_permitted_collective(
        valid_username_password_token, thedude_testpermissions, yosai):

    tp = thedude_testpermissions

    with Yosai.context(yosai):
        new_subject = Yosai.get_current_subject()

        new_subject.login(valid_username_password_token)

        assert ((new_subject.is_permitted_collective(tp['perms'], any) is True) and
                (new_subject.is_permitted_collective(tp['perms'], all) is False))

        new_subject.logout()

        with pytest.raises(IdentifiersNotSetException):
            new_subject.is_permitted_collective(tp['perms'], any)


def test_authenticated_subject_check_permission_succeeds(
        thedude_testpermissions, valid_username_password_token, yosai):

    tp = thedude_testpermissions
    event_detected = None

    def event_listener(identifiers=None, items=None, logical_operator=None):
        nonlocal event_detected
        event_detected = items
    event_bus.register(event_listener, 'AUTHORIZATION.GRANTED')

    with Yosai.context(yosai):
        new_subject = Yosai.get_current_subject()
        new_subject.login(valid_username_password_token)

        check = new_subject.check_permission(tp['perms'], any)
        assert (check is None and event_detected == tp['perms'])

        new_subject.logout()

        with pytest.raises(UnauthenticatedException):
            new_subject.check_permission(tp['perms'], any)


def test_check_permission_raises(
        permission_resolver, thedude_testpermissions,
        valid_username_password_token, yosai):

    tp = thedude_testpermissions

    event_detected = None

    def event_listener(identifiers=None, items=None, logical_operator=None):
        nonlocal event_detected
        event_detected = items
    event_bus.register(event_listener, 'AUTHORIZATION.DENIED')

    with Yosai.context(yosai):
        new_subject = Yosai.get_current_subject()

        new_subject.login(valid_username_password_token)

        with pytest.raises(UnauthorizedException):
            new_subject.check_permission(tp['perms'], all)
            assert event_detected == tp['perms']

            new_subject.logout()


def test_has_role(valid_username_password_token, thedude_testroles, yosai):

    tr = thedude_testroles
    event_detected = None

    def event_listener(identifiers=None, items=None):
        nonlocal event_detected
        event_detected = items
    event_bus.register(event_listener, 'AUTHORIZATION.RESULTS')

    with Yosai.context(yosai):
        new_subject = Yosai.get_current_subject()
        new_subject.login(valid_username_password_token)
        result = new_subject.has_role(tr['roles'])

        assert (tr['expected_results'] == result and
                frozenset(event_detected) == result)

        new_subject.logout()


def test_authenticated_subject_has_role_collective(
        thedude_testroles, valid_username_password_token, yosai):

    tr = thedude_testroles

    with Yosai.context(yosai):
        new_subject = Yosai.get_current_subject()

        new_subject.login(valid_username_password_token)

        assert ((new_subject.has_role_collective(tr['roles'], all) is False) and
                (new_subject.has_role_collective(tr['roles'], any) is True))

        new_subject.logout()


def test_check_role_succeeds(
        thedude_testroles, valid_username_password_token, yosai):

    tr = thedude_testroles

    event_detected = None

    def event_listener(identifiers=None, items=None, logical_operator=None):
        nonlocal event_detected
        event_detected = items
    event_bus.register(event_listener, 'AUTHORIZATION.GRANTED')

    with Yosai.context(yosai):
        new_subject = Yosai.get_current_subject()
        new_subject.login(valid_username_password_token)
        assert (new_subject.check_role(tr['roles'], any) is None and
                event_detected == tr['roles'])

        new_subject.logout()


def test_check_role_raises(
        thedude_testroles, valid_username_password_token, yosai):

    tr = thedude_testroles

    event_detected = None

    def event_listener(identifiers=None, items=None, logical_operator=None):
        nonlocal event_detected
        event_detected = items
    event_bus.register(event_listener, 'AUTHORIZATION.DENIED')

    with Yosai.context(yosai):
        new_subject = Yosai.get_current_subject()
        new_subject.login(valid_username_password_token)
        with pytest.raises(UnauthorizedException):
            new_subject.check_role(tr['roles'], all)

            assert event_detected == tr['roles']
        new_subject.logout()


def test_run_as_raises(walter_identifier, yosai):

    with Yosai.context(yosai):
        new_subject = Yosai.get_current_subject()
        # a login is required , so this should raise:
        new_subject.logout()
        with pytest.raises(IllegalStateException):
            new_subject.run_as(walter_identifier)


def test_run_as_pop(walter_identifier, jackie_identifier, yosai,
                    jackie_testpermissions, walter_testpermissions,
                    valid_username_password_token):

    jp = jackie_testpermissions
    wp = walter_testpermissions

    with Yosai.context(yosai):
        new_subject = Yosai.get_current_subject()
        new_subject.login(valid_username_password_token)

        new_subject.run_as(jackie_identifier)
        jackieresults = new_subject.is_permitted(jp['perms'])
        assert jackieresults == jp['expected_results']

        new_subject.run_as(walter_identifier)
        walterresults = new_subject.is_permitted(wp['perms'])
        assert walterresults == wp['expected_results']

        new_subject.pop_identity()
        assert new_subject.identifiers == jackie_identifier

        new_subject.logout()


def test_logout_clears_cache(
        thedude_identifier, valid_username_password_token, yosai,
        thedude_testpermissions, caplog):

    tp = thedude_testpermissions

    with Yosai.context(yosai):
        new_subject = Yosai.get_current_subject()
        new_subject.login(valid_username_password_token)  # caches credentials
        new_subject.is_permitted(tp['perms'])  # caches authz_info

        new_subject.logout()

        out = caplog.text

        assert ('Clearing cached credentials for [thedude]' in out and
                'Clearing cached authz_info for [thedude]' in out)


def test_session_stop_clears_cache(
        thedude_identifier, valid_username_password_token, yosai,
        thedude_testpermissions, caplog):

    tp = thedude_testpermissions

    with Yosai.context(yosai):
        new_subject = Yosai.get_current_subject()
        new_subject.login(valid_username_password_token)  # caches credentials
        new_subject.is_permitted(tp['perms'])  # caches authz_info

        session = new_subject.get_session()
        session.stop(None)

        out = caplog.text

        assert ('Clearing cached credentials for [thedude]' in out and
                'Clearing cached authz_info for [thedude]' in out)


def test_login_clears_cache(
        thedude_identifier, valid_username_password_token, caplog, yosai):

    with Yosai.context(yosai):
        new_subject = Yosai.get_current_subject()
        new_subject.login(valid_username_password_token)  # caches credentials

        out = caplog.text

        assert 'Clearing cached authz_info for [thedude]' in out
    new_subject.logout()


def test_session_idle_expiration_clears_cache(
        valid_username_password_token, thedude_testpermissions,
        caplog, cache_handler, yosai):

    tp = thedude_testpermissions

    with Yosai.context(yosai):
        new_subject = Yosai.get_current_subject()
        new_subject.login(valid_username_password_token)  # caches credentials
        new_subject.is_permitted(tp['perms'])  # caches authz_info

        session = new_subject.get_session()
        session = cache_handler.get('session', identifier=session.session_id)

        twenty_ago = (60 * 20 * 1000)
        session.last_access_time = session.last_access_time - twenty_ago
        cache_handler.set('session', session.session_id, session)
        session = cache_handler.get('session', identifier=session.session_id)

        session = new_subject.get_session()

        with pytest.raises(ExpiredSessionException):
            session.last_access_time  # this triggers the expiration

            out = caplot.text
            assert ('Clearing cached credentials for [thedude]' in out and
                    'Clearing cached authz_info for [thedude]' in out)


def test_absolute_expired_session(
        valid_username_password_token, yosai, thedude_testpermissions,
        cache_handler):

    tp = thedude_testpermissions

    with Yosai.context(yosai):
        new_subject = Yosai.get_current_subject()
        new_subject.login(valid_username_password_token)
        session = new_subject.get_session()
        results = new_subject.is_permitted(tp['perms'])
        assert results == tp['expected_results']

        # when time has reached the TTL, the cache entry is removed:
        cache_handler.delete('session', identifier=session.session_id)

        with pytest.raises(UnknownSessionException):
            new_subject.is_permitted(tp['perms'])


def test_requires_permission_succeeds(yosai, valid_username_password_token):

    status = None

    @Yosai.requires_permission(['money:write:bankcheck_19911109069'])
    def do_something():
        nonlocal status
        status = True

    with Yosai.context(yosai):
        new_subject = Yosai.get_current_subject()
        new_subject.login(valid_username_password_token)
        do_something()
        new_subject.logout()
        assert status


def test_requires_permission_fails(yosai, valid_username_password_token):

    status = None

    @Yosai.requires_permission(['money:write:bankcheck_12345'])
    def do_something():
        nonlocal status
        status = True

    with Yosai.context(yosai):
        new_subject = Yosai.get_current_subject()
        new_subject.login(valid_username_password_token)
        try:
            do_something()
        except UnauthorizedException:
            assert status is None
            new_subject.logout()
        else:
            raise Exception('failed to raise')


def test_requires_dynamic_permission_succeeds(yosai, valid_username_password_token):

    class BankCheck:
        def __init__(self):
            self.bankcheck_id = 'bankcheck_19911109069'

    status = None

    @Yosai.requires_dynamic_permission(['money:write:{bankcheck.bankcheck_id}'])
    def do_something(bankcheck):
        nonlocal status
        status = True

    with Yosai.context(yosai):
        new_subject = Yosai.get_current_subject()
        new_subject.login(valid_username_password_token)
        do_something(bankcheck=BankCheck())
        new_subject.logout()
        assert status


def test_requires_dynamic_permission_fails(yosai, valid_username_password_token):

    class BankCheck:
        def __init__(self):
            self.bankcheck_id = 'bankcheck_12345'

    status = None

    @Yosai.requires_dynamic_permission(['money:write:{bankcheck.bankcheck_id}'])
    def do_something(bankcheck):
        nonlocal status
        status = True

    with Yosai.context(yosai):
        new_subject = Yosai.get_current_subject()
        new_subject.login(valid_username_password_token)
        try:
            do_something(bankcheck=BankCheck())
        except UnauthorizedException:
            new_subject.logout()
            assert status is None
        else:
            raise Exception('failed to raise')


def test_requires_role_succeeds(yosai, valid_username_password_token):

    status = None

    @Yosai.requires_role(['courier'])
    def do_something():
        nonlocal status
        status = True

    with Yosai.context(yosai):
        new_subject = Yosai.get_current_subject()
        new_subject.login(valid_username_password_token)
        do_something()
        assert status
        new_subject.logout()


def test_requires_role_fails(yosai, valid_username_password_token):

    status = None

    @Yosai.requires_role(['thief'])
    def do_something():
        nonlocal status
        status = True

    with Yosai.context(yosai):
        new_subject = Yosai.get_current_subject()
        new_subject.login(valid_username_password_token)
        try:
            do_something()
        except UnauthorizedException:
            assert status is None
            new_subject.logout()
