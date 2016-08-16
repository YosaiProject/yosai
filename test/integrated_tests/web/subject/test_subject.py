import pdb

import pytest
from yosai.core import (
    AuthenticationException,
    ExpiredSessionException,
    IdentifiersNotSetException,
    IllegalStateException,
    event_bus,
)

from yosai.web import WebYosai

import datetime


def test_subject_invalid_login(web_yosai, mock_web_registry,
                               invalid_username_password_token):

    with pytest.raises(AuthenticationException):

        with WebYosai.context(web_yosai, mock_web_registry):
            subject = WebYosai.get_current_subject()
            subject.login(invalid_username_password_token)


def test_authenticated_subject_is_permitted(
        web_yosai, mock_web_registry, valid_username_password_token,
        thedude_credentials, authz_info, thedude_testpermissions):

    tp = thedude_testpermissions

    with WebYosai.context(web_yosai, mock_web_registry):
        new_web_subject = WebYosai.get_current_subject()
        new_web_subject.login(valid_username_password_token)

        results = new_web_subject.is_permitted(tp['perms'])
        assert results == tp['expected_results']

        new_web_subject.logout()

        with pytest.raises(IdentifiersNotSetException):
            new_web_subject.is_permitted(tp['perms'])


def test_authenticated_subject_is_permitted_collective(
        valid_username_password_token,
        thedude_credentials, authz_info, thedude_testpermissions):

    tp = thedude_testpermissions

    with WebYosai.context(web_yosai, mock_web_registry):
        new_web_subject = WebYosai.get_current_subject()
        new_web_subject.login(valid_username_password_token)

        assert ((new_web_subject.is_permitted_collective(tp['perms'], any) is True) and
                (new_web_subject.is_permitted_collective(tp['perms'], all) is False))

        new_web_subject.logout()

        with pytest.raises(IdentifiersNotSetException):
            new_web_subject.is_permitted_collective(tp['perms'], any)


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
