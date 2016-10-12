from passlib.totp import TOTP

from yosai.core import (
    load_logconfig,
    TOTPToken,
    UsernamePasswordToken,
    SimpleIdentifierCollection,
)

import pytest

load_logconfig()


@pytest.fixture(scope='function')
def thedude_identifier():
    return SimpleIdentifierCollection(source_name='AccountStoreRealm',
                                      identifier='thedude')


@pytest.fixture(scope='function')
def jackie_identifier():
    return SimpleIdentifierCollection(source_name='AccountStoreRealm',
                                      identifier='jackie')


@pytest.fixture(scope='function')
def walter_identifier():
    return SimpleIdentifierCollection(source_name='AccountStoreRealm',
                                      identifier='walter')


@pytest.fixture(scope='function')  # because successful login clears password
def jackie_username_password_token():
    return UsernamePasswordToken(username='jackie',
                                 password='business',
                                 remember_me=False,
                                 host='127.0.0.1')


@pytest.fixture(scope='function')  # because successful login clears password
def walter_username_password_token():
    return UsernamePasswordToken(username='walter',
                                 password='vietnam',
                                 remember_me=False,
                                 host='127.0.0.1')


@pytest.fixture(scope='function')
def clear_cached_credentials(cache_handler, request, thedude):
    def remove_credentials():
        nonlocal cache_handler
        cache_handler.delete(domain="credentials",
                             identifier=thedude.identifier)

    request.addfinalizer(remove_credentials)


@pytest.fixture(scope='function')
def clear_jackie_cached_credentials(cache_handler, request, jackie):
    def remove_jackie_credentials():
        nonlocal cache_handler
        cache_handler.delete(domain="credentials",
                             identifier=jackie.identifier)

    request.addfinalizer(remove_jackie_credentials)


@pytest.fixture(scope='function')
def clear_walter_cached_credentials(cache_handler, request, walter):
    def remove_walter_credentials():
        nonlocal cache_handler
        cache_handler.delete(domain="credentials",
                             identifier=walter.identifier)

    request.addfinalizer(remove_walter_credentials)


@pytest.fixture(scope='function')
def valid_username_password_token(cache_handler):
    domain = 'authentication:AccountStoreRealm'
    cache_handler.delete(domain=domain, identifier='thedude')
    yield UsernamePasswordToken(username='thedude',
                                 password='letsgobowling',
                                 remember_me=False,
                                 host='127.0.0.1')

    cache_handler.delete(domain=domain, identifier='thedude')

@pytest.fixture(scope='function')
def thedude_totp_key():
    return 'DP3RDO3FAAFUAFXQELW6OTB2IGM3SS6G'

@pytest.fixture(scope='function')
def valid_totp_token(thedude_totp_key, cache_handler):
    domain = 'authentication:AccountStoreRealm'
    cache_handler.delete(domain=domain, identifier='thedude')

    token = int(TOTP(key=thedude_totp_key).generate().token)

    yield TOTPToken(totp_token=token)

    cache_handler.delete(domain=domain, identifier='thedude')

@pytest.fixture(scope='function')  # because successful login clears password
def remembered_valid_username_password_token(cache_handler):
    domain = 'authentication:AccountStoreRealm'
    cache_handler.delete(domain=domain, identifier='thedude')

    yield UsernamePasswordToken(username='thedude',
                                 password='letsgobowling',
                                 remember_me=True,
                                 host='127.0.0.1')

    cache_handler.delete(domain=domain, identifier='thedude')



@pytest.fixture(scope='function')
def invalid_username_password_token():
    return UsernamePasswordToken(username='thedude',
                                 password='never_use__password__',
                                 remember_me=False,
                                 host='127.0.0.1')


@pytest.fixture(scope='function')
def clear_cached_authz_info(cache_handler, request):
    def remove_authz_info():
        nonlocal cache_handler
        cache_handler.delete(domain="authz_info",
                             identifier='thedude')

    request.addfinalizer(remove_authz_info)


@pytest.fixture(scope='function')
def clear_jackie_cached_authz_info(cache_handler, request):
    def remove_jackie_authz_info():
        nonlocal cache_handler
        cache_handler.delete(domain="authz_info",
                             identifier='jackie')

    request.addfinalizer(remove_jackie_authz_info)


@pytest.fixture(scope='function')
def clear_walter_cached_authz_info(cache_handler, request):
    def remove_walter_authz_info():
        nonlocal cache_handler
        cache_handler.delete(domain="authz_info",
                             identifier='walter')

    request.addfinalizer(remove_walter_authz_info)


@pytest.fixture(scope='function')
def thedude_testpermissions(permission_resolver):
    perm1 = permission_resolver('money:write:bankcheck_19911109069')
    perm2 = permission_resolver('money:withdrawal')
    perm3 = permission_resolver('leatherduffelbag:transport:theringer')
    perm4 = permission_resolver('leatherduffelbag:access:theringer')

    perms = [perm1, perm2, perm3, perm4]

    expected_results = frozenset([(perm1, True), (perm2, False),
                                  (perm3, True), (perm4, False)])

    return dict(perms=perms, expected_results=expected_results)


@pytest.fixture(scope='function')
def thedude_testroles():
    roles = {'bankcustomer', 'courier', 'gangster'}

    expected_results = frozenset([('bankcustomer', True),
                                  ('courier', True),
                                  ('gangster', False)])

    return dict(roles=roles, expected_results=expected_results)


@pytest.fixture(scope='function')
def jackie_testpermissions(permission_resolver):

    perm1 = permission_resolver('money:access:ransom')
    perm2 = permission_resolver('leatherduffelbag:access:theringer')
    perm3 = permission_resolver('money:withdrawal')

    perms = [perm1, perm2, perm3]

    expected_results = frozenset([(perm1, True), (perm2, True),
                                  (perm3, False)])

    return dict(perms=perms, expected_results=expected_results)


@pytest.fixture(scope='function')
def walter_testpermissions(permission_resolver):

    perm1 = permission_resolver('leatherduffelbag:transport:theringer')
    perm2 = permission_resolver('leatherduffelbag:access:theringer')
    perm3 = permission_resolver('*:bowl:*')

    perms = [perm1, perm2, perm3]

    expected_results = frozenset([(perm1, True), (perm2, False),
                                  (perm3, True)])

    return dict(perms=perms, expected_results=expected_results)
