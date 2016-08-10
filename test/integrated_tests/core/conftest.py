import pdb

from yosai.core import (
    load_logconfig,
    UsernamePasswordToken,
    SimpleIdentifierCollection,
)

from yosai_alchemystore.models.models import (
    UserModel,
    CredentialModel,
)


from yosai_alchemystore.models.models import (
    ActionModel,
    DomainModel,
    PermissionModel,
    ResourceModel,
    RoleModel,
    UserModel
)


from passlib.context import CryptContext
import datetime
import pytest

load_logconfig()

@pytest.fixture(scope='session')
def new_subject(configured_securityutils, yosai):
    return yosai.subject


@pytest.fixture(scope='session')
def thedude_identifier():
    return SimpleIdentifierCollection(source_name='AccountStoreRealm',
                                      identifier='thedude')

@pytest.fixture(scope='session')
def jackie_identifier():
    return SimpleIdentifierCollection(source_name='AccountStoreRealm',
                                      identifier='jackie')


@pytest.fixture(scope='session')
def walter_identifier():
    return SimpleIdentifierCollection(source_name='AccountStoreRealm',
                                      identifier='walter')


@pytest.fixture(scope='session')
def thedude(cache_handler, request, thedude_identifier, session):
    thedude = UserModel(first_name='Jeffrey',
                        last_name='Lebowski',
                        identifier='thedude')
    session = session()
    session.add(thedude)
    session.commit()

    return thedude


@pytest.fixture(scope='session')
def jackie(cache_handler, request, jackie_identifier, session):
    jackie = UserModel(first_name='Jackie',
                       last_name='Treehorn',
                       identifier='jackie')
    session = session()
    session.add(jackie)
    session.commit()
    return jackie


@pytest.fixture(scope='session')
def walter(cache_handler, request, walter_identifier, session):
    walter = UserModel(first_name='Walter',
                       last_name='Sobchak',
                       identifier='walter')
    session = session()
    session.add(walter)
    session.commit()
    return walter


@pytest.fixture(scope='session')  # because successful login clears password
def jackie_username_password_token():
    return UsernamePasswordToken(username='jackie',
                                 password='business',
                                 remember_me=False,
                                 host='127.0.0.1')


@pytest.fixture(scope='session')  # because successful login clears password
def walter_username_password_token():
    return UsernamePasswordToken(username='walter',
                                 password='vietnam',
                                 remember_me=False,
                                 host='127.0.0.1')


@pytest.fixture(scope='session')
def clear_cached_credentials(cache_handler, request, thedude):
    def remove_credentials():
        nonlocal cache_handler
        cache_handler.delete(domain="credentials",
                             identifier=thedude.identifier)

    request.addfinalizer(remove_credentials)


@pytest.fixture(scope='session')
def clear_jackie_cached_credentials(cache_handler, request, jackie):
    def remove_jackie_credentials():
        nonlocal cache_handler
        cache_handler.delete(domain="credentials",
                             identifier=jackie.identifier)

    request.addfinalizer(remove_jackie_credentials)


@pytest.fixture(scope='session')
def clear_walter_cached_credentials(cache_handler, request, walter):
    def remove_walter_credentials():
        nonlocal cache_handler
        cache_handler.delete(domain="credentials",
                             identifier=walter.identifier)

    request.addfinalizer(remove_walter_credentials)


@pytest.fixture(scope='session')  # because successful login clears password
def valid_username_password_token():
    return UsernamePasswordToken(username='thedude',
                                 password='letsgobowling',
                                 remember_me=False,
                                 host='127.0.0.1')


@pytest.fixture(scope='session')
def invalid_username_password_token():
    return UsernamePasswordToken(username='thedude',
                                 password='never_use__password__',
                                 remember_me=False,
                                 host='127.0.0.1')


@pytest.fixture(scope='session')
def thedude_credentials(request, thedude, clear_cached_credentials, session):
    password = "letsgobowling"
    cc = CryptContext(["bcrypt_sha256"])
    credentials = cc.encrypt(password)
    thirty_from_now = datetime.datetime.now() + datetime.timedelta(days=30)
    credential = CredentialModel(user_id=thedude.pk_id,
                                 credential=credentials,
                                 expiration_dt=thirty_from_now)
    session = session()
    session.add(credential)
    session.commit()

    return credentials


@pytest.fixture(scope='session')
def jackie_credentials(request, jackie, clear_jackie_cached_credentials, session):
    password = "business"
    cc = CryptContext(["bcrypt_sha256"])
    credentials = cc.encrypt(password)
    thirty_from_now = datetime.datetime.now() + datetime.timedelta(days=30)
    credential = CredentialModel(user_id=jackie.pk_id,
                                 credential=credentials,
                                 expiration_dt=thirty_from_now)
    session = session()
    session.add(credential)
    session.commit()

    return credentials


@pytest.fixture(scope='session')
def walter_credentials(request, walter, clear_walter_cached_credentials, session):
    password = "vietnam"
    cc = CryptContext(["bcrypt_sha256"])
    credentials = cc.encrypt(password)
    thirty_from_now = datetime.datetime.now() + datetime.timedelta(days=30)
    credential = CredentialModel(user_id=walter.pk_id,
                                 credential=credentials,
                                 expiration_dt=thirty_from_now)
    session = session()
    session.add(credential)
    session.commit()

    return credentials


@pytest.fixture(scope='session')
def clear_cached_authz_info(cache_handler, request):
    def remove_authz_info():
        nonlocal cache_handler
        cache_handler.delete(domain="authz_info",
                             identifier='thedude')

    request.addfinalizer(remove_authz_info)


@pytest.fixture(scope='session')
def clear_jackie_cached_authz_info(cache_handler, request):
    def remove_jackie_authz_info():
        nonlocal cache_handler
        cache_handler.delete(domain="authz_info",
                             identifier='jackie')

    request.addfinalizer(remove_jackie_authz_info)


@pytest.fixture(scope='session')
def clear_walter_cached_authz_info(cache_handler, request):
    def remove_walter_authz_info():
        nonlocal cache_handler
        cache_handler.delete(domain="authz_info",
                             identifier='walter')

    request.addfinalizer(remove_walter_authz_info)


@pytest.fixture(scope='session')
def authz_info(request, cache_handler, thedude, jackie, walter,
               clear_cached_authz_info, clear_jackie_cached_authz_info,
               clear_walter_cached_authz_info, session):

    domains = [DomainModel(name='money'),
               DomainModel(name='leatherduffelbag')]

    actions = [ActionModel(name='write'),
               ActionModel(name='deposit'),
               ActionModel(name='transport'),
               ActionModel(name='access'),
               ActionModel(name='withdrawal'),
               ActionModel(name='bowl'),
               ActionModel(name='run')]

    resources = [ResourceModel(name='theringer'),
                 ResourceModel(name='ransom'),
                 ResourceModel(name='bankcheck_19911109069'),
                 ResourceModel(name='bowlingball')]

    roles = [RoleModel(title='courier'),
             RoleModel(title='tenant'),
             RoleModel(title='landlord'),
             RoleModel(title='gangster'),
             RoleModel(title='bankcustomer'),
             RoleModel(title='bowler')]

    session = session()
    session.add_all(roles + domains + actions + resources)

    domains = dict((domain.name, domain) for domain in session.query(DomainModel).all())
    actions = dict((action.name, action) for action in session.query(ActionModel).all())
    resources = dict((resource.name, resource) for resource in session.query(ResourceModel).all())
    roles = dict((role.title, role) for role in session.query(RoleModel).all())

    perm1 = PermissionModel(domain=domains['money'],
                            action=actions['write'],
                            resource=resources['bankcheck_19911109069'])

    perm2 = PermissionModel(domain=domains['money'],
                            action=actions['deposit'])

    perm3 = PermissionModel(domain=domains['money'],
                            action=actions['access'],
                            resource=resources['ransom'])

    perm4 = PermissionModel(domain=domains['leatherduffelbag'],
                            action=actions['transport'],
                            resource=resources['theringer'])

    perm5 = PermissionModel(domain=domains['leatherduffelbag'],
                            action=actions['access'],
                            resource=resources['theringer'])

    perm6 = PermissionModel(domain=domains['money'],
                            action=actions['withdrawal'])

    perm7 = PermissionModel(action=actions['bowl'])

    perm8 = PermissionModel(action=actions['run'])  # I dont know!?

    session.add_all([perm1, perm2, perm3, perm4, perm5, perm6, perm7, perm8])

    bankcustomer = roles['bankcustomer']
    courier = roles['courier']
    tenant = roles['tenant']
    landlord = roles['landlord']
    gangster = roles['gangster']
    bowler = roles['bowler']

    bankcustomer.permissions.extend([perm1, perm2])
    courier.permissions.extend([perm4, perm7])
    tenant.permissions.extend([perm1, perm7])
    gangster.permissions.extend([perm3, perm4, perm5, perm7])
    landlord.permissions.extend([perm6, perm7])
    bowler.permissions.append(perm8)

    userquery = session.query(UserModel)
    thedude = userquery.filter(UserModel.identifier == 'thedude').scalar()
    thedude.roles.extend([bankcustomer, courier, tenant, bowler])

    jackie = userquery.filter(UserModel.identifier == 'jackie').scalar()
    jackie.roles.extend([bankcustomer, gangster])

    walter = userquery.filter(UserModel.identifier == 'walter').scalar()
    walter.roles.extend([bowler, courier])

    session.commit()


@pytest.fixture(scope='session')
def thedude_testpermissions(authz_info, permission_resolver):
    perm1 = permission_resolver('money:write:bankcheck_19911109069')
    perm2 = permission_resolver('money:withdrawal')
    perm3 = permission_resolver('leatherduffelbag:transport:theringer')
    perm4 = permission_resolver('leatherduffelbag:access:theringer')

    perms = [perm1, perm2, perm3, perm4]

    expected_results = frozenset([(perm1, True), (perm2, False),
                                  (perm3, True), (perm4, False)])

    return dict(perms=perms, expected_results=expected_results)


@pytest.fixture(scope='session')
def thedude_testroles(authz_info):
    roles = {'bankcustomer', 'courier', 'gangster'}

    expected_results = frozenset([('bankcustomer', True),
                                  ('courier', True),
                                  ('gangster', False)])

    return dict(roles=roles, expected_results=expected_results)


@pytest.fixture(scope='session')
def jackie_testpermissions(authz_info, permission_resolver):

    perm1 = permission_resolver('money:access:ransom')
    perm2 = permission_resolver('leatherduffelbag:access:theringer')
    perm3 = permission_resolver('money:withdrawal')

    perms = [perm1, perm2, perm3]

    expected_results = frozenset([(perm1, True), (perm2, True),
                                  (perm3, False)])

    return dict(perms=perms, expected_results=expected_results)


@pytest.fixture(scope='session')
def walter_testpermissions(authz_info, permission_resolver):

    perm1 = permission_resolver('leatherduffelbag:transport:theringer')
    perm2 = permission_resolver('leatherduffelbag:access:theringer')
    perm3 = permission_resolver('*:bowl:*')

    perms = [perm1, perm2, perm3]

    expected_results = frozenset([(perm1, True), (perm2, False),
                                  (perm3, True)])

    return dict(perms=perms, expected_results=expected_results)
