import pytest
from passlib.context import CryptContext
import datetime

from yosai.core import (
    AuthzInfoResolver,
    Credential,
    CredentialResolver,
    DefaultPermission,
    IndexedAuthorizationInfo,
    PermissionResolver,
    RoleResolver,
    SimpleRole,
    UsernamePasswordToken,
)

from yosai_alchemystore import (
    Session,
)

from yosai_alchemystore.models.models import (
    Action,
    Credential,
    Domain,
    User,
    Permission,
    Resource,
    Role,
)


@pytest.fixture(scope='function')
def authz_info_resolver():
    return AuthzInfoResolver(IndexedAuthorizationInfo)


@pytest.fixture(scope='function')
def credential_resolver():
    return CredentialResolver(Credential)


@pytest.fixture(scope='function')
def indexed_authz_info(permission_collection, role_collection):
    return IndexedAuthorizationInfo(roles=role_collection,
                                    permissions=permission_collection)


@pytest.fixture(scope='function')
def permission_collection():
    return {DefaultPermission(domain={'domain1'}, action={'action1'}),
            DefaultPermission(domain={'domain2'}, action={'action1', 'action2'}),
            DefaultPermission(domain={'domain3'}, action={'action1', 'action2', 'action3'}, target={'target1'}),
            DefaultPermission(domain={'domain4'}, action={'action1', 'action2'}),
            DefaultPermission(domain={'domain4'}, action={'action3'}, target={'target1'}),
            DefaultPermission(wildcard_string='*:action5')}


@pytest.fixture(scope='function')
def permission_resolver():
    return PermissionResolver(DefaultPermission)


@pytest.fixture(scope='function')
def role_collection():
    return {SimpleRole(role_identifier='role1'),
            SimpleRole(role_identifier='role2'),
            SimpleRole(role_identifier='role3')}


@pytest.fixture(scope='function')
def role_resolver():
    return RoleResolver(SimpleRole)


@pytest.fixture(scope='function')
def username_password_token():
    return UsernamePasswordToken(username='user123',
                                 password='letsgobowling',
                                 remember_me=False,
                                 host='127.0.0.1')


@pytest.fixture(scope='module')
def user_thedude(request, cache_handler):
    thedude = User(first_name='Jeffrey',
                   last_name='Lebowski',
                   identifier='thedude')
    
    session = Session()
    session.add(thedude)
    session.commit()
    session.close()

    def remove_user():
        nonlocal cache_handler
        session.delete(thedude)
        session.commit()
        session.close()

    request.addfinalizer(remove_user)

    return thedude 


@pytest.fixture(scope='module')
def thedude_credentials(request, user_thedude, cache_handler):

    cc = CryptContext(["bcrypt_sha256"])
    credentials = cc.encrypt("letsgobowling")

    thirty_from_now = datetime.datetime.now() + datetime.timedelta(days=30)
    credential = Credential(user_id=user_thedude.pk_id,
                            credential=credentials,
                            expiration_dt=thirty_from_now)
    
    session = Session()
    session.add(credential)
    session.commit()
    session.close()

    def remove_credentials():
        nonlocal cache_handler
        nonlocal session
        cache_handler.delete(domain="credentials",
                             identifier=user_thedude.identifier)
        session.delete(credential)
        session.commit()
        session.close()

    request.addfinalizer(remove_credentials)


@pytest.fixture(scope='module')
def thedude_authz_info(request, user_thedude, cache_handler):
    
    def remove_authz_info():
        nonlocal cache_handler
        nonlocal session
        nonlocal roles, domains, actions, resources
        cache_handler.delete(domain="authz_info",
                             identifier=user_thedude.identifier)
        for x in (roles + domains + actions + resources):
            session.delete(x)

        session.commit()

    request.addfinalizer(remove_authz_info)

    domains = [Domain(name='money'),
               Domain(name='leatherduffelbag')]

    actions = [Action(name='write'),
               Action(name='deposit'),
               Action(name='transport'),
               Action(name='access'),
               Action(name='withdrawal'),
               Action(name='bowl'),
               Action(name='run')]

    resources = [Resource(name='theringer'),
                 Resource(name='ransom'),
                 Resource(name='bankcheck_19911109069')]

    roles = [Role(title='courier'),
             Role(title='tenant'),
             Role(title='landlord'),
             Role(title='thief'),
             Role(title='bankcustomer')]

    session = Session()
    session.add_all(users + roles + domains + actions + resources)

    users = dict((user.first_name+'_'+user.last_name, user) for user in session.query(User).all())
    domains = dict((domain.name, domain) for domain in session.query(Domain).all())
    actions = dict((action.name, action) for action in session.query(Action).all())
    resources = dict((resource.name, resource) for resource in session.query(Resource).all())
    roles = dict((role.title, role) for role in session.query(Role).all())

    perm1 = Permission(domain=domains['money'],
                       action=actions['write'],
                       resource=resources['bankcheck_19911109069'])

    perm2 = Permission(domain=domains['money'],
                       action=actions['deposit'])

    perm3 = Permission(domain=domains['money'],
                       action=actions['access'],
                       resource=resources['ransom'])

    perm4 = Permission(domain=domains['leatherduffelbag'],
                       action=actions['transport'],
                       resource=resources['theringer'])

    perm5 = Permission(domain=domains['leatherduffelbag'],
                       action=actions['access'],
                       resource=resources['theringer'])

    perm6 = Permission(domain=domains['money'],
                       action=actions['withdrawal'])

    perm7 = Permission(action=actions['bowl'])

    perm8 = Permission(action=actions['run'])  # I dont know!?

    session.add_all([perm1, perm2, perm3, perm4, perm5, perm6, perm7, perm8])

    bankcustomer = roles['bankcustomer']
    courier = roles['courier']
    tenant = roles['tenant']
    landlord = roles['landlord']
    thief = roles['thief']

    bankcustomer.permissions.extend([perm2, perm7, perm8])
    courier.permissions.extend([perm4, perm7, perm8])
    tenant.permissions.extend([perm1, perm7, perm8])
    thief.permissions.extend([perm3, perm4, perm5, perm7, perm8])
    landlord.permissions.extend([perm6, perm7, perm8])

    thedude = users['Jeffrey_Lebowski']
    thedude.roles.extend([bankcustomer, courier, tenant])

    session.commit()
    session.close()
