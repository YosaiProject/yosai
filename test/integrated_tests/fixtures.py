from yosai.core import (
    AccountStoreRealm,
    UsernamePasswordToken,
)

from yosai_alchemystore import (
    Base,
    engine,
)

from yosai_alchemystore.models.models import (
    ActionModel,
    CredentialModel,
    DomainModel,
    UserModel,
    PermissionModel,
    ResourceModel,
    RoleModel,
)

from yosai_alchemystore import (
    Session,
    meta,
)
from yosai_dpcache.cache import DPCacheHandler
from yosai_alchemystore import AlchemyAccountStore
from passlib.context import CryptContext

import pytest
import datetime


@pytest.fixture(scope='module')
def test_db(request):
    Base.metadata.create_all(engine)

    def drop_all():
        Base.metadata.drop_all(engine)

    request.addfinalizer(drop_all)

@pytest.fixture(scope='module')
def cache_handler():
    return DPCacheHandler()


@pytest.fixture(scope='module')
def alchemy_store(test_db):
    return AlchemyAccountStore()


@pytest.fixture(scope='module')
def account_store_realm(cache_handler, permission_resolver,
                        role_resolver, credential_resolver,
                        authz_info_resolver, alchemy_store):
    asr = AccountStoreRealm()

    asr.cache_handler = cache_handler
    asr.account_store = alchemy_store
    asr.permission_resolver = permission_resolver
    asr.credential_resolver = credential_resolver
    asr.authz_info_resolver = authz_info_resolver
    asr.role_resolver = role_resolver

    return asr


#def init_test_db():
# creates an in-memory sqlite instance
#    engine = create_engine('sqlite://')

@pytest.fixture(scope='module')
def thedude(cache_handler, request):
    thedude = UserModel(first_name='Jeffrey',
                        last_name='Lebowski',
                        identifier='thedude')
    
    session = Session()
    session.add(thedude)
    session.commit()

    return thedude


@pytest.fixture(scope='module')
def clear_cache(cache_handler, request, thedude):
    def remove_credentials():
        nonlocal cache_handler
        cache_handler.delete(domain="credentials",
                             identifier=thedude.identifier)

    request.addfinalizer(remove_credentials)
    

@pytest.fixture(scope='module')
def thedude_credentials(request, thedude, clear_cache):
    password = "letsgobowling"
    cc = CryptContext(["bcrypt_sha256"])
    credentials = cc.encrypt(password)
    thirty_from_now = datetime.datetime.now() + datetime.timedelta(days=30)
    credential = CredentialModel(user_id=thedude.pk_id,
                            credential=credentials,
                            expiration_dt=thirty_from_now)

    session = Session()
    session.add(credential)
    session.commit()
    
    return credentials


@pytest.fixture(scope='module')
def valid_username_password_token(thedude, thedude_credentials):
    return UsernamePasswordToken(username=thedude.identifier,
                                 password='letsgobowling',
                                 remember_me=False,
                                 host='127.0.0.1')


@pytest.fixture(scope='module')
def invalid_username_password_token():
    return UsernamePasswordToken(username='thedude',
                                 password='never_use__password__',
                                 remember_me=False,
                                 host='127.0.0.1')


@pytest.fixture(scope='module')
def thedude_authz_info(request, thedude, cache_handler):
    
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
                 ResourceModel(name='bankcheck_19911109069')]

    roles = [RoleModel(title='courier'),
             RoleModel(title='tenant'),
             RoleModel(title='landlord'),
             RoleModel(title='thief'),
             RoleModel(title='bankcustomer')]

    session = Session()
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
    thief = roles['thief']

    bankcustomer.permissions.extend([perm2, perm7, perm8])
    courier.permissions.extend([perm4, perm7, perm8])
    tenant.permissions.extend([perm1, perm7, perm8])
    thief.permissions.extend([perm3, perm4, perm5, perm7, perm8])
    landlord.permissions.extend([perm6, perm7, perm8])

    thedude.roles.extend([bankcustomer, courier, tenant])

    session.commit()
    
    def remove_authz_info():
        nonlocal cache_handler
        nonlocal thedude
        session = Session()
        nonlocal roles, domains, actions, resources

        # cascading deletes clear the association tables:
        cache_handler.delete(domain="authz_info",
                             identifier=thedude.identifier)
        for x in (roles + domains + actions + resources):
            session.delete(x)

        session.commit()

    request.addfinalizer(remove_authz_info)

