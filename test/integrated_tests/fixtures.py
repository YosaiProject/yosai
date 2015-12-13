from marshmallow import Schema, fields

from yosai.core import (
    AccountStoreRealm,
    NativeSecurityManager,
    event_bus,
    UsernamePasswordToken,
    SecurityUtils,
    SimpleIdentifierCollection,
)

from yosai_alchemystore import (
    Base,
    engine,
)

from yosai_alchemystore.models.models import (
    UserModel,
    CredentialModel,
)

from yosai_alchemystore import (
    Session,
)


from yosai_alchemystore.models.models import (
    ActionModel,
    DomainModel,
    PermissionModel,
    ResourceModel,
    RoleModel,
    UserModel
)




from yosai_dpcache.cache import DPCacheHandler
from yosai_alchemystore import AlchemyAccountStore
from passlib.context import CryptContext
import datetime
import pytest


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
def alchemy_store():
    return AlchemyAccountStore()


@pytest.fixture(scope='module')
def account_store_realm(cache_handler, alchemy_store, permission_resolver,
                        role_resolver, authz_info_resolver, credential_resolver):

    asr = AccountStoreRealm()

    asr.cache_handler = cache_handler
    asr.account_store = alchemy_store

    asr.credential_resolver = credential_resolver
    asr.permission_resolver = permission_resolver
    asr.authz_info_resolver = authz_info_resolver
    asr.role_resolver = role_resolver

    return asr


#def init_test_db():
# creates an in-memory sqlite instance
#    engine = create_engine('sqlite://')

@pytest.fixture(scope='module')
def thedude_identifier():
    return SimpleIdentifierCollection(source_name='AccountStoreRealm',
                                      identifiers={'thedude'})

@pytest.fixture(scope='module')
def thedude(test_db, cache_handler, request, thedude_identifier):
    thedude = UserModel(first_name='Jeffrey',
                        last_name='Lebowski',
                        identifier='thedude')

    session = Session()
    session.add(thedude)
    session.commit()

    return thedude


@pytest.fixture(scope='function')  # because successful login clears password
def valid_username_password_token():
    return UsernamePasswordToken(username='thedude',
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
def clear_cached_credentials(cache_handler, request, thedude):
    def remove_credentials():
        nonlocal cache_handler
        cache_handler.delete(domain="credentials",
                             identifier=thedude.identifier)

    request.addfinalizer(remove_credentials)


@pytest.fixture(scope='module')
def thedude_credentials(request, thedude, clear_cached_credentials):
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
def native_security_manager(account_store_realm, cache_handler):

    class AttributesSchema(Schema):
        name = fields.String()

    nsm = NativeSecurityManager(realms=(account_store_realm,),
                                session_attributes_schema=AttributesSchema)
    nsm.cache_handler = cache_handler
    nsm.event_bus = event_bus
    return nsm


@pytest.fixture(scope='module')
def configured_securityutils(native_security_manager):
    SecurityUtils.security_manager = native_security_manager


@pytest.fixture(scope='module')
def new_subject(configured_securityutils):
    return SecurityUtils.get_subject()


@pytest.fixture(scope='module')
def clear_cached_authz_info(cache_handler, request):
    def remove_authz_info():
        nonlocal cache_handler
        cache_handler.delete(domain="authz_info",
                             identifier='thedude')

    request.addfinalizer(remove_authz_info)


@pytest.fixture(scope='module')
def thedude_authz_info(request, cache_handler, thedude, clear_cached_authz_info):

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

    userquery = session.query(UserModel)
    thedude = userquery.filter(UserModel.identifier == 'thedude').scalar()
    thedude.roles.extend([bankcustomer, courier, tenant])

    session.commit()


@pytest.fixture(scope='module')
def thedude_testpermissions(thedude_authz_info, permission_resolver):
    perm1 = permission_resolver('money:write:bankcheck_19911109069')
    perm2 = permission_resolver('money:withdrawal')
    perm3 = permission_resolver('leatherduffelbag:transport:theringer')
    perm4 = permission_resolver('leatherduffelbag:access:theringer')

    perms = [perm1, perm2, perm3, perm4]

    expected_results = frozenset([(perm1, True), (perm2, False),
                                  (perm3, True), (perm4, False)])

    return dict(perms=perms, expected_results=expected_results)
