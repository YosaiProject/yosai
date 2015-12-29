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

    asr = AccountStoreRealm(name='AccountStoreRealm')

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
                                      identifier='thedude')

@pytest.fixture(scope='module')
def thedude(test_db, cache_handler, request, thedude_identifier):
    thedude = UserModel(first_name='Jeffrey',
                        last_name='Lebowski',
                        identifier='thedude')

    session = Session()
    session.add(thedude)
    session.commit()

    return thedude


@pytest.fixture(scope='module')
def jackie_identifier():
    return SimpleIdentifierCollection(source_name='AccountStoreRealm',
                                      identifier='jackie')


@pytest.fixture(scope='module')
def jackie(test_db, cache_handler, request, jackie_identifier):
    jackie = UserModel(first_name='Jackie',
                       last_name='Treehorn',
                       identifier='jackie')

    session = Session()
    session.add(jackie)
    session.commit()

    return jackie


@pytest.fixture(scope='module')
def walter_identifier():
    return SimpleIdentifierCollection(source_name='AccountStoreRealm',
                                      identifier='walter')


@pytest.fixture(scope='module')
def walter(test_db, cache_handler, request, walter_identifier):
    walter = UserModel(first_name='Walter',
                       last_name='Sobchak',
                       identifier='walter')

    session = Session()
    session.add(walter)
    session.commit()

    return walter


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


@pytest.fixture(scope='module')
def clear_jackie_cached_credentials(cache_handler, request, jackie):
    def remove_jackie_credentials():
        nonlocal cache_handler
        cache_handler.delete(domain="credentials",
                             identifier=jackie.identifier)

    request.addfinalizer(remove_jackie_credentials)


@pytest.fixture(scope='module')
def clear_walter_cached_credentials(cache_handler, request, walter):
    def remove_walter_credentials():
        nonlocal cache_handler
        cache_handler.delete(domain="credentials",
                             identifier=walter.identifier)

    request.addfinalizer(remove_walter_credentials)


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
def jackie_credentials(request, jackie, clear_jackie_cached_credentials):
    password = "business"
    cc = CryptContext(["bcrypt_sha256"])
    credentials = cc.encrypt(password)
    thirty_from_now = datetime.datetime.now() + datetime.timedelta(days=30)
    credential = CredentialModel(user_id=jackie.pk_id,
                                 credential=credentials,
                                 expiration_dt=thirty_from_now)

    session = Session()
    session.add(credential)
    session.commit()

    return credentials


@pytest.fixture(scope='module')
def walter_credentials(request, walter, clear_walter_cached_credentials):
    password = "vietnam"
    cc = CryptContext(["bcrypt_sha256"])
    credentials = cc.encrypt(password)
    thirty_from_now = datetime.datetime.now() + datetime.timedelta(days=30)
    credential = CredentialModel(user_id=walter.pk_id,
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
def clear_jackie_cached_authz_info(cache_handler, request):
    def remove_jackie_authz_info():
        nonlocal cache_handler
        cache_handler.delete(domain="authz_info",
                             identifier='jackie')

    request.addfinalizer(remove_jackie_authz_info)


@pytest.fixture(scope='module')
def clear_walter_cached_authz_info(cache_handler, request):
    def remove_walter_authz_info():
        nonlocal cache_handler
        cache_handler.delete(domain="authz_info",
                             identifier='walter')

    request.addfinalizer(remove_walter_authz_info)


@pytest.fixture(scope='module')
def authz_info(request, cache_handler, thedude, jackie, walter,
               clear_cached_authz_info, clear_jackie_cached_authz_info,
               clear_walter_cached_authz_info):

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


@pytest.fixture(scope='module')
def thedude_testpermissions(authz_info, permission_resolver):
    perm1 = permission_resolver('money:write:bankcheck_19911109069')
    perm2 = permission_resolver('money:withdrawal')
    perm3 = permission_resolver('leatherduffelbag:transport:theringer')
    perm4 = permission_resolver('leatherduffelbag:access:theringer')

    perms = [perm1, perm2, perm3, perm4]

    expected_results = frozenset([(perm1, True), (perm2, False),
                                  (perm3, True), (perm4, False)])

    return dict(perms=perms, expected_results=expected_results)


@pytest.fixture(scope='module')
def thedude_testroles(authz_info):
    roles = {'bankcustomer', 'courier', 'gangster'}

    expected_results = frozenset([(SimpleRole('bankcustomer'), True),
                                  (SimpleRole('courier'), True),
                                  (Simplerole('gangster'), False)])

    return dict(roles=roles, expected_results=expected_results)


@pytest.fixture(scope='module')
def jackie_testpermissions(authz_info, permission_resolver):

    perm1 = permission_resolver('money:access:ransom')
    perm2 = permission_resolver('leatherduffelbag:access:theringer')
    perm3 = permission_resolver('money:withdrawal')

    perms = [perm1, perm2, perm3]

    expected_results = frozenset([(perm1, True), (perm2, True),
                                  (perm3, False)])

    return dict(perms=perms, expected_results=expected_results)


@pytest.fixture(scope='module')
def walter_testpermissions(authz_info, permission_resolver):

    perm1 = permission_resolver('leatherduffelbag:transport:theringer')
    perm2 = permission_resolver('leatherduffelbag:access:theringer')
    perm3 = permission_resolver('*:bowl:*')

    perms = [perm1, perm2, perm3]

    expected_results = frozenset([(perm1, True), (perm2, False),
                                  (perm3, True)])

    return dict(perms=perms, expected_results=expected_results)
