import pytest

from yosai.core import (
    ModularRealmAuthorizer,
    event_bus,
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


@pytest.fixture(scope='module')
def modular_realm_authorizer(account_store_realm, permission_resolver,
                             role_resolver, authz_info_resolver):
    mra = ModularRealmAuthorizer()
    mra.realms = (account_store_realm,)
    mra.event_bus = event_bus
    mra.permission_resolver = permission_resolver
    mra.authz_info_resolver = authz_info_resolver
    mra.role_resolver = role_resolver
    return mra


@pytest.fixture(scope='module')
def clear_cached_authz_info(cache_handler, request):
    def remove_authz_info():
        nonlocal cache_handler
        cache_handler.delete(domain="authz_info",
                             identifier='thedude')

    request.addfinalizer(remove_authz_info)


@pytest.fixture(scope='module')
def thedude_authz_info(request, cache_handler, thedude,
                       clear_cached_authz_info):

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
