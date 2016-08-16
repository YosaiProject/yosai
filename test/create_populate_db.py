from yosai_alchemystore import (
    init_engine,
    init_session,
    Base,
)

    
from yosai_alchemystore.models.models import (
    CredentialModel,
    UserModel,
    DomainModel,
    ActionModel,
    ResourceModel,
    PermissionModel,
    RoleModel,
    role_membership,
    role_permission,
)
import datetime
from sqlalchemy import case, func, distinct
from passlib.context import CryptContext
from yosai.core import LazySettings

settings = LazySettings(env_var='YOSAI_SETTINGS')
engine = init_engine(settings=settings)
Base.metadata.drop_all(engine)
Base.metadata.create_all(engine)
import pprint
pp = pprint.PrettyPrinter(indent=1)

Session = init_session(settings=settings)

# Please watch 'The Big Lebowski' so that you may understand the following data.
users = [UserModel(first_name='Jeffrey', last_name='Lebowski', identifier='thedude'),
         UserModel(first_name='Walter', last_name='Sobchak', identifier='walter'),
         UserModel(first_name='Larry', last_name='Sellers', identifier='larry'),
         UserModel(first_name='Jackie', last_name='Treehorn', identifier='jackie'),
         UserModel(first_name='Karl', last_name='Hungus', identifier='karl'),
         UserModel(first_name='Marty', last_name='Houston', identifier='marty')]

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
session.add_all(users + roles + domains + actions + resources)

users = dict((user.first_name+'_'+user.last_name, user) for user in session.query(UserModel).all())
domains = dict((domain.name, domain) for domain in session.query(DomainModel).all())
actions = dict((action.name, action) for action in session.query(ActionModel).all())
resources = dict((resource.name, resource) for resource in session.query(ResourceModel).all())
roles = dict((role.title, role) for role in session.query(RoleModel).all())

thirty_from_now = datetime.datetime.now() + datetime.timedelta(days=30)
print('thirty from now is:  ', thirty_from_now)

cc = CryptContext(schemes=['bcrypt_sha256'])
password = cc.encrypt('letsgobowling')

credentials = [CredentialModel(user_id=user.pk_id, 
                          credential=password,
                          expiration_dt=thirty_from_now) for user in users.values()]
session.add_all(credentials)


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

thedude = users['Jeffrey_Lebowski']
thedude.roles.extend([bankcustomer, courier, tenant])

walter = users['Walter_Sobchak']
walter.roles.extend([bankcustomer, courier])

marty = users['Marty_Houston']
marty.roles.extend([bankcustomer, landlord])

larry = users['Larry_Sellers']
larry.roles.extend([bankcustomer, thief])  # yes, I know, it's not confirmed

jackie = users['Jackie_Treehorn']
jackie.roles.extend([bankcustomer, thief])  # karl may be working for him-- close enough

karl = users['Karl_Hungus']
karl.roles.extend([bankcustomer, thief])

session.commit()

pp.pprint(karl.permissions)

def get_permissions_query(session, identifier_s):
    """
    :type identifier_s: list
    """
    thedomain = case([(DomainModel.name == None, '*')], else_=DomainModel.name)
    theaction = case([(ActionModel.name == None, '*')], else_=ActionModel.name)
    theresource = case([(ResourceModel.name == None, '*')], else_=ResourceModel.name)

    action_agg = func.group_concat(theaction.distinct())
    resource_agg = func.group_concat(theresource.distinct())

    return (session.query(thedomain + ':' + action_agg + ':' + resource_agg).
            select_from(UserModel).
            join(role_membership, UserModel.pk_id == role_membership.c.user_id).
            join(role_permission, role_membership.c.role_id == role_permission.c.role_id).
            join(PermissionModel, role_permission.c.permission_id == PermissionModel.pk_id).
            outerjoin(DomainModel, PermissionModel.domain_id == DomainModel.pk_id).
            outerjoin(ActionModel, PermissionModel.action_id == ActionModel.pk_id).
            outerjoin(ResourceModel, PermissionModel.resource_id == ResourceModel.pk_id).
            filter(UserModel.identifier.in_(identifier_s)).
            group_by(PermissionModel.domain_id, PermissionModel.resource_id))

#result = get_permissions_query(session, ['walter']).all()
#pp.pprint(result)
session.close()
