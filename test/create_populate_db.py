from yosai_alchemystore import (
    init_engine,
    init_session,
    Base,
)


from yosai_alchemystore.models.models import (
    Credential,
    CredentialType,
    User,
    Domain,
    Action,
    Resource,
    Permission,
    Role,
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
users = [User(first_name='Jeffrey', last_name='Lebowski', identifier='thedude'),
         User(first_name='Walter', last_name='Sobchak', identifier='walter'),
         User(first_name='Larry', last_name='Sellers', identifier='larry'),
         User(first_name='Jackie', last_name='Treehorn', identifier='jackie'),
         User(first_name='Karl', last_name='Hungus', identifier='karl'),
         User(first_name='Marty', last_name='Houston', identifier='marty')]

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

credential_types = [CredentialType(title='password'),
                    CredentialType(title='totp_key')]

session = Session()
session.add_all(users + roles + domains + actions + resources + credential_types)

users = dict((user.first_name+'_'+user.last_name, user) for user in session.query(User).all())
domains = dict((domain.name, domain) for domain in session.query(Domain).all())
actions = dict((action.name, action) for action in session.query(Action).all())
resources = dict((resource.name, resource) for resource in session.query(Resource).all())
roles = dict((role.title, role) for role in session.query(Role).all())
cred_types =  dict((ct.title, ct) for ct in session.query(CredentialType).all())

thirty_from_now = datetime.datetime.now() + datetime.timedelta(days=30)
print('thirty from now is:  ', thirty_from_now)

cc = CryptContext(schemes=['bcrypt'])
password = cc.hash('letsgobowling')

totp_key = 'DP3RDO3FAAFUAFXQELW6OTB2IGM3SS6G'

thedude = users['Jeffrey_Lebowski']

passwords = [Credential(user_id=user.pk_id,
                          credential=password,
                          credential_type_id=cred_types['password'].pk_id,
                          expiration_dt=thirty_from_now) for user in users.values()]
thedude_totp_key = [Credential(user_id=thedude.pk_id,
                          credential=totp_key,
                          credential_type_id=cred_types['totp_key'].pk_id,
                          expiration_dt=thirty_from_now)]
session.add_all(passwords + thedude_totp_key)


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
    thedomain = case([(Domain.name == None, '*')], else_=Domain.name)
    theaction = case([(Action.name == None, '*')], else_=Action.name)
    theresource = case([(Resource.name == None, '*')], else_=Resource.name)

    action_agg = func.group_concat(theaction.distinct())
    resource_agg = func.group_concat(theresource.distinct())

    return (session.query(thedomain + ':' + action_agg + ':' + resource_agg).
            select_from(User).
            join(role_membership, User.pk_id == role_membership.c.user_id).
            join(role_permission, role_membership.c.role_id == role_permission.c.role_id).
            join(Permission, role_permission.c.permission_id == Permission.pk_id).
            outerjoin(Domain, Permission.domain_id == Domain.pk_id).
            outerjoin(Action, Permission.action_id == Action.pk_id).
            outerjoin(Resource, Permission.resource_id == Resource.pk_id).
            filter(User.identifier.in_(identifier_s)).
            group_by(Permission.domain_id, Permission.resource_id))

#result = get_permissions_query(session, ['walter']).all()
#pp.pprint(result)
session.close()
