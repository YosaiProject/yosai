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

Session = init_session(settings=settings)

# Please watch 'The Big Lebowski' so that you may understand the following data.
users = [User(first_name='Jeffrey', last_name='Lebowski', identifier='thedude', phone_number='12123841000'),
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

cc = CryptContext(schemes=['argon2'])
password = cc.hash('letsgobowling')

totp_key = '{"enckey":{"c":14,"k":"CAEC5ELC3O7G3PSA55JLWLI2HM2ESMKW","s":"HQDWA3BNQXYP4PYH4COA","t":"1478866824532","v":1},"type":"totp","v":1}'

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

# ------------------------------------------------------------------------------
# The following data is for performance testing purposes
# ------------------------------------------------------------------------------

dumb_domains = [Domain(name='domain'+str(x)) for x in range(1, 10)]
dd_two =[Domain(name='domain11'), Domain(name='domain12'),
         Domain(name='domain13'), Domain(name='domain14')]
dumb_actions = [Action(name='action'+str(x)) for x in range(1, 5)]
dumb_resources = [Resource(name='resource'+str(x)) for x in range(1, 10)]
dr_two = [Resource(name='resource11'), Resource(name='resource12'), Resource(name='resource13')]
session.add_all(dumb_domains + dd_two + dumb_actions + dumb_resources + dr_two)
session.commit()
dumb_permissions = [Permission(domain=d, action=a, resource=r)
                    for d in dumb_domains for a in dumb_actions for r in dumb_resources]

dumb_wildcard_perms = [Permission(domain=dd_two[0], action=dumb_actions[0]),
                       Permission(domain=dd_two[0], action=dumb_actions[1]),
                       Permission(domain=dd_two[0], action=dumb_actions[2]),
                       Permission(domain=dd_two[1]),
                       Permission(domain=dd_two[2], resource=dr_two[0])]

other_perms = [Permission(domain=dd_two[3], action=dumb_actions[0]),
               Permission(domain=dd_two[3], action=dumb_actions[1]),
               Permission(domain=dd_two[3], resource=dumb_resources[2]),
               Permission(domain=dd_two[3], resource=dumb_resources[3]),
               Permission(domain=dd_two[3], action=dumb_actions[2], resource=dumb_resources[0])]

dumb_roles = [Role(title='role'+str(x)) for x in range(1, 10)]

dumb_perms = dumb_permissions + dumb_wildcard_perms + other_perms
session.add_all(dumb_perms + dumb_roles)

session.commit()
print('Added: ' + str(len(dumb_permissions)) + ' dumb permissions')
print('Added: ' + str(len(dumb_perms)) + ' total dumb permissions')
print('Added: ' + str(len(dumb_roles)) + ' dumb roles')

chunk_size = (len(dumb_permissions) // len(dumb_roles))
chunked_perms = [dumb_permissions[i: i + chunk_size]
                 for i in range(0, len(dumb_permissions), chunk_size)]

print('Chunked: ', sum(len(x) for x in chunked_perms))

for r in dumb_roles:
    r.permissions.extend(chunked_perms.pop())

more_actions = [Action(name='action121'), Action(name='action357'), Action(name='action189')]
more_perms = [Permission(action=x) for x in more_actions]

dumb_roles[0].permissions.extend(dumb_wildcard_perms + other_perms + more_perms)

thedude.roles.extend(r for r in dumb_roles)
walter.roles.extend(r for r in dumb_roles)

session.commit()


# ------------------------------------------------------------------------------
# End of performance testing data
# ------------------------------------------------------------------------------


session.close()
