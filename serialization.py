from yosai import DefaultPermission
from yosai import IndexedAuthorizationInfo
from yosai import SimpleRole
from yosai import SerializationManager
import pprint

perms = {DefaultPermission(domain={'domain1'}, action={'action1'}),
         DefaultPermission(domain={'domain2'}, action={'action1', 'action2'}),
         DefaultPermission(domain={'domain3'}, action={'action1', 'action2', 'action3'}, target={'target1'}),
         DefaultPermission(domain={'domain4'}, action={'action1', 'action2'}),
         DefaultPermission(domain={'domain4'}, action={'action3'}, target={'target1'}),
         DefaultPermission(wildcard_string='*:action5')}

roles = {SimpleRole(role_identifier='role1'), SimpleRole(role_identifier='role2'), SimpleRole(role_identifier='role3')}

authz_info = IndexedAuthorizationInfo(roles=roles, permissions=perms)

requested_permissions = ['domain3:action3', 
                         'domain10:action5:target1', 
                         'domain5:action1',
                         'domain2:action2']

requested_roles = {'role1', 'role2', 'role4'}

sm = SerializationManager()

pp = pprint.PrettyPrinter(indent=1)

pp.pprint(authz_info)

serialized = sm.serialize(authz_info)
deserialized = sm.deserialize(serialized)

pp.pprint(deserialized)

