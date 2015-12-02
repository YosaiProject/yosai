from yosai import (DefaultPermission, SimpleRole, IndexedAuthorizationInfo,
                   SerializationManager)

from yosai_dpcache.cache import DPCacheHandler

perms = {DefaultPermission(domain={'domain1'}, action={'action1'}),
         DefaultPermission(domain={'domain2'}, action={'action1', 'action2'}),
         DefaultPermission(domain={'domain3'}, action={'action1', 'action2', 'action3'}, target={'target1'}),
         DefaultPermission(domain={'domain4'}, action={'action1', 'action2'}),
         DefaultPermission(domain={'domain4'}, action={'action3'}, target={'target1'}),
         DefaultPermission(wildcard_string='*:action5')}

roles = {SimpleRole(role_identifier='role1'), SimpleRole(role_identifier='role2'), SimpleRole(role_identifier='role3')}

authz_info = IndexedAuthorizationInfo(roles=roles, permissions=perms)

ch = DPCacheHandler()


ch.get_or_create('authz_info', 'id123', lambda x: authz_info, object)


