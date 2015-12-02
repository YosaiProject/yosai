from yosai import DefaultPermission
from yosai import IndexedAuthorizationInfo
from yosai import SerializationManager
from yosai import SimpleRole

from yosai_dpcache.cache.region import make_region
from proxy import SerializationProxy


perms = {DefaultPermission(domain={'domain1'}, action={'action1'}),
         DefaultPermission(domain={'domain2'}, action={'action1', 'action2'}),
         DefaultPermission(domain={'domain3'}, action={'action1', 'action2', 'action3'}, target={'target1'}),
         DefaultPermission(domain={'domain4'}, action={'action1', 'action2'}),
         DefaultPermission(domain={'domain4'}, action={'action3'}, target={'target1'}),
         DefaultPermission(wildcard_string='*:action5')}

roles = {SimpleRole(role_identifier='role1'), SimpleRole(role_identifier='role2'), SimpleRole(role_identifier='role3')}

authz_info = IndexedAuthorizationInfo(roles=roles, permissions=perms)

sm = SerializationManager()

region = make_region().configure('yosai_dpcache.redis', expiration_time=3600, arguments={'url': '127.0.0.1'}, wrap=[(SerializationProxy, sm.serialize, sm.deserialize)])

region.set('yosai:userid:dowwie:authz', authz_info, 20)


