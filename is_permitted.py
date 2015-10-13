from yosai import DefaultPermission
from yosai import IndexedAuthorizationInfo
from yosai import SimpleRole
from yosai import AccountStoreRealm
from yosai import DefaultPermissionResolver

from unittest import mock

perms = {DefaultPermission(domain={'domain1'}, action={'action1'}),
         DefaultPermission(domain={'domain2'}, action={'action1', 'action2'}),
         DefaultPermission(domain={'domain3'}, action={'action1', 'action2', 'action3'}, target={'target1'}),
         DefaultPermission(domain={'domain4'}, action={'action1', 'action2'}),
         DefaultPermission(domain={'domain4'}, action={'action3'}, target={'target1'}),
         DefaultPermission(wildcard_string='*:action5')}

roles = {SimpleRole(name='role1'), SimpleRole(name='role2'), SimpleRole(name='role3')}

authz_info = IndexedAuthorizationInfo(roles=roles, permissions=perms)

requested_permissions = ['domain3:action3', 
                         'domain10:action5:target1', 
                         'domain5:action1',
                         'domain2:action2']

with mock.patch('yosai.PasswordMatcher') as pm:
    pm.return_value = None

    with mock.patch.object(AccountStoreRealm, 'get_authorization_info') as gai:
        gai.return_value = authz_info

        asr = AccountStoreRealm()
        asr.permission_resolver = DefaultPermissionResolver() 

        for x in asr.is_permitted('identifiers', requested_permissions):
            print(x)

