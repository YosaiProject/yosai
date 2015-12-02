from yosai import DefaultPermission
from yosai import IndexedAuthorizationInfo
from yosai import SimpleRole
from yosai import AccountStoreRealm
from yosai import DefaultPermissionResolver
import pprint
from unittest import mock

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

with mock.patch('yosai.PasswordMatcher') as pm:
    pm.return_value = None

    with mock.patch.object(AccountStoreRealm, 'get_authorization_info') as gai:
        gai.return_value = authz_info

        asr = AccountStoreRealm()
        asr.permission_resolver = DefaultPermissionResolver() 

        print('\n\nis_permitted test')
        print('-' * 100)
        pp = pprint.PrettyPrinter(indent=1)
        print('permissions:')
        pp.pprint(perms)
        print('\n\nresults:')
        for x in asr.is_permitted('identifiers', requested_permissions):
            print(x)

        print('\nhas_role test')
        print('-' * 100)
        print('expected results:  role1 and role2 are True, role4 is False')
        for x in asr.has_role('identifiers', requested_roles):
            print(x)
    
        print('\nhas_all_roles tests')
        print('-' * 100)
        print('test one results should be:  False')
        print(asr.has_all_roles('identifiers', requested_roles))

        requested_roles = {'role1', 'role2'}
        print('test two results should be:  True')
        print(asr.has_all_roles('identifiers', requested_roles))
