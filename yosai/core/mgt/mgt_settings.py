from yosai.core import (
    maybe_resolve,
)


class SecurityManagerSettings:
    """
    SecurityManagerSettings is a settings proxy.  It is new for Yosai.
    It obtains security-manager related configuration from Yosai's global
    settings, defaulting values when necessary.

    The format of realm settings is:
        {'name_of_realm':
            {'cls': 'location to realm class',
             'account_store': 'location to realm account_store class'}}

        - 'name of realm' is a label used for internal tracking
        - 'cls' and 'account_store' are static key names and are not to be changed
        - the location of classes should follow dotted notation: pkg.module.class
    """
    def __init__(self, settings):
        mgt_config = settings.MGT_CONFIG
        self.default_cipher_key = mgt_config.get('default_cipher_key')
        manager_config = settings.SECURITY_MANAGER
        self.default_realm = {'account_store_realm':
                              {'cls': 'yosai.core.AccountStoreRealm',
                               'account_store': 'yosai_alchemystore.AlchemyAccountStore'}}
        self.cache_handler = manager_config.get('cache_handler',
                                                'yosai_dpcache.cache.DPCacheHandler')
        self.security_manager = manager_config.get('security_manager',
                                                   'yosai.core.DefaultSecurityManager')
        self.session_attributes_schema = manager_config.get('session_attributes_schema')
        self.realms = self.create_realms()

    def create_realms(self):
        realms = []

        try:
            realm_config = self.manager_config['realm']

            for realm in realm_config.keys():
                realm_cls = maybe_resolve(realm_config[realm]['cls'])
                account_store_cls = maybe_resolve(realm_config[realm]['account_store'])
                realms.append(realm_cls(account_store_cls()))
            realms = tuple(realms)  # make it immutable

        except KeyError:
            realm_config = self.default_realm
            realm_cls = maybe_resolve(realm_config[realm]['cls'])
            account_store_cls = maybe_resolve(realm_config[realm]['account_store'])
            realms.append(realm_cls(account_store_cls()))
            realms = tuple(realms)  # make it immutable

        return realms

    def __repr__(self):
        return ("SecurityManagerSettings(security_manager={0}, cache_handler={1},"
                "session_attributes_schema={2}, realms={3}, default_cipher_key={4})".
                format(self.security_manager, self.cache_handler,
                       self.session_attributes_schema, self.realms,
                       self.default_cipher_key))
