from yosai.core import (
    maybe_resolve,
)


class RememberMeSettings:

    def __init__(self, settings):
        rmm_config = settings.REMEMBER_ME_CONFIG
        self.default_cipher_key = rmm_config.get('default_cipher_key')


class SecurityManagerSettings:
    """
    SecurityManagerSettings is a settings proxy.  It is new for Yosai.
    It obtains security-manager related configuration from Yosai's global
    settings, defaulting values when necessary.

    """
    def __init__(self, settings):
        manager_config = settings.SECURITY_MANAGER_CONFIG
        self.security_manager =\
            maybe_resolve(manager_config.get('security_manager',
                                             'yosai.core.DefaultSecurityManager'))
        self.attributes = self.resolve_attributes(manager_config.get('attributes'))

    def resolve_attributes(self, attributes):
        realms = self.resolve_realms(attributes)
        cache_handler = self.resolve_cache_handler(attributes)
        session_attributes_schema = self.resolve_session_attributes_schema(attributes)

        return {'realms': realms,
                'cache_handler': cache_handler,
                'session_attributes_schema': session_attributes_schema
                }

    def resolve_cache_handler(self, attributes):
        return maybe_resolve(attributes.get('cache_handler'))

    def resolve_session_attributes_schema(self, attributes):
        return maybe_resolve(attributes.get('session_attributes_schema'))

    def resolve_realms(self, attributes):
        """
        The format of realm settings is:
            {'name_of_realm':
                {'cls': 'location to realm class',
                 'account_store': 'location to realm account_store class'}}

            - 'name of realm' is a label used for internal tracking
            - 'cls' and 'account_store' are static key names and are not to be changed
            - the location of classes should follow dotted notation: pkg.module.class
        """
        realms = []

        for realm, account_store in self.attributes['realms'].items():
            realm_cls = maybe_resolve(realm)
            account_store_cls = maybe_resolve(account_store)
            realms.append([realm_cls, account_store_cls])

        return realms

    def __repr__(self):
        return ("SecurityManagerSettings(security_manager={0}, attributes={1})"".
                format(self.security_manager, self.attributes))
