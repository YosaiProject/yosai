from yosai.core import (
    maybe_resolve,
)


class RememberMeSettings:

    def __init__(self, settings):
        rmm_config = settings.REMEMBER_ME_CONFIG
        self.default_cipher_key = rmm_config.get('default_cipher_key').encode()


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
        serializer = attributes.get('serializer', 'cbor')
        realms = self.resolve_realms(attributes)
        cache_handler = self.resolve_cache_handler(attributes)
        session_attributes = self.resolve_session_attributes(attributes)

        return {'serializer': serializer,
                'realms': realms,
                'cache_handler': cache_handler,
                'session_attributes': session_attributes
                }

    def resolve_cache_handler(self, attributes):
        return maybe_resolve(attributes.get('cache_handler'))

    def resolve_session_attributes(self, attributes):
        return maybe_resolve(attributes.get('session_attributes'))

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

        for realm in attributes['realms'].items():
            realm_cls = maybe_resolve(realm)
            account_store_cls = maybe_resolve(realm['account_store'])

            verifiers = {}

            authc_verifiers = realm.get('authc_verifiers')
            if authc_verifiers:
                if isinstance(authc_verifiers, list):
                    authc_verifiers_cls = tuple(maybe_resolve(verifier) for
                                                verifier in authc_verifiers)
                else:
                    authc_verifiers_cls = tuple(maybe_resolve(authc_verifiers))
                verifiers['authc_verifiers'] = authc_verifiers_cls

            authz_verifiers = realm.get('authz_verifiers')
            if authz_verifiers:
                permission_verifier_cls = authz_verifiers.get('permission_verifier')
                if permission_verifier_cls:
                    verifiers['permission_verifier'] = permission_verifier_cls
                role_verifier_cls = authz_verifiers.get('role_verifier')
                if role_verifier_cls:
                    verifiers['role_verifier'] = role_verifier_cls

            realms.append([realm_cls, account_store_cls, verifiers])

        return realms

    def __repr__(self):
        return "SecurityManagerSettings(security_manager={0}, attributes={1})".\
            format(self.security_manager, self.attributes)
