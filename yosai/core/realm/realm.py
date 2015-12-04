"""
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
"""

from yosai.core import (
    AccountStoreRealmAuthenticationException,
    AuthzInfoNotFoundException,
    CacheCredentialsException,
    ClearCacheCredentialsException,
    CredentialsNotFoundException,
    DefaultPermission,
    GetCachedCredentialsException,
    IdentifierMismatchException,
    InvalidArgumentException,
    IndexedAuthorizationInfo,
    IncorrectCredentialsException,
    IndexedPermissionVerifier,
    LogManager,
    PasswordVerifier,
    RealmMisconfiguredException,
    SimpleRole,
    SimpleRoleVerifier,
    UsernamePasswordToken,
    authz_abcs,
    cache_abcs,
    realm_abcs,
)


class AccountStoreRealm(realm_abcs.AuthenticatingRealm,
                        realm_abcs.AuthorizingRealm,
                        authz_abcs.AuthzInfoResolverAware,
                        cache_abcs.CacheHandlerAware,
                        authz_abcs.CredentialResolverAware,
                        authz_abcs.PermissionResolverAware,
                        authz_abcs.RoleResolverAware):
    """
    A Realm interprets information from a datastore.

    Differences between yosai.core.and shiro include:
        1) yosai.core.uses two AccountStoreRealm interfaces to specify authentication
           and authorization
        2) yosai.core.includes support for authorization within the AccountStoreRealm
            - as of shiro v2 alpha rev1693638, shiro doesn't (yet)
    """

    def __init__(self):
        #  DG:  this needs to be updated so that positional arguments
        #       are used to construct the object rather than mutator methods

        self.name = 'AccountStoreRealm' + str(id(self))  # DG:  replace later..
        self._account_store = None
        self._cache_handler = None

        # resolvers are setter-injected after init
        self._permission_resolver = None
        self._role_resolver = None
        self._credential_resolver = None
        self._authz_info_resolver = None

        # yosai.core.renamed credentials_matcher:
        self._credentials_verifier = PasswordVerifier()  # 80/20 rule: passwords

        self._permission_verifier = IndexedPermissionVerifier()
        self._role_verifier = SimpleRoleVerifier()

    @property
    def account_store(self):
        return self._account_store

    @account_store.setter
    def account_store(self, accountstore):
        self._account_store = accountstore

    @property
    def credentials_verifier(self):
        return self._credentials_verifier

    @credentials_verifier.setter
    def credentials_verifier(self, credentialsmatcher):
        self._credentials_verifier = credentialsmatcher

    @property
    def cache_handler(self):
        return self._cache_handler

    @cache_handler.setter
    def cache_handler(self, cachehandler):
        self._cache_handler = cachehandler

    @property
    def authz_info_resolver(self):
        return self._authz_info_resolver

    @authz_info_resolver.setter
    def authz_info_resolver(self, authz_info_resolver):
        self._authz_info_resolver = authz_info_resolver
        self.account_store.authz_info_resolver = authz_info_resolver

    @property
    def credential_resolver(self):
        return self._credential_resolver

    @credential_resolver.setter
    def credential_resolver(self, credentialresolver):
        self._credential_resolver = credentialresolver
        self.account_store.credential_resolver = credentialresolver

    @property
    def permission_resolver(self):
         self._permission_resolver

    @permission_resolver.setter
    def permission_resolver(self, permissionresolver):
        # passes through realm and onto the verifier that actually uses it
        self._permission_resolver = permissionresolver
        self.permission_verifier.permission_resolver = permissionresolver
        self.account_store.permission_resolver = permissionresolver

    @property
    def role_resolver(self):
        return self._role_resolver

    @role_resolver.setter
    def role_resolver(self, roleresolver):
        # passes through realm and onto the verifier that actually uses it
        self._role_resolver = roleresolver
        self.account_store.role_resolver = roleresolver

    @property
    def permission_verifier(self):
        return self._permission_verifier

    @permission_verifier.setter
    def permission_verifier(self, verifier):
        self._permission_verifier = verifier

    @property
    def role_verifier(self):
        return self._role_verifier

    @role_verifier.setter
    def role_verifier(self, verifier):
        self._role_verifier = verifier

    def do_clear_cache(self, identifier_s):
        msg = "Clearing cache for: " + str(identifier_s)
        print(msg)
        # log info here

        self.clear_cached_credentials(identifier_s)
        self.clear_cached_authorization_info(identifier_s)

    def clear_cached_credentials(self, identifier_s):
        """
        When cached credentials are no longer needed, they can be manually
        cleared with this method.  However, account credentials should be
        cached with a short expiration time (TTL), making the manual clearing
        of cached credentials an alternative use case.
        """
        self.cache_handler.delete('credentials', identifier_s)

    def clear_cached_authorization_info(self, identifier_s):
        """
        This process prevents stale authorization data from being used.
        If any authorization data for an account is changed at runtime, such as
        adding or removing roles and/or permissions, the subclass implementation
        of AccountStoreRealm should clear the cached AuthorizationInfo for that
        account through this method. This ensures that the next call to
        get_authorization_info(PrincipalCollection) will acquire the account's
        fresh authorization data, which is cached for efficient re-use.
        """
        self.cache_handler.delete('authz_info', identifier_s)

    # --------------------------------------------------------------------------
    # Authentication
    # --------------------------------------------------------------------------

    # removed the basic accessor/mutator methods (not pythonic)
    def supports(self, authc_token):
        # override the following return to False if you do not wish to support
        # authentication from this realm
        return isinstance(authc_token, UsernamePasswordToken)

    def get_credentials(self, identifier):
        """
        The default authentication caching policy is to cache an account's
        credentials that are queried from an account store, for a specific
        user, so to facilitate any subsequent authentication attempts for
        that user. Naturally, in order to cache one must have a CacheHandler.
        If a user were to fail to authenticate, perhaps due to an
        incorrectly entered password, during the the next authentication
        attempt (of that user id) the cached account will be readily
        available from cache and used to match credentials, boosting
        performance.

        :returns: an Account object
        """
        account = None
        ch = self.cache_handler

        try:
            def get_stored_credentials(self):
                msg = ("Could not obtain cached credentials for [{0}].  "
                       "Will try to acquire credentials from account store."
                       .format(identifier))
                # log here (debug)
                print(msg)
                account = self.account_store.get_credentials(identifier)
                if account is None:
                    msg = "Could not get credentials for {0}".format(identifier)
                    raise CredentialsNotFoundException(msg)
                return account.credentials

            try:
                msg2 = ("Attempting to get cached credentials for [{0}]"
                        .format(identifier))
                # log here (debug)
                print(msg2)
                account = ch.get_or_create(domain='credentials',
                                           identifier=identifier,
                                           creator_func=get_stored_credentials,
                                           creator=self)
            except CredentialsNotFoundException:
                # log here
                msg3 = ("No account credentials found for identifier [{0}].  "
                        "Returning None.".format(identifier))
                print(msg3)

        except AttributeError:
            msg = ('AccountStoreRealm misconfigured.  At a minimum, '
                   'define an AccountStore and CacheHandler.')
            # log here (exception)
            raise RealmMisconfiguredException(msg)

        return account

    # yosai.core.refactors:
    def authenticate_account(self, authc_token):
        try:
            identifier = authc_token.identifier
        except AttributeError:
            msg = 'Failed to obtain authc_token.identifier'
            raise InvalidArgumentException(msg)

        account = self.get_credentials(identifier)

        self.assert_credentials_match(authc_token, account)

        # at this point, authentication is confirmed, so clear
        # the cache of credentials (however, they should have a short ttl anyway)
        self.clear_cached_credentials(identifier)
        return account

    def assert_credentials_match(self, authc_token, account):
        cm = self.credentials_verifier
        if (not cm.credentials_match(authc_token, account)):
            # not successful - raise an exception as signal:
            msg = ("Submitted credentials for token [" + str(authc_token) +
                   "] did not match the stored credentials.")
            # log here
            raise IncorrectCredentialsException(msg)

    # --------------------------------------------------------------------------
    # Authorization
    # --------------------------------------------------------------------------

    def get_authorization_info(self, identifier):
        """
        The default caching policy is to cache an account's authorization info,
        obtained from an account store so to facilitate subsequent authorization
        checks. In order to cache, a realm must have a CacheHandler.

        :returns: an AuthorizationInfo object
        """
        account = None
        ch = self.cache_handler

        try:
            def get_stored_authz_info(self):
                msg = ("Could not obtain cached authz_info for [{0}].  "
                       "Will try to acquire authz_info from account store."
                       .format(identifier))
                # log here (debug)
                print(msg)
                account = self.account_store.get_authz_info(identifier)
                if account is None:
                    msg = "Could not get authz_info for {0}".format(identifier)
                    raise AuthzInfoNotFoundException(msg)
                return account.authz_info

            try:
                msg2 = ("Attempting to get cached authz_info for [{0}]"
                        .format(identifier))
                # log here (debug)
                print(msg2)
                account = ch.get_or_create(domain='authz_info',
                                           identifier=identifier,
                                           creator_func=get_stored_authz_info,
                                           creator=self)
            except AuthzInfoNotFoundException:
                # log here
                msg3 = ("No account authz_info found for identifier [{0}].  "
                        "Returning None.".format(identifier))
                print(msg3)

        except AttributeError:
            msg = ('AccountStoreRealm misconfigured.  At a minimum, '
                   'define an AccountStore and CacheHandler.')
            # log here (exception)
            raise RealmMisconfiguredException(msg)

        return account

    def is_permitted(self, identifier_s, permission_s):
        """
        :param permission_s: a collection of one or more permissions, represented
                             as string-based permissions or Permission objects
                             and NEVER comingled
        :type permission_s: list of either String(s) or Permission(s)
        :yields: tuple(Permission, Boolean)
        """

        authz_info = self.get_authorization_info(identifier_s).authz_info
        yield from self.permission_verifier.is_permitted(authz_info,
                                                         permission_s)

    def has_role(self, identifier_s, roleid_s):
        """
        Confirms whether a subject is a member of one or more roles.

        :param roleid_s: a collection of 1..N Role identifier_s
        :type roleid_s: Set of String(s)

        :yields: tuple(roleid, Boolean)
        """
        authz_info = self.get_authorization_info(identifier_s).authz_info
        yield from self.role_verifier.has_role(authz_info, roleid_s)
