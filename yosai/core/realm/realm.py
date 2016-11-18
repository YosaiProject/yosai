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
import logging
from uuid import uuid4
import time
import rapidjson
from yosai.core import (
    AccountException,
    ConsumedTOTPToken,
    DefaultPermission,
    IncorrectCredentialsException,
    LockedAccountException,
    SimpleIdentifierCollection,
    TOTPToken,
    realm_abcs,
)

logger = logging.getLogger(__name__)


class AccountStoreRealm(realm_abcs.TOTPAuthenticatingRealm,
                        realm_abcs.AuthorizingRealm,
                        realm_abcs.LockingRealm):
    """
    A Realm interprets information from a datastore.

    Differences between yosai.core.and shiro include:
        1) yosai.core.uses two AccountStoreRealm interfaces to specify authentication
           and authorization
        2) yosai.core.includes support for authorization within the AccountStoreRealm
            - as of shiro v2 alpha rev1693638, shiro doesn't (yet)
    """

    def __init__(self,
                 name='AccountStoreRealm_' + str(uuid4()),
                 account_store=None,
                 authc_verifiers=None):
        """
        :authc_verifiers: tuple of Verifier objects
        """
        self.name = name
        self.account_store = account_store
        self.authc_verifiers = authc_verifiers

        self.cache_handler = None
        self.token_resolver = self.init_token_resolution()

    @property
    def supported_authc_tokens(self):
        """
        :rtype: list
        :returns: a list of authentication token classes supported by the realm
        """
        return self.token_resolver.keys()

    def supports(self, token):
        return token.__class__ in self.token_resolver

    def init_token_resolution(self):
        token_resolver = {}
        for verifier in self.authc_verifiers:
            for token_cls in verifier.supported_tokens:
                token_resolver[token_cls] = verifier
        return token_resolver

    def do_clear_cache(self, identifier):
        """
        :param identifier: the identifier of a specific source, extracted from
                           the SimpleIdentifierCollection (identifiers)
        """
        msg = "Clearing cache for: " + str(identifier)
        logger.debug(msg)

        self.clear_cached_authc_info(identifier)
        self.clear_cached_authorization_info(identifier)

    def clear_cached_authc_info(self, identifier):
        """
        When cached credentials are no longer needed, they can be manually
        cleared with this method.  However, account credentials may be
        cached with a short expiration time (TTL), making the manual clearing
        of cached credentials an alternative use case.

        :param identifier: the identifier of a specific source, extracted from
                           the SimpleIdentifierCollection (identifiers)
        """
        msg = "Clearing cached authc_info for [{0}]".format(identifier)
        logger.debug(msg)

        self.cache_handler.delete('authentication:' + self.name, identifier)

    def clear_cached_authorization_info(self, identifier):
        """
        This process prevents stale authorization data from being used.
        If any authorization data for an account is changed at runtime, such as
        adding or removing roles and/or permissions, the subclass implementation
        of AccountStoreRealm should clear the cached AuthorizationInfo for that
        account through this method. This ensures that the next call to
        get_authorization_info(PrincipalCollection) will acquire the account's
        fresh authorization data, which is cached for efficient re-use.

        :param identifier: the identifier of a specific source, extracted from
                           the SimpleIdentifierCollection (identifiers)
        """
        msg = "Clearing cached authz_info for [{0}]".format(identifier)
        logger.debug(msg)
        self.cache_handler.delete('authorization:' + self.name, identifier)

    def lock_account(self, identifier):
        """
        :type account: Account
        """
        locked_time = int(time.time() * 1000)  # milliseconds
        self.account_store.lock_account(identifier, locked_time)

    def unlock_account(self, identifier):
        """
        :type account: Account
        """
        self.account_store.unlock_account(identifier)

    # --------------------------------------------------------------------------
    # Authentication
    # --------------------------------------------------------------------------

    def get_authentication_info(self, identifier):
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
        account_info = None
        ch = self.cache_handler

        def query_authc_info(self):
            msg = ("Could not obtain cached credentials for [{0}].  "
                   "Will try to acquire credentials from account store."
                   .format(identifier))
            logger.debug(msg)

            # account_info is a dict
            account_info = self.account_store.get_authc_info(identifier)

            if account_info is None:
                msg = "Could not get stored credentials for {0}".format(identifier)
                raise ValueError(msg)

            return account_info

        try:
            msg2 = ("Attempting to get cached credentials for [{0}]"
                    .format(identifier))
            logger.debug(msg2)

            # account_info is a dict
            account_info = ch.get_or_create(domain='authentication:' + self.name,
                                            identifier=identifier,
                                            creator_func=query_authc_info,
                                            creator=self)

        except AttributeError:
            # this means the cache_handler isn't configured
            account_info = query_authc_info(self)
        except ValueError:
            msg3 = ("No account credentials found for identifiers [{0}].  "
                    "Returning None.".format(identifier))
            logger.warning(msg3)

        if account_info:
            account_info['account_id'] = SimpleIdentifierCollection(source_name=self.name,
                                                                    identifier=identifier)
        return account_info

    def authenticate_account(self, authc_token):
        """
        :type authc_token: authc_abcs.AuthenticationToken
        :rtype: dict
        :raises IncorrectCredentialsException:  when authentication fails
        """
        try:
            identifier = authc_token.identifier
        except AttributeError:
            msg = 'Failed to obtain authc_token.identifiers'
            raise AttributeError(msg)

        tc = authc_token.__class__
        try:
            verifier = self.token_resolver[tc]
        except KeyError:
            raise TypeError('realm does not support token type: ', tc.__name__)

        account = self.get_authentication_info(identifier)

        try:
            if account.get('account_locked'):
                msg = "Account Locked:  {0} locked at: {1}".\
                    format(account['account_id'], account['account_locked'])
                raise LockedAccountException(msg)
        except (AttributeError, TypeError):
            if not account:
                msg = "Could not obtain account credentials for: " + str(identifier)
                raise AccountException(msg)

        self.assert_credentials_match(verifier, authc_token, account)

        return account

    def update_failed_attempt(self, authc_token, account):
        cred_type = authc_token.token_info['cred_type']

        attempts = account['authc_info'][cred_type].get('failed_attempts', [])
        attempts.append(int(time.time() * 1000))
        account['authc_info'][cred_type]['failed_attempts'] = attempts

        self.cache_handler.set(domain='authentication:' + self.name,
                               identifier=authc_token.identifier,
                               value=account)
        return account

    def assert_credentials_match(self, verifier, authc_token, account):
        """
        :type verifier: authc_abcs.CredentialsVerifier
        :type authc_token: authc_abcs.AuthenticationToken
        :type account:  account_abcs.Account
        :returns: account_abcs.Account
        :raises IncorrectCredentialsException:  when authentication fails,
                                                including unix epoch timestamps
                                                of recently failed attempts
        """
        cred_type = authc_token.token_info['cred_type']

        try:
            verifier.verify_credentials(authc_token, account['authc_info'])
        except IncorrectCredentialsException:
            updated_account = self.update_failed_attempt(authc_token, account)

            failed_attempts = updated_account['authc_info'][cred_type].\
                get('failed_attempts', [])

            raise IncorrectCredentialsException(failed_attempts)
        except ConsumedTOTPToken:
            account['authc_info'][cred_type]['consumed_token'] = authc_token.credentials
            self.cache_handler.set(domain='authentication:' + self.name,
                                   identifier=authc_token.identifier,
                                   value=account)

    def generate_totp_token(self, account):
        try:
            stored_totp_key = account['authc_info']['totp_key']['credential']
        except KeyError:
            identifier = account['account_id'].primary_identifier
            account = self.get_authentication_info(identifier)
            stored_totp_key = account['authc_info']['totp_key']['credential']

        verifier = self.token_resolver[TOTPToken]
        return verifier.generate_totp_token(stored_totp_key)

    # --------------------------------------------------------------------------
    # Authorization
    # --------------------------------------------------------------------------

    def get_authzd_permissions(self, identifier, perm_domain):
        """
        :type identifier:  str
        :type domain:  str

        :returns: a list of relevant DefaultPermission instances (permission_s)
        """
        permission_s = []
        related_perms = []
        keys = ['*', perm_domain]

        def query_permissions(self):
            msg = ("Could not obtain cached permissions for [{0}].  "
                   "Will try to acquire permissions from account store."
                   .format(identifier))
            logger.debug(msg)

            permissions = self.account_store.get_authz_permissions(identifier)
            if not permissions:
                msg = "Could not get permissions from account_store for {0}".\
                    format(identifier)
                raise ValueError(msg)
            return permissions

        try:
            msg2 = ("Attempting to get cached authz_info for [{0}]"
                    .format(identifier))
            logger.debug(msg2)

            domain = 'authorization:permissions:' + self.name

            related_perms = self.cache_handler.\
                hmget_or_create(domain=domain,
                                identifier=identifier,
                                keys=keys,
                                creator_func=query_permissions,
                                creator=self)
        except ValueError:
            msg3 = ("No permissions found for identifiers [{0}].  "
                    "Returning None.".format(identifier))
            logger.warning(msg3)

        except AttributeError:
            # this means the cache_handler isn't configured
            queried_permissions = query_permissions(self)

            related_perms = [queried_permissions.get('*'),
                             queried_permissions.get(perm_domain)]

        for perms in related_perms:
            # must account for None values:
            try:
                for parts in rapidjson.loads(perms):
                    permission_s.append(DefaultPermission(parts=parts))
            except (TypeError, ValueError):
                pass

        return permission_s

    def get_authzd_roles(self, identifier):
        roles = [] 

        def query_roles(self):
            msg = ("Could not obtain cached roles for [{0}].  "
                   "Will try to acquire roles from account store."
                   .format(identifier))
            logger.debug(msg)

            roles = self.account_store.get_authz_roles(identifier)
            if not roles:
                msg = "Could not get roles from account_store for {0}".\
                    format(identifier)
                raise ValueError(msg)
            return roles
        try:
            msg2 = ("Attempting to get cached roles for [{0}]"
                    .format(identifier))
            logger.debug(msg2)

            roles = self.cache_handler.get_or_create(
                domain='authorization:roles:' + self.name,
                identifier=identifier,
                creator_func=query_roles,
                creator=self)
        except AttributeError:
            # this means the cache_handler isn't configured
            roles = query_roles(self)
        except ValueError:
            msg3 = ("No roles found for identifiers [{0}].  "
                    "Returning None.".format(identifier))
            logger.warning(msg3)

        return set(roles)

    def is_permitted(self, identifiers, permission_s):
        """
        If the authorization info cannot be obtained from the accountstore,
        permission check tuple yields False.

        :type identifiers:  subject_abcs.IdentifierCollection

        :param permission_s: a collection of one or more permissions, represented
                             as string-based permissions or Permission objects
                             and NEVER comingled types
        :type permission_s: list of string(s)

        :yields: tuple(Permission, Boolean)
        """
        identifier = identifiers.primary_identifier

        for required_perm in permission_s:

            required_permission = DefaultPermission(wildcard_string=required_perm)

            # get_authzd_permissions returns a list of DefaultPermission instances,
            # requesting from cache using '*' and permission.domain as hash keys:
            domain = next(iter(required_permission.domain))
            assigned_permission_s = self.get_authzd_permissions(identifier, domain)

            is_permitted = False
            for authorized_permission in assigned_permission_s:
                if authorized_permission.implies(required_permission):
                    is_permitted = True
                    break
            yield (required_perm, is_permitted)

    def has_role(self, identifiers, required_role_s):
        """
        Confirms whether a subject is a member of one or more roles.

        If the authorization info cannot be obtained from the accountstore,
        role check tuple yields False.

        :type identifiers:  subject_abcs.IdentifierCollection

        :param required_role_s: a collection of 1..N Role identifiers
        :type required_role_s: Set of String(s)

        :yields: tuple(role, Boolean)
        """
        identifier = identifiers.primary_identifier

        # assigned_role_s is a set
        assigned_role_s = self.get_authzd_roles(identifier)

        if not assigned_role_s:
            msg = 'has_role:  no roles obtained from account_store for [{0}]'.\
                format(identifier)
            logger.warning(msg)
            for role in required_role_s:
                yield (role, False)
        else:
            for role in required_role_s:
                hasrole = ({role} <= assigned_role_s)
                yield (role, hasrole)
