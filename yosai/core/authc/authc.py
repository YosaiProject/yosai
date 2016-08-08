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

from yosai.core import (
    AuthenticationException,
    AuthenticationEventException,
    InvalidTokenPasswordException,
    UnknownAccountException,
    UnsupportedTokenException,
    event_abcs,
    authc_abcs,
    serialize_abcs,
    FirstRealmSuccessfulStrategy,
    DefaultAuthenticationAttempt,
    realm_abcs,
)

logger = logging.getLogger(__name__)


class UsernamePasswordToken(authc_abcs.HostAuthenticationToken,
                            authc_abcs.RememberMeAuthenticationToken):

    def __init__(self, username, password, remember_me=False,
                 host=None):
        """
        :param username: the username submitted for authentication
        :type username: str

        :param password: the password submitted for authentication
        :type password: bytearray or string

        :param remember_me:  if the user wishes their identity to be
                             remembered across sessions
        :type remember_me: bool
        :param host:     the host name or IP string from where the attempt
                         is occuring
        :type host: str
        """
        self.host = host
        self.password = password
        self.is_remember_me = remember_me
        self.username = username
        self.identifier = username  # used in public api  DG:  TBD - I Dont like
        self.credentials = password  # used in public apiDG:  TBD - I Dont like

    # DG:  these properties are required implementations of the abcs

    @property
    def host(self):
        return self._host

    @host.setter
    def host(self, host):
        self._host = host

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, password):
        if not password:
            raise InvalidTokenPasswordException('Password must be defined.')

        if isinstance(password, bytearray):
            self._password = password
        if isinstance(password, str):
            self._password = bytearray(password, 'utf-8')
        else:
            raise InvalidTokenPasswordException

    @property
    def is_remember_me(self):
        return self._is_remember_me

    @is_remember_me.setter
    def is_remember_me(self, isrememberme):
        self._is_remember_me = isrememberme

    @property
    def username(self):
        return self._username

    @username.setter
    def username(self, username):
        if not username:
            raise InvalidTokenPasswordException('Username must be defined.')

        self._username = username

    @property
    def identifier(self):
        return self._identifier

    @identifier.setter
    def identifier(self, identifier):
        self._identifier = identifier

    @property
    def credentials(self):
        return self._credentials

    @credentials.setter
    def credentials(self, credentials):
        self._credentials = credentials

    def clear(self):
        self.identifier = None
        self.host = None
        self.remember_me = False

        try:
            if (self._password):
                for index in range(len(self._password)):
                    self._password[index] = 0  # DG:  this equals 0x00
        except TypeError:
            msg = 'expected password to be a bytearray'
            raise InvalidTokenPasswordException(msg)

    def __repr__(self):
        result = "{0} - {1}, remember_me={2}".format(
            self.__class__.__name__, self.username, self.is_remember_me)
        if (self.host):
            result += ", ({0})".format(self.host)
        return result

# Yosai deprecates FailedAuthenticationEvent
# Yosai deprecates SuccessfulAuthenticationEvent


class DefaultAuthenticator(authc_abcs.Authenticator,
                           event_abcs.EventBusAware):

    # Unlike Shiro, Yosai injects the strategy and the eventbus
    def __init__(self, strategy=FirstRealmSuccessfulStrategy()):
        """ Default in Shiro 2.0 is 'first successful'. This is the desired
        behavior for most Shiro users (80/20 rule).  Before v2.0, was
        'at least one successful', which was often not desired and caused
        unnecessary I/O.  """
        self.authentication_strategy = strategy
        self._realms = None
        self._event_bus = None
        self._credential_resolver = None

    @property
    def event_bus(self):
        return self._event_bus

    @event_bus.setter
    def event_bus(self, eventbus):
        self._event_bus = eventbus

    @property
    def cache_invalidator(self):
        return self._cache_invalidator

    @cache_invalidator.setter
    def cache_invalidator(self, cacheinvalidator):
        self._cache_invalidator = cacheinvalidator

    @property
    def realms(self):
        return self._realms

    @realms.setter
    def realms(self, realms):
        """
        :type realms: Tuple
        """
        self._realms = tuple(realm for realm in realms
                             if isinstance(realm, realm_abcs.AuthenticatingRealm))
        self.register_cache_clear_listener()

    def authenticate_single_realm_account(self, realm, authc_token):
        if (not realm.supports(authc_token)):
            msg = ("Realm [{0}] does not support authentication token [{1}]."
                   "Please ensure that the appropriate Realm implementation "
                   "is configured correctly or that the realm accepts "
                   "AuthenticationTokens of this type.".format(realm,
                                                               authc_token))
            raise UnsupportedTokenException(msg)

        else:
            return realm.authenticate_account(authc_token)

    def authenticate_multi_realm_account(self, realms, authc_token):
        """
        :type realms: Tuple
        """
        attempt = DefaultAuthenticationAttempt(authc_token, realms)
        return self.authentication_strategy.execute(attempt)

    def authenticate_account(self, authc_token):

            msg = ("Authentication submission received for authentication "
                   "token [" + str(authc_token) + "]")
            logger.debug(msg)

            try:
                account = self.do_authenticate_account(authc_token)
                if (account is None):
                    msg2 = ("No account returned by any configured realms for "
                            "submitted authentication token [{0}]".
                            format(authc_token))

                    raise UnknownAccountException(msg2)

            except Exception as ex:
                ae = None
                if isinstance(ex, AuthenticationException):
                    ae = AuthenticationException()
                if ae is None:
                    """
                    Exception thrown was not an expected
                    AuthenticationException.  Therefore it is probably a
                    little more severe or unexpected.  So, wrap in an
                    AuthenticationException, log to warn, and propagate:
                    """
                    msg3 = ("Authentication failed for submitted token [" +
                            str(authc_token) + "].  Possible unexpected "
                            "error? (Typical or expected login exceptions "
                            "should extend from AuthenticationException).")
                    ae = AuthenticationException(msg3, ex)

                try:
                    self.notify_failure(authc_token, ae)
                except Exception:
                    if logger.getEffectiveLevel() <= logging.WARNING:
                        msg4 = ("Unable to send notification for failed "
                                "authentication attempt - listener error?.  "
                                "Please check your EventBus implementation.  "
                                "Logging 'send' exception  and propagating "
                                "original AuthenticationException instead...")
                        logger.warning(msg4, exc_info=True)
                raise ae

            msg5 = ("Authentication successful for submitted authentication "
                    "token [{0}].  Returned account [{1}]".
                    format(authc_token, account))
            logger.debug(msg5)

            self.notify_success(account)

            return account

    def do_authenticate_account(self, authc_token):

        if (not self.realms):
            msg = ("One or more realms must be configured to perform "
                   "authentication.")
            raise AuthenticationException(msg)

        if (len(self.realms) == 1):
            return self.authenticate_single_realm_account(
                next(iter(self.realms)), authc_token)

        return self.authenticate_multi_realm_account(self.realms, authc_token)

    # --------------------------------------------------------------------------
    # Event Communication
    # --------------------------------------------------------------------------

    def clear_cache(self, items=None):
        """
        expects event object to be in the format of a session-stop or
        session-expire event, whose results attribute is a
        namedtuple(identifiers, session_key)
        """
        try:
            for realm in self.realms:
                identifiers = items.identifiers
                realm_identifier = identifiers.from_source(realm.name)
                if realm_identifier:
                    realm.clear_cached_credentials(realm_identifier)
        except AttributeError:
            msg = ('Could not clear authc_info from cache after event. '
                   'items: ' + str(items))
            logger.warn(msg)

    def register_cache_clear_listener(self):
        if self.event_bus:
            self.event_bus.register(self.clear_cache, 'SESSION.EXPIRE')
            self.event_bus.is_registered(self.clear_cache, 'SESSION.EXPIRE')
            self.event_bus.register(self.clear_cache, 'SESSION.STOP')
            self.event_bus.is_registered(self.clear_cache, 'SESSION.STOP')

    def notify_success(self, account):
        try:
            self.event_bus.publish('AUTHENTICATION.SUCCEEDED',
                                   identifiers=account.account_id)
        except AttributeError:
            msg = "Could not publish AUTHENTICATION.SUCCEEDED event"
            raise AuthenticationEventException(msg)

    def notify_failure(self, authc_token, throwable):
        try:
            self.event_bus.publish('AUTHENTICATION.FAILED',
                                   username=authc_token.username)
        except AttributeError:
            msg = "Could not publish AUTHENTICATION.FAILED event"
            raise AuthenticationEventException(msg)

    # --------------------------------------------------------------------------

    def __repr__(self):
        return "<DefaultAuthenticator(event_bus={0}, strategy={0})>".\
            format(self.event_bus, self.authentication_strategy)


class Credential(serialize_abcs.Serializable):

    def __init__(self, credential):
        """
        :type credential: bytestring
        """
        self.credential = credential

    def __eq__(self, other):
        return self.credential == other.credential

    def __bool__(self):
        return bool(self.credential)

    def __getstate__(self):
        return {'credential': self.credential}

    def __setstate__(self, state):
        self.credential = state['credential']


class CredentialResolver(authc_abcs.CredentialResolver):

    # using dependency injection to define which Role class to use
    def __init__(self, credential_class):
        self.credential_class = credential_class

    def resolve(self, credential):
        """
        :type credential: String
        """
        return self.credential_class(credential)

    def __call__(self, credential):
        """
        :type credential: String
        """
        return self.credential_class(credential)

    def __repr__(self):
        return "CredentialResolver({0})".format(self.credential_class)
