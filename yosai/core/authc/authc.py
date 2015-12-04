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

from marshmallow import Schema, fields, post_load

from yosai.core import (
    AccountException,
    AuthenticationException,
    AuthenticationEventException,
    Event,
    InvalidTokenPasswordException,
    LogManager,
    MissingPrivateSaltException,
    PasswordMatchException,
    PreparePasswordException,
    RealmAttributesException,  # new in Yosai
    settings,
    UnknownAccountException,
    UnsupportedTokenException,
    YosaiException,
    event_abcs,
    authc_abcs,
    serialize_abcs,
    AuthenticationSettings,
    CryptContextFactory,
    FirstRealmSuccessfulStrategy,
    DefaultAuthenticationAttempt,
    authc_settings,
)

class UsernamePasswordToken(authc_abcs.HostAuthenticationToken,
                            authc_abcs.RememberMeAuthenticationToken):

    def __init__(self, username, password, remember_me=False,
                 host=None):
        """
        :param username: the username submitted for authentication
        :type username: str
        :param password: the password submitted for authentication
        :type password: bytearray
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
        self.username = None
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


class DefaultAuthenticator(authc_abcs.Authenticator, event_abcs.EventBusAware):

    # Unlike Shiro, Yosai injects the strategy and the eventbus
    def __init__(self, strategy=FirstRealmSuccessfulStrategy()):
        """ Default in Shiro 2.0 is 'first successful'. This is the desired
        behavior for most Shiro users (80/20 rule).  Before v2.0, was
        'at least one successful', which was often not desired and caused
        unnecessary I/O.  """
        self.authentication_strategy = strategy
        self.realms = None  # this gets set by DefaultSecurityManager as a tuple
        self._event_bus = None

    @property
    def event_bus(self):
        return self._event_bus

    @event_bus.setter
    def event_bus(self, eventbus):
        self._event_bus = eventbus

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

            # log here
            msg = ("Authentication submission received for authentication "
                   "token [" + str(authc_token) + "]")
            print(msg)

            try:
                account = self.do_authenticate_account(authc_token)
                if (account is None):
                    msg2 = ("No account returned by any configured realms for "
                            "submitted authentication token [{0}]".
                            format(authc_token))

                    raise UnknownAccountException(msg2)

            except Exception as ex:
                print('ex is: ', ex)
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
                except Exception as ex:
                    msg4 = ("Unable to send notification for failed "
                            "authentication attempt - listener error?.  "
                            "Please check your EventBus implementation.  "
                            "Logging 'send' exception  and propagating "
                            "original AuthenticationException instead...")
                    # log warn here
                    print(msg4)
                raise ae

            # log here
            msg5 = ("Authentication successful for submitted authentication "
                    "token [{0}].  Returned account [{1}]".
                    format(authc_token, account))
            print(msg5)

            self.notify_success(authc_token, account)

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

    def notify_success(self, authc_token, account):
        try:
            event = Event(source=self.__class__.__name__,
                          event_topic='AUTHENTICATION.SUCCEEDED',
                          authc_token=authc_token,
                          account=account)
            self.event_bus.publish(event.event_topic, event=event)
        except AttributeError:
            msg = "Could not publish AUTHENTICATION.SUCCEEDED event"
            raise AuthenticationEventException(msg)

    def notify_failure(self, authc_token, throwable):
        try:
            event = Event(source=self.__class__.__name__,
                          event_topic='AUTHENTICATION.FAILED',
                          authc_token=authc_token,
                          throwable=throwable)
            self.event_bus.publish(event.event_topic, event=event)
        except AttributeError:
            msg = "Could not publish AUTHENTICATION.FAILED event"
            raise AuthenticationEventException(msg)

    # --------------------------------------------------------------------------

    def __repr__(self):
        return "<DefaultAuthenticator(event_bus={0}, strategy={0})>".\
            format(self.event_bus, self.authentication_strategy)


class AbstractAuthcService:
    # this class is new to Yosai
    def __init__(self):
        # using default algorithm when generating crypt context:
        self.crypt_context = CryptContextFactory(authc_settings).\
            create_crypt_context()
        self.private_salt = bytearray(authc_settings.private_salt, 'utf-8')

    def clear_source(self, source):
        try:
            for index in range(len(source)):
                source[index] = 0  # this becomes 0x00
        except TypeError:
            msg = 'Expected a bytearray source'
            raise InvalidTokenPasswordException(msg)

    def prepare_password(self, source):
        """
          A few differences between Shiro and Yosai regarding salts:
          1) Shiro generates its own public salt whereas Yosai defers salt
             creation to passlib
          2) Shiro concatenates the PUBLIC SALT with its PRIVATE SALT (pepper).
             Unlike Shiro, Yosai isn't peppering.
          3) to minimize copies of the password in memory, 'source' is
             cleared from memory the moment it is prepared

        :type source: bytearray
        """

        if (isinstance(source, bytearray)):
            credential = bytes(source)

            # the moment you no longer need a password, clear it because
            # it is a lingering copy in memory -- prepared_pass remains
            self.clear_source(source)

        else:
            msg = "could not prepare password -- must use bytearrays"
            raise PreparePasswordException(msg)

        return credential


class DefaultHashService(AbstractAuthcService):

    def __init__(self):
        super().__init__()

    def compute_hash(self, source):
        """
        note that Yosai omits HashRequest overhead used in Shiro
        :returns: dict
        """

        # Shiro's SimpleHash functionality is replaced by that of passlib's
        # CryptoContext API.  With that given, rather than return a SimpleHash
        # object from this compute method, Yosai now simply returns a dict
        result = {}
        prepared_bytes = self.prepare_password(source)
        result['ciphertext'] = bytearray(
            self.crypt_context.encrypt(prepared_bytes), 'utf-8')
        result['config'] = self.crypt_context.to_dict()

        return result  # DG:  this design is unique to Yosai, not Shiro

    def __repr__(self):
        return "<{0}(crypt_context={1})>".\
            format(self.__class__.__name__, self.crypt_context)

    # DG: removed combine method

# DG omitted HashRequest definition


class DefaultPasswordService(AbstractAuthcService):

    def __init__(self):
        super().__init__()
        # in Yosai, hash formatting is taken care of by passlib

    def passwords_match(self, password, saved):
        """
        :param password: the password requiring authentication, passed by user
        :type password: bytearray
        :param saved: the password saved for the corresponding account, in
                      the MCF Format as created by passlib

        :returns: a Boolean confirmation of whether plaintext equals saved

        Unlike Shiro:
            - Yosai expects saved to be a str and never a binary Hash
            - passlib determines the format and compatability
        """
        try:
            prepared_pass = self.prepare_password(password)  # s/b bytes
            return self.crypt_context.verify(prepared_pass, saved)

        except (AttributeError, TypeError):
            raise PasswordMatchException('unrecognized attribute type')


class Credential(serialize_abcs.Serializable):

    def __init__(self, credential):
        self.credential = credential

    @classmethod
    def serialization_schema(cls):

        class SerializationSchema(Schema):
            credential = fields.String()

            @post_load
            def make_credential(self, data):
                mycls = Credential
                instance = mycls.__new__(mycls)
                instance.__dict__.update(data)
                return instance

        return SerializationSchema


class CredentialResolver(authc_abcs.CredentialResolver):

    # using dependency injection to define which Role class to use
    def __init__(self, credential_class):
        self.credential_class = credential_class

    def resolve(self, credential):
        """
        :type credential: String
        """
        pass  # never used 

    def __call__(self, credential):
        """
        :type credential: String
        """
        return self.credential_class(credential)

    def __repr__(self):
        return "CredentialResolver({0})".format(self.credential_class)
