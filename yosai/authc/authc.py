from yosai import (
    AuthenticationException,
    Event,
    EventBus,
    IEventBusAware,
    InvalidTokenPasswordException,
    LogManager,
    MissingPrivateSaltException,
    PasswordMatchException,
    PepperPasswordException,
    RealmAttributesException,  # new in Yosai
    settings,
    UnknownAccountException,
    UnsupportedTokenException,
    YosaiException,
)

from . import (
    AuthenticationSettings,
    CryptContextFactory,
    FirstRealmSuccessfulStrategy,
    DefaultAuthenticationAttempt,
    IAuthenticator,
    IHostAuthenticationToken,
    IRememberMeAuthenticationToken,
)


class UsernamePasswordToken(IHostAuthenticationToken,
                            IRememberMeAuthenticationToken,
                            object):

    def __init__(self, username=None, password=None, remember_me=False,
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
        self.principal = username  # used in public api  DG:  TBD - I Dont like
        self.credentials = password  # used in public apiDG:  TBD - I Dont like

    # DG:  these properties are required implementations of the interfaces

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
    def principal(self):
        return self._principal

    @principal.setter
    def principal(self, principal):
        self._principal = principal

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

        if (self.password):
            for index, value in enumerate(self.password):
                self.password[index] = 0  # DG:  this equals 0x00
        return self.password

    def __repr__(self):
        result = "{0} - {1}, remember_me={2}".format(
            self.__class__.__name__, self.username, self.is_remember_me)
        if (self.host):
            result += ", ({0})".format(self.host)
        return result

# Yosai deprecates FailedAuthenticationEvent
# Yosai deprecates SuccessfulAuthenticationEvent


class DefaultAuthenticator(IAuthenticator, IEventBusAware, object):

    def __init__(self):
        """ Default in Shiro 2.0 is 'first successful'. This is the desired 
        behavior for most Shiro users (80/20 rule).  Before v2.0, was
        'at least one successful', which was often not desired and caused
        unnecessary I/O.  """
        self.authentication_strategy = FirstRealmSuccessfulStrategy()
        self.realms = None
        self.event_bus = EventBus()

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
        # DG TBD: replace with a strategy factory and init dependency injection
        attempt = DefaultAuthenticationAttempt(authc_token,
                                               frozenset(realms))
        return self.authentication_strategy.execute(attempt)

    def authenticate_account(self, authc_token):

            # log here
            msg = ("Authentication submission received for authentication "
                   "token [" + authc_token + "]")
            print(msg)

            try:
                account = self.do_authenticate_account(authc_token)
                if (account is None):
                    msg2 = ("No account returned by any configured realms for "
                            "submitted authentication token [" + authc_token +
                            "].")
                    raise UnknownAccountException(msg2)

            except Exception as ex:
                ae = ex
                if (not isinstance(ae, AuthenticationException)):
                    """
                    Exception thrown was not an expected
                    AuthenticationException.  Therefore it is probably a
                    little more severe or unexpected.  So, wrap in an
                    AuthenticationException, log to warn, and propagate:
                    """
                    msg3 = ("Authentication failed for submitted token [" +
                            authc_token + "].  Possible unexpected "
                            "error? (Typical or expected login exceptions "
                            "should extend from AuthenticationException).")
                    ae = AuthenticationException(msg3, ex)

                try:
                    self.notify_failure(authc_token, ae)
                except Exception as ex:
                    # log here
                    msg4 = ("Unable to send notification for failed "
                            "authentication attempt - listener error?.  "
                            "Please check your EventBus implementation.  "
                            "Logging 'send' exception  and propagating "
                            "original AuthenticationException instead...")
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

    def notify_success(self, authc_token, account):
        if (self.event_bus):
            event = Event(source=self,
                          event_type='AUTHENTICATION',
                          event_topic='AUTHENTICATION.SUCCEEDED',
                          authc_token=authc_token,
                          account=account)
            self.event_bus.publish(event)

    def notify_failure(self, authc_token, throwable):
        if (self.event_bus):
            event = Event(source=self,
                          event_type='AUTHENTICATION',
                          event_topic='AUTHENTICATION.FAILED',
                          authc_token=authc_token,
                          throwable=throwable)
            self.event_bus.publish(event)


class DefaultAuthcService(object):
    def __init__(self):
        authc_settings = AuthenticationSettings()
        # using default algorithm when generating crypt context:
        self.crypt_context = CryptContextFactory(authc_settings).\
            create_crypt_context()
        self.private_salt = authc_settings.private_salt  # it's a string

    def pepper_password(self, source):
        """
          A few differences between Shiro and Yosai regarding salts:
          1) Shiro generates its own public salt whereas Yosai defers salt
             creation to passlib
          2) Shiro concatenates the PUBLIC SALT with its PRIVATE SALT (pepper).
             Unlike Shiro, Yosai concatenates the PRIVATE SALT with the
             PASSWORD (rather than a public salt).  The peppered password
             is salted by passlib according to the cryptcontext settings
             else default passlib settings.

        :type source: str
        """
        if (isinstance(source, str)):
            peppered_pass = self.private_salt + source

        else:
            msg = "could not pepper password"
            raise PepperPasswordException(msg)

        return peppered_pass


class DefaultHashService(DefaultAuthcService):

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
        peppered_plaintext = self.pepper_password(source)
        result['ciphertext'] = bytearray(
            self.crypt_context.encrypt(peppered_plaintext), 'utf-8')
        result['config'] = self.crypt_context.to_dict()

        return result  # DG:  this design is unique to Yosai, not Shiro

    def __repr__(self):
        return "<{0}(crypt_context={1})>".\
            format(self.__class__.__name__, self.crypt_context)

    # DG: removed combine method

# DG omitted HashRequest definition


class DefaultPasswordService(DefaultAuthcService):

    def __init__(self):
        super().__init__()
        # in Yosai, hash formatting is taken care of by passlib

    def passwords_match(self, plaintext, saved):
        """
        :param plaintext: the password requiring authentication, passed by user
        :param saved: the password saved for the corresponding account, in
                      the MCF Format as created by passlib

        :returns: a Boolean confirmation of whether plaintext equals saved

        Unlike Shiro:
            - Yosai expects saved to be a str and never a binary Hash
            - passwords remain strings and are not converted to bytearray
            - passlib determines the format and compatability
        """
        try:
            peppered_plaintext = self.pepper_password(plaintext)
            return self.crypt_context.verify(peppered_plaintext, saved)

        except (AttributeError, TypeError):
            raise PasswordMatchException('unrecognized attribute type')
