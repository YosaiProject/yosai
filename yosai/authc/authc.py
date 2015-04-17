import importlib
import copy
import traceback
from collections import defaultdict
from yosai import (
    AuthenticationException,
    AccountException,
    ConcurrentAccessException,
    CredentialsException,
    DisabledAccountException,
    Event,
    EventBus,
    ExcessiveAttemptsException,
    ExpiredCredentialsException,
    IEventBusAware,
    IllegalStateException,
    IncorrectCredentialsException,
    LockedAccountException,
    LogManager,
    PasswordMatchException,
    RealmAttributesException,  # new in Yosai
    settings,
    UnknownAccountException,
    UnsupportedTokenException,
    YosaiException,
)

from . import (
    ABCAuthenticationEvent,
    FirstRealmSuccessfulStrategy,
    DefaultAuthenticationAttempt,
    IAuthenticator,
    IHashingPasswordService,
    ICompositeAccount,
    ICompositeAccountId,
    IHostAuthenticationToken, 
    IRememberMeAuthenticationToken,
)

AUTHC_CONFIG = settings.AUTHC_CONFIG


class DefaultCompositeAccount(ICompositeAccount, object):

    def __init__(self, overwrite=True):
        self.account_id = DefaultCompositeAccountId()  # DG renamed 
        self.credentials = None
        self.merged_attrs = {}  # maybe change to OrderedDict() 
        self.overwrite = overwrite
        self.realm_attrs = defaultdict(dict)

    @property
    def attributes(self):
        return self.merged_attrs

    @property
    def realm_names(self):
        return self.realm_attrs.keys()

    def append_realm_account(self, realm_name, account):

        self.account_id.set_realm_account_id(realm_name, account.account_id)

        realm_attributes = copy.copy(account.attributes)  # DG: TBD-TO CONFIRM
        if (realm_attributes is None):
            realm_attributes = {} 

        try:
            self.realm_attrs[realm_name].update(realm_attributes)
        except (AttributeError, TypeError):
            msg = 'Could not update realm_attrs using ' + str(realm_attributes)
            raise RealmAttributesException(msg)

        for key, value in realm_attributes.items():
            if (self.overwrite):
                self.merged_attrs[key] = value 
            else:
                if (key not in self.merged_attrs):
                    self.merged_attrs[key] = value 
                
    def get_realm_attributes(self, realm_name):
        return self.realm_attrs.get(realm_name, dict())  # DG: no frozen dict


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
        self.remember_me = remember_me 
        self.username = username
        self.principal = self.username  # used in public api
        self.credentials = self.password  # used in public api

    def __repr__(self):
        result = "{0} - {1}, remember_me={2}".format(
            self.__class__.__name__, self.username, self.remember_me)
        if (self.host):
            result += "({0})".format(self.host)
        return result

    def clear(self):
        self.username = None 
        self.host = None 
        self.remember_me = False
      
        if (self.password is not None):
            for element in self.password:
                self.password[element] = 0  # DG:  this equals 0x00
        

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
            event = SuccessfulAuthenticationEvent(self, authc_token, account)
            self.event_bus.publish(event)

    def notify_failure(self, authc_token, throwable):
        if (self.event_bus):
            event = FailedAuthenticationEvent(self, authc_token, throwable)
            self.event_bus.publish(event)


class DefaultCompositeAccountId(ICompositeAccountId, object):

    def __init__(self):
        self.realm_accountids = defaultdict(set) 

    def get_realm_accountid(self, realm_name=None):
        return self.realm_accountids.get(realm_name, None)

    def set_realm_accountid(self, realm_name, accountid):
        self.realm_accountids[realm_name].add(accountid)

    def __eq__(self, other):
        if (other is self):
            return True
        
        if isinstance(other, DefaultCompositeAccountId):
            return self.realm_accountids == other.realm_accountids

        return False 
    
    def __repr__(self):
        return ', '.join(["{0}: {1}".format(realm, acctids) for realm, acctids 
                         in self.realm_accountids.items()])

class FailedAuthenticationEvent(ABCAuthenticationEvent):

    def __init__(self, source, authc_token, exception):
        super().__init__(source, authc_token)
        self.exception = exception  # DG:  renamed from throwable to exception


class SuccessfulAuthenticationEvent(ABCAuthenticationEvent):

    def __init__(self, source, authc_token, account):
        super().__init__(source, authc_token)
        self.account = account
    

class PasswordMatcher(object):
    """ DG:  Dramatic changes made here adapting to passlib and python """

    def __init__(self):
        self.password_service = DefaultPasswordService()

    def credentials_match(self, authc_token, account):
        self.ensure_password_service()
        submitted_password = self.get_submitted_password(authc_token)

        # stored_credentials should either be bytes or unicode:
        stored_credentials = self.get_stored_password(account)

        return self.password_service.passwords_match(submitted_password,
                                                     stored_credentials)

    def ensure_password_service(self):
        if (self.password_service is None):
            msg = "Required PasswordService has not been configured."
            raise IllegalStateException(msg)
        return self.password_service

    def get_submitted_password(self, authc_token):
        return authc_token.credentials if authc_token else None

    def get_stored_password(self, account_info): 
        # should be either bytes or unicode:
        stored = getattr(account_info, 'credentials', None)
        return stored

