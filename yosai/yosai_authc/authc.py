import copy
import eventbus
import traceback
from authc_abstracts import AuthenticationEvent


class IllegalArgumentException(Exception):
    pass


class YosaiException(Exception):
    def __init__(self, msg=None, cause=None):
        super().__init__(msg, cause)  # DG:  not sure about the args..


class AuthenticationException(YosaiException):
    def __init__(self, msg=None, cause=None):
        super().__init__(msg, cause)


class AccountException(AuthenticationException):
    def __init__(self, msg=None, cause=None):
        super().__init__(msg, cause)


class UnknownAccountException(AccountException):
    def __init__(self, msg=None, cause=None):
        super().__init__(msg, cause)


class ConcurrentAccessException(AccountException):
    def __init__(self, msg=None, cause=None):
        super().__init__(msg, cause)


class UnsupportedTokenException(Exception):
    pass


class DefaultCompositeAccount(object):

    def __init__(self, overwrite=True):
        self.overwrite = overwrite
        self.account_id = DefaultCompositeAccountId()  # DG renamed 
        self.credentials = None
        self.merged_attrs = {}  # maybe change to OrderedDict() 
        self.realm_attrs = {}  # maybe change to OrderedDict() 

    @property
    def attributes(self):
        return self.merged_attrs  # not frozen
    
    @property
    def realm_names(self):
        return frozenset(self.realm_attrs)

    def append_realm_account(self, realm_name, account):

        self.account_id.set_realm_account_id(realm_name, account.account_id)

        realm_attributes = copy.copy(account.attributes)  # DG: TBD-TO CONFIRM
        if (realm_attributes is None):
            realm_attributes = {}

        self.realm_attrs[realm_name] = realm_attributes

        for key, value in realm_attributes.items():
            if (self.overwrite):
                self.merged_attrs[key] = value 
            else:
                if (key not in self.merged_attrs):
                    self.merged_attrs[key] = value 
                
    def get_realm_attributes(self, realm_name):
        return self.realm_attrs.get(realm_name, dict())  # DG: no frozen dict


class UsernamePasswordToken(object):

    def __init__(self, username=None, password=None, host=None, 
                 remember_me=False):
        """
        :type password: bytearray
        """
        self.host = host
        self.password = password
        self.remember_me = remember_me 
        self.username = username
        self.principal = self.username
        self.credentials = self.password

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
      
        # following is required for government contracting development:
        if (self.password is not None):
            for element in self.password:
                self.password[element] = 0  # DG:  this equals 0x00
            self.password = None 
        

class DefaultAuthenticator(object):

    def __init__(self): 
        """ Default in Shiro 2.0 is 'first successful'. This is the desired 
        behavior for most Shiro users (80/20 rule).  Before v2.0, was 
        'at least one successful', which was often not desired and caused
        unnecessary I/O.  """
        self.authentication_strategy = FirstRealmSuccessfulStrategy()
        self.realms = None
        self.event_bus = eventbus.EventBus()

    def authenticate_single_realm_account(self, realm, authc_token):
        try:
            if (not realm.supports(authc_token)):
                msg = ("Realm [" + realm + "] does not support "
                       "authentication token [" + authc_token + 
                       "].  Please ensure that the appropriate Realm "
                       "implementation is configured correctly or that "
                       "the realm accepts AuthenticationTokens of this type.")
                raise UnsupportedTokenException(msg)
            
        except UnsupportedTokenException as ex:
            print('DefaultAuthenticator.authenticate_single_realm_account: ',
                  ex)
        else:
            return realm.authenticate_account(authc_token)
    
    def authenticate_multi_realm_account(self, realms, authc_token):
        try:
            attempt = DefaultAuthenticationAttempt(authc_token, 
                                                   frozenset(realms))
            return self.authentication_strategy.execute(attempt)
        except:
            raise

    def authenticate_account(self, authc_token):

            if authc_token is None:
                msg = "AuthenticationToken argument cannot be null."
                raise IllegalArgumentException(msg) 

            # log here
            msg2 = ("Authentication submission received for authentication "
                    "token ["+authc_token+"]")
            print(msg2)

            try:
                account = self.do_authenticate_account(authc_token)
                if (account is None): 
                    msg3 = ("No account returned by any configured realms for "
                            "submitted authentication token [" + authc_token +
                            "].")
                    raise UnknownAccountException(msg3)
                
            except Exception as ex: 
                if (isinstance(ex, AuthenticationException)):
                    ae = ex 
                
                if (ae is None): 
                    """
                    Exception thrown was not an expected
                    AuthenticationException.  Therefore it is probably a 
                    little more severe or unexpected.  So, wrap in an
                    AuthenticationException, log to warn, and propagate:
                    """
                    msg4 = ("Authentication failed for submitted token ["
                            + authc_token + "].  Possible unexpected " 
                            "error? (Typical or expected login exceptions "
                            "should extend from AuthenticationException).")
                    ae = AuthenticationException(msg4, ae)
                
                try:
                    self.notify_failure(authc_token, ae)
                except:
                    # log here
                    msg5 = ("Unable to send notification for failed "
                            "authentication attempt - listener error?.  " 
                            "Please check your EventBus implementation.  "
                            "Logging 'send' exception  and propagating "
                            "original AuthenticationException instead...")
                    print(msg5)
                raise ae 

            # log here
            msg6 = ("Authentication successful for submitted authentication "
                    "token [{0}].  Returned account [{1}]".
                    format(authc_token, account))
            print(msg6)

            self.notify_success(authc_token, account)

            return account
        
    def do_authenticate_account(self, authc_token):
        
        if (not self.realms):
            msg = ("One or more realms must be configured to perform "
                   "authentication.")
            raise AuthenticationException(
                'DefaultAuthenticator.do_authenticate_account: ' + msg)

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


class DefaultCompositeAccountId(object):

    def __init__(self):
        self.realm_accountids = {} 

    def get_realm_accountid(self, realm_name):
        return self.realm_accountids.get(realm_name, None)

    def set_realm_accountid(self, realm_name, accountid):
        try:
            self.realm_accountids[realm_name] = accountid
        except (AttributeError, TypeError):
            traceback.print_exc()

    def __eq__(self, other):
        if (other == self):
            return True
        
        try:
            return self.realm_accountids == other.realm_accountids

        except (AttributeError, TypeError):
            traceback.print_exc()
            return False

        return False 

    def __repr__(self):
 
        try:
            return str(self.realm_acctids) 
        except (AttributeError, TypeError):
            traceback.print_exc()
            return '' 

    def hash_code(self):
        try:
            return id(self.realm_accountids)
        except (AttributeError, TypeError):
            return 0
        return 0


class FailedAuthenticationEvent(AuthenticationEvent):

    def __init__(self, source, authc_token, exception):
        super().__init__(source, authc_token)
        self.exception = exception  # DG:  renamed throwable


class SuccessfulAuthenticationEvent(AuthenticationEvent):

    def __init__(self, source, authc_token, account):
        super().__init__(source, authc_token)
        self.account = account
    

