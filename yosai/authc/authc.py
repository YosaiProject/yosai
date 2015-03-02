
import passlib
import copy
import traceback
from authc_abstracts import AuthenticationEvent
from yosai import (
    AuthenticationException,
    AccountException,
    ConcurrentAccessException,
    CredentialsException,
    DisabledAccountException,
    EventBus,
    ExcessiveAttemptsException,
    ExpiredCredentialsException,
    IllegalStateException,
    IncorrectCredentialsException,
    LockedAccountException,
    LogManager,
    PasswordMatchException,
    settings,
    UnknownAccountException,
    UnsupportedTokenException,
    YosaiException,
)

from .interfaces import (
    IHashingPasswordService,
)


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
            del self.password
        

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

# Credentials Classes:  DefaultPasswordService,
#                       SimpleCredentialsMatcher,
#                       AllowAllCredentialsMatcher


class DefaultPasswordService(IHashingPasswordService, object):

    def __init__(self):
        self.default_hash_algorithm = "bcrypt_sha256"
        hash_scheme_settings = AUTHC_CONFIG.get('hash_algorithms', None).\
                               get(self.default_hash_algorithm, None)
        self.default_hash_iterations =\
            hash_scheme_settings.get('iterations', None).get('default', None)

        hash_service = DefaultHashService()
        hash_service.hash_algorithm_name = self.default_hash_algorithm
        hash_service.hash_iterations = self.default_hash_iterations
        hash_service.generate_public_salt = True  # always want generated salts
        self.hash_service = hash_service

        self.hash_format = Shiro1CryptFormat()
        self.hash_format_factory = DefaultHashFormatFactory()

    def encrypt_password(self, plaintext):
        hashed = self.hash_password(plaintext)
        self.check_hash_format_durability()
        return self.hash_format.format(hashed)
    
    def hash_password(self, plaintext):
        plaintext_bytes = self.create_byte_source(plaintext)
        if (not plaintext_bytes):
            return None 
        request = self.create_hash_request(plaintext_bytes)
        return hash_service.compute_hash(request)

    def passwords_match(self, plaintext, saved):
        """
        :type plaintext:
        :param plaintext: the password requiring authentication, passed by user

        :type saved: Hash or str
        :param saved: the password saved for the corresponding account

        :returns: a Boolean confirmation of whether plaintext equals saved
        :rtype: bool
        """

        if isinstance(saved, Hash):

            plaintext_bytes = self.create_byte_source(plaintext)

            if (not saved):
                return (not plaintext_bytes)
            else:
                if (not plaintext_bytes):
                    return False

            request = self.build_hash_request(plaintext_bytes, saved)

            computed = self.hash_service.compute_hash(request)

            return saved.equals(computed)

        elif isinstance(saved, str): 
            plaintext_bytes = self.create_byte_source(plaintext)

            if (not saved):
                return (not plaintext_bytes)
            else: 
                if (not plaintext_bytes):
                    return False

            """
            First check to see if we can reconstitute the original hash - self
            allows us to perform password hash comparisons even for previously
            saved passwords that don't match the current HashService 
            configuration values.  This is a very nice feature for password
            comparisons because it ensures backwards compatibility even after
            configuration changes.
            """
            discovered_format = self.hash_format_factory.get_instance(saved)

            if (discovered_format):
                try:
                    saved_hash = discovered_format.parse(saved)
                except:
                    raise
                return self.passwords_match(plaintext, saved_hash)

            """
            If we're at self point in the method's execution, We couldn't
            reconstitute the original hash.  So, we need to hash the
            submittedPlaintext using current HashService configuration and then
            compare the formatted output with the saved string.  This will
            correctly compare passwords, but does not allow changing the
            HashService configuration without breaking previously saved 
            passwords:
        
            The saved text value can't be reconstituted into a Hash instance.
            We need to format the submittedPlaintext and then compare self
            formatted value with the saved value: 
            """
            request = self.create_hash_request(plaintext_bytes)
            computed = self.hash_service.compute_hash(request)
            formatted = self.hash_format.format(computed)

            return (saved == formatted)

        else:
            raise PasswordMatchException('unrecognized attribute type')

    def create_hash_request(self, plaintext):
        return HashRequest.Builder().set_source(plaintext).build()

    def create_byte_source(self, target_object):
        return bytearray(bytes(target_object))

    def build_hash_request(self, plaintext, saved):
        # keep everything from the saved hash except for the source:
        # now use the existing saved data:
        return HashRequest.Builder().set_source(plaintext).\
                set_algorithm_name(saved.algorithm_name).\
                set_salt(saved.salt).\
                set_iterations(saved.iterations).\
                build()


class SimpleCredentialsMatcher(object):

    def __init__(self):
        pass

    def get_credentials(self, credential_source):
        """
        :type credential_source: an AuthenticationToken or Account object
        :param credential_source:  an object that manages state of credentials
        """
        try:
            return credential_source.credentials
        except (AttributeError, TypeError):
            traceback.print_exc()
            return None 

    def credentials_match(self, authc_token, account):
        try:
            return authc_token.credentials == account.credentials
        except (AttributeError, TypeError):
            traceback.print_exc()
            return False


class AllowAllCredentialsMatcher(object):

    def credentials_match(self, authc_token, account):
        return True
