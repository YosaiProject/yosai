import importlib
from yosai import (
    MissingCredentialsException,
    settings,
)

from . import (
    AuthenticationSettings,
    DefaultHashService,
    ICredentialsMatcher,
    IHashingPasswordService,
)

class DefaultPasswordService(IHashingPasswordService, object):

    def __init__(self):

        self.default_hash_algorithm = "bcrypt_sha256"

        # new to Yosai:
        authc_config = AuthenticationSettings().get_password_service_defaults()

        # Unlike Shiro, Yosai references a config file:
        hash_scheme_settings = AUTHC_CONFIG.get('hash_algorithms', None).\
            get(self.default_hash_algorithm, None)

        self.default_hash_iterations =\
            hash_scheme_settings.get('iterations', None).get('default', None)

        hash_service = DefaultHashService()
        hash_service.hash_algorithm_name = self.default_hash_algorithm
        hash_service.hash_iterations = self.default_hash_iterations
        # Yosai omitted logic for hash_service.generate_public_salt 
        self.hash_service = hash_service

        # in Yosai, hash formatting is taken care of by passlib
        # self.hash_format ...
        # self.hash_format_factory ...

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


class SimpleCredentialsMatcher(object, ICredentialsMatcher):

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
            raise MissingCredentialsException  # new to Yosai 

    def credentials_match(self, authc_token, account):
        try:
            return authc_token.credentials == account.credentials
        except (AttributeError, TypeError):
            raise MissingCredentialsException  # new to Yosai 

    def equals(self, token_credentials, account_credentials):
        """
        returns bool confirming whether the token_credentials are equal to the 
        account_credentials
        """
        # log here
        msg = ("Performing credentials equality check for tokenCredentials "
               "of type [{0}] and accountCredentials of type [{1}]".
               format(token_credentials.__class__.__name__, 
                      account_credentials.__class__.__name__))
        print(msg)            
        
        if (isinstance(token_credentials, str)): 
            token_credentials = bytearray(token_credentials, 'utf-8')
        if (isinstance(account_credentials, str)):
            account_credentials = bytearray(account_credentials, 'utf-8')

        return token_credentials == account_credentials
        

class AllowAllCredentialsMatcher(object):

    def credentials_match(self, authc_token, account):
        return True
