import importlib
from yosai import (
    MissingCredentialsException,
    settings,
)

from . import (
    DefaultAuthenticationSettings,
    DefaultHashService,
    ICredentialsMatcher,
    IHashingPasswordService,
)

class DefaultPasswordService(IHashingPasswordService, object):

    def __init__(self):

        # Yosai introduces AuthenticationSettings based config:
        auth_settings = DefaultAuthenticationSettings()
        self.default_hash_algorithm = auth_settings.default_algorithm 
        self.default_hash_iterations = auth_settings.default_rounds 

        hash_service = DefaultHashService()
        hash_service.hash_algorithm_name = self.default_hash_algorithm
        hash_service.hash_iterations = self.default_hash_iterations
        # Yosai omitted logic for hash_service.generate_public_salt 
        self.hash_service = hash_service

        # in Yosai, hash formatting is taken care of by passlib
        # self.hash_format ...
        # self.hash_format_factory ...

    def encrypt_password(self, plaintext):
        # Yosai omits the hash formatting logic and merges with hash_password
        request = self.create_hash_request(plaintext)  # Yosai refactor to str
        return self.hash_service.compute_hash(request)

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

            return (saved == formatted)

        except (AttributeError, TypeError):
            raise PasswordMatchException('unrecognized attribute type')

    def create_hash_request(self, plaintext):
        return HashRequest.Builder().set_source(plaintext).build()

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
