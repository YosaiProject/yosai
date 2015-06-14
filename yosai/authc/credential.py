from yosai import (
    IllegalStateException,
    MissingCredentialsException,
    PasswordMatcherInvalidAccountException,
    PasswordMatcherInvalidTokenException,
)

from . import (
    DefaultPasswordService,
)

from yosai.authc import abcs


class PasswordMatcher(abcs.CredentialsMatcher):
    """ DG:  Dramatic changes made here while adapting to passlib and python"""

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
        if (not self.password_service):
            msg = "Required PasswordService has not been configured."
            raise IllegalStateException(msg)
        return self.password_service

    def get_submitted_password(self, authc_token):
        try:
            return authc_token.credentials
        except AttributeError:
            raise PasswordMatcherInvalidTokenException

    def get_stored_password(self, account): 
        try:
            return account.credentials
        except AttributeError:
            raise PasswordMatcherInvalidAccountException


class SimpleCredentialsMatcher(abcs.CredentialsMatcher):

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
            return self.equals(authc_token.credentials, account.credentials)
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
        

class AllowAllCredentialsMatcher(abcs.CredentialsMatcher):

    def credentials_match(self, authc_token, account):
        return True
