from yosai.core import (
    account_abcs,
)


class Account(account_abcs.Account):
    """
    This is a basic collection of the security related attributes associated
    with an account
    """

    def __init__(self, account_id=None, credentials=None, attributes=None,
                 authz_info=None):
        self.account_id = account_id
        self.credentials = credentials
        self.attributes = attributes
        self.authz_info = authz_info

    @property
    def account_id(self):
        return self._account_id

    @account_id.setter
    def account_id(self, accountid):
        self._account_id = accountid

    @property
    def credentials(self):
        return self._credentials

    @credentials.setter
    def credentials(self, credentials):
        self._credentials = credentials

    @property
    def attributes(self):
        return self._attributes

    @attributes.setter
    def attributes(self, attributes):
        self._attributes = attributes

    @property
    def authz_info(self):
        return self._authz_info

    @authz_info.setter
    def authz_info(self, authz_info):
        self._authz_info = authz_info

    def __repr__(self):
        return "Account(account_id={0})".format(self._account_id)
