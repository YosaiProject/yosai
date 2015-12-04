from yosai import (
    account_abcs,
)

from marshmallow import Schema, fields, post_load


class Account(account_abcs.Account):
    """
    This is a basic collection of the security related attributes associated
    with an account
    """

    def __init__(self, account_id=None, credentials=None, identifiers=None,
                 authz_info=None):
        self.account_id = account_id
        self.credentials = credentials
        self.identifiers = identifiers
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
    def identifiers(self):
        return self._identifiers

    @identifiers.setter
    def identifiers(self, identifiers):
        self._identifiers = identifiers

    @property
    def authz_info(self):
        return self._authz_info

    @authz_info.setter
    def authz_info(self, authz_info):
        self._authz_info = authz_info

    # this is a placeholder for later -- TBD
    @classmethod
    def serialization_schema(cls):

        class SerializationSchema(Schema):
            pass

            @post_load
            def make_account(self, data):
                mycls = Account
                instance = mycls.__new__(mycls)
                instance.__dict__.update(data)

        return SerializationSchema

    # omitting credentials from print output:
    def __repr__(self):
        return "Account(account_id={0}, authz_info={1})".format(
            self.account_id, self.authz_info)
