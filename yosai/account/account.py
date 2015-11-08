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
                 permissions=None, roles=None):
        self.account_id = account_id
        self.credentials = credentials 
        self.identifiers = identifiers
        self.permissions = permissions
        self.roles = roles

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
    def permissions(self):
        return self._permissions

    @permissions.setter
    def permissions(self, permissions):
        self._permissions = permissions

    @property
    def roles(self):
        pass

    @roles.setter
    def roles(self, roles):
        self._roles = roles

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



