from yosai import (
    IAccount,
)

class MockAccount(IAccount):

    def __init__(self, account_id, credentials=None, attributes=None):
        self._account_id = account_id
        self._credentials = credentials
        self._attributes = attributes
        
    @property 
    def account_id(self):
        return self._account_id 

    @property 
    def credentials(self):
        return self._credentials 

    @property 
    def attributes(self):
        return self._attributes 

    def __repr__(self):
        return "<MockAccount(account_id={0})>".format(self.account_id)
