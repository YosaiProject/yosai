from collections import defaultdict

from yosai import (
    RealmAttributesException,
)

from . import (
    ICompositeAccountId,
    ICompositeAccount,
)


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

        realm_attributes = account.attributes
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
