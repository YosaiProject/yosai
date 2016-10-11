from collections import namedtuple

# this is a namedtuple with default values, it may not get used (TBD)
class Account(namedtuple('Account', 'account_id, account_locked, authc_info, authz_info')):
    __slots__ = ()
    def __new__(cls, account_id, account_locked=None, authc_info=None, authz_info=None):
        return super(Account, cls).__new__(cls, account_id, account_locked,
                                           authc_info, authz_info)
