from yosai.core import (
    DelegatingSubject,
    account_abcs,
    authc_abcs,
    authz_abcs,
    cache_abcs,
    mgt_abcs,
    realm_abcs,
    serialize_abcs,
    session_abcs,
    subject_abcs,
)

import datetime


class MockToken(authc_abcs.AuthenticationToken):
    pass

class MockAccountStore(account_abcs.AccountStore):
    pass

class MockPubSub:

    def isSubscribed(self, listener, topic_name):
        return True

    def sendMessage(self, topic_name, **kwargs):
        pass  # True   just for testing, otherwise returns None in production

    def subscribe(self, _callable, topic_name):
        return _callable, True

    def unsubscribe(self, listener, topic_name):
        return listener

    def unsubAll(self):
        return []

    def __repr__(self):
        return "<MockPubSub()>"


class MockSubject(DelegatingSubject):

    def __init__(self):
        self.identifiers = type('DumbCollection', (object,), {})()
        self.identifiers.primary_identifier = 'attribute1'
        self.host = 'host'
        self.authenticated = None

    def is_permitted(self, permissions):
        pass

    def is_permitted_all(self, permissions):
        pass

    def check_permission(self, permissions):
        pass

    def has_role(self, role_identifiers):
        pass

    def has_role_collective(self, roleid_s, logical_operator):
        pass

    def check_role(self, roleid_s, logical_operator):
        pass

    def login(self, auth_token):
        pass

    @property
    def authenticated(self):
        return self._authenticated

    @property
    def is_remembered(self):
        pass

    def get_session(self, create=None):
        return 'mocksession'

    def logout(self):
        pass

    def execute(self, x_able):
        pass

    def associate_with(self, x_able):
        pass

    def run_as(self, identifiers):
        pass

    def is_run_as(self):
        pass

    def get_previous_identifiers(self):
        pass

    def release_run_as(self):
        pass


# verified double due to use of interfaces:
class MockSecurityManager(mgt_abcs.SecurityManager):

    def authenticate_account(self, authc_token):
        pass

    def is_permitted(self, identifiers, permission_s):
        pass

    def is_permitted_collective(self, identifiers, permission_s, logical_operator):
        return True

    def check_permission(self, identifiers, permission_s):
        pass

    def has_role(self, identifiers, roleid_s):
        pass

    def has_role_collective(self, identifiers, roleid_s, logical_operator):
        pass

    def check_role(self, identifiers, roleid_s, logical_operator):
        pass

    def login(self, subject, authc_token):
        pass

    def logout(self, subject):
        pass

    def create_subject(self, subject_context):
        pass

    def start(self, session_context):
        pass

    def get_session(self, session_key):
        pass

    def __repr__(self):
        return "MockSecurityManager()"


class MockCacheHandler(cache_abcs.CacheHandler):

    def get(self, key, identifier):
        pass

    def get_or_create(self, key, identifier, creator_func):
        pass

    def set(self, key, identifier, value):
        pass

    def delete(self, key, identifier):
        pass

