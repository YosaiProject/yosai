from yosai import (
    CacheKeyRemovalException,
    DelegatingSubject,
    MapContext,
    account_abcs,
    authc_abcs,
    authz_abcs,
    cache_abcs,
    mgt_abcs,
    realm_abcs,
    session_abcs,
    subject_abcs,
)

from marshmallow import fields, Schema, post_load
import datetime


class MockSession(session_abcs.ValidatingSession, object):

    def __init__(self):
        self.session = {'attr1': 1, 'attr2': 2, 'attr3': 3}
        self._idle_timeout = datetime.timedelta(minutes=15)
        self._absolute_timeout = datetime.timedelta(minutes=60)
        self._isvalid = True  # only used for testing

    @property
    def attribute_keys(self):
        return self.session.keys()

    @property
    def host(self):
        return '127.0.0.1'

    @property
    def is_valid(self):
        return self._isvalid

    def validate(self, session):
        pass

    @property
    def session_id(self):
        return 'MockSession12345'

    @property
    def last_access_time(self):
        return datetime.datetime(2015, 6, 17, 19, 45, 51, 818810)

    @property
    def start_timestamp(self):
        return datetime.datetime(2015, 6, 17, 19, 43, 51, 818810)

    @property
    def idle_timeout(self):
        return self._idle_timeout

    @idle_timeout.setter
    def idle_timeout(self, idle_timeout):
        self._idle_timeout = idle_timeout

    @property
    def absolute_timeout(self):
        return self._absolute_timeout

    @absolute_timeout.setter
    def absolute_timeout(self, absolute_timeout):
        self._absolute_timeout = absolute_timeout

    def get_attribute(self, key):
        return self.session.get(key)

    def remove_attribute(self, key):
        return self.session.pop(key, None)

    def set_attribute(self, key, value):
        self.session[key] = value

    def stop(self):
        pass

    def touch(self):
        pass

    def validate(self):
        pass

    def __repr__(self):
        attrs = ','.join([str(key) + ':' + str(value) for key, value in 
                          self.session.items()])
        return "MockSession(" + attrs + ")"


class MockCache(cache_abcs.Cache):

    def __init__(self, keyvals={}):
        # keyvals is a dict
        self.kvstore = {}
        self.kvstore.update(keyvals)

    @property
    def values(self):
        return self.kvstore.values()

    def get(self, key):
        return self.kvstore.get(key, None)

    def put(self, key, value):
        self.kvstore[key] = value

    def remove(self, key):
        try:
            return self.kvstore.pop(key)
        except KeyError:
            raise CacheKeyRemovalException


class MockCacheManager(cache_abcs.CacheManager):

    def __init__(self, cache):
        self.cache = cache

    def get_cache(self, name):
        # regardless of the name, return the stock cache
        return self.cache


class MockToken(authc_abcs.AuthenticationToken):

    @property
    def identifier(self):
        pass

    @property
    def credentials(self):
        pass


class MockCredentialsCacheHandler(realm_abcs.CredentialsCacheHandler):

    def __init__(self, account):
        self.account = account

    def get_cached_credentials(self, account):
        return self.account  # always returns the initialized account


class MockAccount(account_abcs.Account):

    def __init__(self, account_id, credentials={}, identifiers={}):
        self._account_id = account_id
        self._credentials = credentials
        self._identifiers = identifiers

    @property
    def account_id(self):
        return self._account_id

    @property
    def authorization_info(self):
        return "authz_info"

    @property
    def credentials(self):
        return self._credentials

    @property
    def identifiers(self):
        return self._identifiers

    def __eq__(self, other):
        try:
            result = (self._account_id == other._account_id and
                      self.credentials == other.credentials and
                      self.identifiers == other.identifiers)
        except Exception:
            return False
        return result

    def __repr__(self):
        return "<MockAccount(id={0}, credentials={1}, identifiers={2})>".\
            format(self.account_id, self.credentials, self.identifiers)

    @classmethod
    def serialization_schema(cls):
        class SerializationSchema(Schema):
            account_id = fields.Str()
            credentials = fields.Nested(cls.AccountCredentialsSchema)
            identifiers = fields.Nested(cls.AccountAttributesSchema)

            @post_load
            def make_account(self, data):
                mycls = MockAccount
                instance = mycls.__new__(cls)
                instance.__dict__.update(data)
                return instance

        return SerializationSchema

    class AccountCredentialsSchema(Schema):
        password = fields.Str()
        api_key_secret = fields.Str()

        @post_load
        def make_account_credentials(self, data):
            return dict(data)

    class AccountAttributesSchema(Schema):
        givenname = fields.Str()
        surname = fields.Str()
        email = fields.Email()
        username = fields.Str()
        api_key_id = fields.Str()

        @post_load
        def make_acct_attributes(self, data):
            return dict(data)


class MockAccountStore(account_abcs.AccountStore):

    def __init__(self, account=MockAccount(account_id='MAS123')):
        self.account = account

    def get_account(self, request): 
        return self.account  # always returns the initialized account


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


class MockSubjectContext(MapContext):

    def resolve_security_manager(self):
        return None

    def resolve_session(self):
        return None

    def resolve_identifiers(self):
        return None


class MockSubject(DelegatingSubject):

    def __init__(self):
        self._identifiers = type('DumbCollection', (object,), {})()
        self._identifiers.primary_identifier = 'attribute1'
        self.host = 'host'

    @property
    def identifier(self):
        return None

    @property
    def identifiers(self):
        return self._identifiers

    def is_permitted(self, permissions):
        pass

    def is_permitted_all(self, permissions):
        pass

    def check_permission(self, permissions):
        pass

    def has_role(self, role_identifiers):
        pass

    def has_all_roles(self, role_identifiers):
        pass

    def check_role(self, role_identifiers):
        pass

    def login(self, auth_token):
        pass

    @property
    def authenticated(self):
        pass

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

    def is_permitted_all(self, identifiers, permission_s):
        return True

    def check_permission(self, identifiers, permission_s):
        pass

    def has_role(self, identifiers, roleid_s):
        pass

    def has_all_roles(self, identifiers, roleid_s):
        pass

    def check_role(self, identifiers, role_s):
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
