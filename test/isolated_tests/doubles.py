from yosai.core import (
    Credential,
    DelegatingSubject,
    MapContext,
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

from marshmallow import fields, Schema, post_load
import datetime


class MockSession(session_abcs.ValidatingSession):

    def __init__(self):
        self.attributes = {'attr1': 1, 'attr2': 2, 'attr3': 3}
        self._internal_attributes = {}
        self._idle_timeout = datetime.timedelta(minutes=15)
        self._absolute_timeout = datetime.timedelta(minutes=60)
        self._isvalid = True  # only used for testing
        self._session_id = 'MockSession12345'
        self._start_timestamp = None 
        self._stop_timestamp = None 
        self._last_access_time = None
        self._internal_attribute_keys = None
        self._attribute_keys = None

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
        return self._session_id

    @property
    def last_access_time(self):
        return self._last_access_time 

    @last_access_time.setter
    def last_access_time(self, lat):
        self._last_access_time = lat

    @property
    def start_timestamp(self):
        return self._start_timestamp 
    
    @property
    def stop_timestamp(self):
        return self._stop_timestamp 

    @stop_timestamp.setter
    def stop_timestamp(self, st):
        self._stop_timestamp = st

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

    @property
    def attribute_keys(self):
        return self._attribute_keys  # dirty hack
    
    @property
    def internal_attribute_keys(self):
        return self._internal_attribute_keys  # dirty hack

    def get_attribute(self, key):
        return self.attributes.get(key)

    def remove_attribute(self, key):
        return self.attributes.pop(key, None)

    def set_attribute(self, key, value):
        self.attributes[key] = value

    def get_internal_attribute(self, key):
        pass

    def remove_internal_attribute(self, key):
        pass 

    def set_internal_attribute(self, key, value):
        pass

    def stop(self):
        pass

    def touch(self):
        pass

    def validate(self):
        pass

    def __repr__(self):
        attrs = ','.join([str(key) + ':' + str(value) for key, value in
                          self.attributes.items()])
        return "MockSession(" + attrs + ")"


class MockToken(authc_abcs.AuthenticationToken):

    @property
    def identifier(self):
        pass

    @property
    def credentials(self):
        pass


class MockAccount(account_abcs.Account,
                  serialize_abcs.Serializable):

    def __init__(self, account_id, credentials={}, attributes={},
                 authz_info=None):
        self._account_id = account_id
        self._credentials = credentials
        self._attributes = attributes 

    @property
    def account_id(self):
        return self._account_id

    @account_id.setter
    def account_id(self, aid):
        self._account_id = aid

    @property
    def attributes(self):
        return self._attributes

    @property
    def authz_info(self):
        pass

    @property
    def credentials(self):
        return self._credentials

    def __eq__(self, other):
        try:
            result = (self._account_id == other._account_id and
                      self.credentials == other.credentials and
                      self.attributes == other.attributes)
        except Exception:
            return False
        return result

    def __repr__(self):
        return "<MockAccount(id={0}, credentials={1}, attributes={2})>".\
            format(self.account_id, self.credentials, self.attributes)

    @classmethod
    def serialization_schema(cls):
        class SerializationSchema(Schema):
            account_id = fields.Str()
            credentials = fields.Nested(Credential.serialization_schema())
            attributes = fields.Nested(cls.AccountAttributesSchema)

            @post_load
            def make_account(self, data):
                mycls = MockAccount
                instance = mycls.__new__(cls)
                instance.__dict__.update(data)
                return instance

        return SerializationSchema

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

    def get_authz_info(self, identifiers):
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
        self._authenticated = None

    @property
    def identifiers(self):
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


class MockThreadContext:

    def __init__(self):
        self.subject = 'threadcontextsubject'
        self.security_manager = 'security_manager'

    def bind(self, subject):
        pass


class MockSubjectBuilder:

    def __init__(self, security_utils, security_manager):
        pass

    def build_subject(self):
        return 'subjectbuildersubject'


class MockCacheHandler(cache_abcs.CacheHandler):

    def get(self, key, identifier):
        pass

    def get_or_create(self, key, identifier, creator_func):
        pass

    def set(self, key, identifier, value):
        pass

    def delete(self, key, identifier):
        pass


class MockSecUtil:

    def __init__(self):
        self.subject = MockSubject()

