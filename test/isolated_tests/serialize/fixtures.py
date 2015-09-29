from .doubles import (
    MockSerializable,
)

from yosai import(
    SerializationManager,
)

import pytest
import inspect
import sys
import yosai  # to get serializable classes

@pytest.fixture(scope='function')
def mock_serializable():
    return MockSerializable()


@pytest.fixture(scope='function')
def serialization_manager():
    return SerializationManager()  # defaults to msgpack


@pytest.fixture(scope='function')
def serializable_classes():
    clsmembers = inspect.getmembers(sys.modules['yosai'], inspect.isclass)
    return {member[0]: member[1] for member in clsmembers if
            issubclass(member[1], yosai.serialize_abcs.Serializable)}


@pytest.fixture(scope='function')
def serialized_simple_session():
    return {'serialized_cls': 'SimpleSession',
            'serialized_dist_version': '0.1.0',
            'serialized_record_dt': '2015-09-28T11:39:01.000000+00:00',
            '_session_id': 'sessionid123',
            '_start_timestamp': '2015-09-28T11:37:05.446732+00:00',
            '_stop_timestamp': None,
            '_last_access_time': '2015-09-28T11:39:00.000000+00:00',
            '_idle_timeout': 900,
            '_absolute_timeout': 1800,
            '_is_expired': False,
            '_host': '127.0.0.1'}


@pytest.fixture(scope='function')
def serialized_simple_identifier_collection():
    return {'serialized_cls': 'SimpleIdentifierCollection',
            'serialized_dist_version': '0.1.0',
            'serialized_record_dt': '2015-09-28T11:39:01.000000+00:00',
            'realm_identifiers': {'realm1': ['identifier1', 'identifier2'],
                                  'realm2': ['identifier1', 'identifier2']}}

@pytest.fixture(scope='function',
                params= [{'serialized_cls': 'SimpleSession',
                          'serialized_dist_version': '0.1.0',
                          'serialized_record_dt': '2015-09-28T11:39:01.000000+00:00',
                          '_session_id': 'sessionid123',
                          '_start_timestamp': '2015-09-28T11:37:05.446732+00:00',
                          '_stop_timestamp': None,
                          '_last_access_time': '2015-09-28T11:39:00.000000+00:00',
                          '_idle_timeout': 900,
                          '_absolute_timeout': 1800,
                          '_is_expired': False,
                          '_host': '127.0.0.1'},
                         {'serialized_cls': 'SimpleIdentifierCollection',
                          'serialized_dist_version': '0.1.0',
                          'serialized_record_dt': '2015-09-28T11:39:01.000000+00:00',
                          'realm_identifiers': {'realm1': ['identifier1', 'identifier2'],
                                                'realm2': ['identifier1', 'identifier2']}}])
def serialized(request):
    return request.param


@pytest.fixture(scope='function')
def serializeds(serialized_simple_session,
                serialized_simple_identifier_collection):
    return [serialized_simple_session,
            serialized_simple_identifier_collection]


# DelegatingSession
# DefaultSessionKey
# SimpleAccount
# MapContext
# SimpleRole
# AllPermission
# WildcardPermission
