import pytest
from unittest import mock

from yosai.core import (
    Event,
    DefaultEventBus,
)

from ..doubles import (
    MockPubSub,
)

from pubsub.core import (
    ListenerMismatchError,
    SenderMissingReqdMsgDataError, 
    SenderUnknownMsgDataError,
    TopicDefnError,
    TopicNameError,
)

@pytest.fixture(scope='function')
def listener_mismatch_error(): 
    mock_error = mock.Mock()
    mock_error.side_effect = ListenerMismatchError('message', 'listener')
    return mock_error

@pytest.fixture(scope='function')
def topic_name_error():
    mock_error = mock.Mock()
    mock_error.side_effect = TopicNameError('topic_name', 'message')
    return mock_error

@pytest.fixture(scope='function')
def topic_defn_error():
    mock_error = mock.Mock()
    mock_error.side_effect = TopicDefnError(['topic'])
    return mock_error

@pytest.fixture(scope='function')
def send_unknown_msgdata_error():
    mock_error = mock.Mock()
    mock_error.side_effect =\
        SenderUnknownMsgDataError('topic_name', ['arg_names'], ['extra'])
    return mock_error

@pytest.fixture(scope='function')
def send_missing_reqd_msgdata_error():
    mock_error = mock.Mock()
    mock_error.side_effect =\
        SenderMissingReqdMsgDataError('topic_name', ['arg_names'], ['missing'])
    return mock_error

@pytest.fixture(scope='function')
def default_event():
    return Event(event_type='default_event_type',
                 event_topic='default_event_topic',
                 source='source_object_here')
