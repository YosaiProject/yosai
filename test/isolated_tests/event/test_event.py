import pytest
import datetime

from yosai import (
    Event,
    DefaultEventBus,
    EventBusMessageDataException,
    EventBusTopicException,
    EventBusSubscriptionException,
)

# -----------------------------------------------------------------------------
# Event Tests
# -----------------------------------------------------------------------------

def test_event_timestamp_verify(default_event):
    """ timestamp integrity is vital, so confirm that it is working """
    timestamp = datetime.datetime.utcnow() 
    assert (timestamp - default_event.timestamp) <= datetime.timedelta(minutes=1) 

def test_event_attr_set():
    test_event = Event(event_topic='topic1',
                       event_type='type1',
                       source='source',
                       attr1=type('Attr1', (object,), {}))
    assert hasattr(test_event, 'attr1')

# -----------------------------------------------------------------------------
# EventBus Tests
# -----------------------------------------------------------------------------

#    event_bus_message_data_exception,
#    event_bus_subscription_exception,
#    event_bus_topic_exception,
#    mock_pubsub,
#    patched_event_bus,

def test_is_registered_succeeds(patched_event_bus):
    peb = patched_event_bus

    assert peb.is_registered('listener', 'any_topic')  # dumb call

def test_is_registered_raises_topicnameerror(
        patched_event_bus, monkeypatch, topic_name_error):

    peb = patched_event_bus
    mock_error = topic_name_error 
    monkeypatch.setattr(peb._event_bus, 'isSubscribed', mock_error) 

    with pytest.raises(EventBusTopicException):
        peb.is_registered('listener', 'any_topic')  # dumb args 

def test_is_registered_raises_topicdefnerror(
        monkeypatch, patched_event_bus, topic_defn_error):

    peb = patched_event_bus
    mock_error = topic_defn_error 
    monkeypatch.setattr(peb._event_bus, 'isSubscribed', mock_error)

    with pytest.raises(EventBusTopicException):
        peb.is_registered('listener', 'any_topic')  # dumb args 

def test_publish_succeeds(patched_event_bus):
    peb = patched_event_bus

    result = peb.publish('topic_name', arg1='arg1', arg2='arg2')

    assert result

def test_publish_raises_message_missing_data_error(
        monkeypatch, patched_event_bus, send_missing_reqd_msgdata_error):

    peb = patched_event_bus
    mock_error = send_missing_reqd_msgdata_error 
    monkeypatch.setattr(peb._event_bus, 'sendMessage', mock_error) 

    with pytest.raises(EventBusMessageDataException):
        peb.publish('topic_name', arg1='anything')  # dumb args 

def test_publish_raises_unknown_message_data_error(
        monkeypatch, patched_event_bus, send_unknown_msgdata_error):

    peb = patched_event_bus
    mock_error = send_unknown_msgdata_error 
    monkeypatch.setattr(peb._event_bus, 'sendMessage', mock_error) 

    with pytest.raises(EventBusMessageDataException):
        peb.publish('topic_name', arg1='anything')  # dumb args 

def test_publish_raises_topicdefnerror(
        monkeypatch, patched_event_bus, topic_defn_error): 

    peb = patched_event_bus
    mock_error = topic_defn_error 
    monkeypatch.setattr(peb._event_bus, 'sendMessage', mock_error) 

    with pytest.raises(EventBusTopicException):
        peb.publish('topic_name', arg1='anything')  # dumb args 

def test_register_succeeds(patched_event_bus):

    peb = patched_event_bus

    result1, result2 = peb.register('callable', 'topic_name')

    assert (result1 and result2)

def test_register_raises_listener_mismatch_error(
        monkeypatch, patched_event_bus, listener_mismatch_error): 

    peb = patched_event_bus
    mock_error = listener_mismatch_error 
    monkeypatch.setattr(peb._event_bus, 'subscribe', mock_error) 

    with pytest.raises(EventBusSubscriptionException):
        peb.register('callable', 'topic_name')  # dumb args 

def test_register_raises_topicdefnerror(
        monkeypatch, patched_event_bus, topic_defn_error): 

    peb = patched_event_bus
    mock_error = topic_defn_error 
    monkeypatch.setattr(peb._event_bus, 'subscribe', mock_error) 

    with pytest.raises(EventBusTopicException):
        peb.register('callable', 'topic_name')  # dumb args 

def test_unregister_succeeds(patched_event_bus):

    peb = patched_event_bus
    result = peb.unregister('listener', 'topic_name')
    assert result

def test_unregister_raises_topicnameerror(
        monkeypatch, patched_event_bus, topic_name_error): 

    peb = patched_event_bus
    mock_error = topic_name_error 
    monkeypatch.setattr(peb._event_bus, 'unsubscribe', mock_error) 

    with pytest.raises(EventBusTopicException):
        peb.unregister('listener', 'topic_name')  # dumb args 

def test_unregister_raises_topicdefn_error(
        monkeypatch, patched_event_bus, topic_defn_error): 

    peb = patched_event_bus
    mock_error = topic_defn_error 
    monkeypatch.setattr(peb._event_bus, 'unsubscribe', mock_error) 

    with pytest.raises(EventBusTopicException):
        peb.unregister('listener', 'topic_name')  # dumb args 

def test_unregister_all(patched_event_bus):

    peb = patched_event_bus

    result = peb.unregister_all()

    assert isinstance(result, list)
