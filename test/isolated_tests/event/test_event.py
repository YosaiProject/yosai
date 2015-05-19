import pytest
import calendar
import time

from yosai import (
    Event,
    EventBus,
)

# -----------------------------------------------------------------------------
# Event Tests
# -----------------------------------------------------------------------------

def test_event_timestamp_verify(default_event):
    """ timestamp integrity is vital, so confirm that it is working """
    timestamp = calendar.timegm(time.gmtime())
    assert (timestamp - default_event.timestamp) <= 10 

def test_event_attr_set():
    test_event = Event(event_topic='topic1',
                       event_type='type1',
                       source='source',
                       attr1=type('Attr1', (object,), {}))
    assert hasattr(test_event, 'attr1')

# -----------------------------------------------------------------------------
# EventBus Tests
# -----------------------------------------------------------------------------
def test_if_subscribed
