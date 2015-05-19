import pytest

from yosai import (
    Event,
    EventBus,
)

@pytest.fixture(scope='function')
def default_event():
    return Event(event_type='default_event_type',
                 event_topic='default_event_topic',
                 source='source_object_here')

@pytest.fixture(scope='function')
def default_event_bus():
    return EventBus()
