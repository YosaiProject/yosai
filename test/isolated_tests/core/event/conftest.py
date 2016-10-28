import pytest

from yosai.core import (
    EventLogger,
)


@pytest.fixture(scope='function')
def event_logger(event_bus):
    return EventLogger(event_bus)
