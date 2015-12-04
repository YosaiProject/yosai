import pytest
from yosai.core import (
    StoppableScheduledExecutor,
)


@pytest.fixture(scope='function')
def stoppable_scheduled_executor():

    def test_func():
        print('test_func')

    return StoppableScheduledExecutor(my_func=test_func, interval=10)  # seconds
