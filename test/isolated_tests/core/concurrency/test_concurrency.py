from unittest import mock
import threading
import time
from yosai.core import (
    StoppableScheduledExecutor,
)


def test_sse_stops(stoppable_scheduled_executor):
    sse = stoppable_scheduled_executor
    with mock.patch.object(threading.Thread, 'join') as mock_join:
        sse.stop()
        assert sse.event.is_set() and mock_join.called


def test_sse_runs(stoppable_scheduled_executor):
    sse = stoppable_scheduled_executor
    with mock.patch.object(StoppableScheduledExecutor, 'run') as mock_run:
        sse.start()
        time.sleep(1)
        sse.stop()
        assert mock_run.called
