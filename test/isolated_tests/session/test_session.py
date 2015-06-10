import pytest
from unittest import mock

@pytest.mark.parametrize('field', ['session_id', 'start_timestamp'])
def test_ps_getter_confirm(mock_session, default_proxied_session, field):
    """
    unit tested:  every accessor (property) 

    test case:
    confirm that the proxy to delegate is working
    """
    dps = default_proxied_session  # uses mock_session
    ms = mock_session

    assert getattr(dps, field) == getattr(ms, field) 
