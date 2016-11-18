import pytest


@pytest.fixture(scope='function')
def sample_parts():
    return {'domain': 'domain1', 'action': ['action1', 'action2'], 'target': ['target1']}
