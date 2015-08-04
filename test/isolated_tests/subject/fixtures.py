import pytest

from yosai import (
    DefaultSubjectContext,
)

@pytest.fixture(scope='function')
def subject_context():
    mydict = {'attr1': 'attribute1'}
    return mydict


@pytest.fixture(scope='function')
def default_subject_context(subject_context):
    return DefaultSubjectContext(subject_context)
