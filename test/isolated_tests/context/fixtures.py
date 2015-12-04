from yosai.core import (
    MapContext,
)

import pytest

@pytest.fixture(scope='function')
def default_map_context():
    return MapContext({'attr1': 'attribute1', 
                       'attr2': 'attribute2',
                       'attr3': 'attribute3'})

