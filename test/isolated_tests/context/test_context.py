import pytest
from yosai import (
    IllegalArgumentException,
    MapContext,
)


def test_mapcontext_init():
    MapContext()

def test_mapcontext_attributes(default_map_context):
    assert isinstance(default_map_context.attributes, list)

def test_mapcontext_values(default_map_context):
    assert isinstance(default_map_context.values, tuple)

def test_mapcontext_clear(default_map_context):
    default_map_context.clear()
    assert len(default_map_context.context) == 0

def test_mapcontext_len(default_map_context):
    assert default_map_context.size() == 3

def test_mapcontext_nonzero():
    emptycontext1 = MapContext()
    emptycontext2 = MapContext({'one': 1})
    assert emptycontext1.is_empty and not emptycontext2.is_empty

def test_mapcontext_contains(default_map_context):
    assert ('nine' not in default_map_context and
            'attribute2' not in default_map_context and
            'attr3' in default_map_context)

def test_mapcontext_setattr(default_map_context):
    default_map_context.put('test', 'testing')
    assert default_map_context.context.get('test') == 'testing'

def test_mapcontext_getattr(default_map_context):
    assert default_map_context.get('attr2') == 'attribute2'

def test_mapcontext_delattr(default_map_context):
    default_map_context.remove('attr1')
    assert default_map_context.context.get('attr1', 'nope') == 'nope'

def test_put_all(default_map_context):
    test_context = MapContext({'attrX': 'attributeX',
                               'attrY': 'attributeY'})

    default_map_context.put_all(test_context)

    assert 'attrY' in default_map_context

def test_put_all_raises(default_map_context):
    test_context = {'attrX': 'attributeX', 'attrY': 'attributeY'}

    with pytest.raises(IllegalArgumentException):
        default_map_context.put_all(test_context)

