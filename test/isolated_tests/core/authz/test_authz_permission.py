import pytest
from unittest import mock

from yosai.core import (
    DefaultPermission,
    WildcardPermission,
)


# -----------------------------------------------------------------------------
# WildcardPermission Tests
# -----------------------------------------------------------------------------

def test_wcp_init_with_wildcard_string(monkeypatch):
    """
    unit tested:  __init__

    test case:
    control flow depending on whether a wildcard_string is passed
    """
    with mock.patch.object(WildcardPermission, 'setparts') as wp_sp:
        wp_sp.return_value = None
        wcs = WildcardPermission(wildcard_string='DOMAIN:ACTION:INSTANCE')
        assert wcs.setparts.called

def test_wcp_init_without_wildcard_string(monkeypatch):
    """
    unit tested:  __init__

    test case:
    control flow depending on whether a wildcard_string is passed
    """
    with mock.patch.object(WildcardPermission, 'setparts') as wp_sp:
        wp_sp.return_value = None
        with pytest.raises(ValueError):
            wcs = WildcardPermission()


def test_wcp_setparts_casesensitive(
        default_wildcard_permission, monkeypatch):
    """
    unit tested:  setparts

    test case:
    case_sensitive parts remain as-is
    """
    wcp = default_wildcard_permission
    monkeypatch.setattr(wcp, 'case_sensitive', True)
    wildcardstring = "One,Two,Three:Four,Five,Six:Seven,Eight"
    wcp.setparts(wildcard_string=wildcardstring)
    expected_parts = {'domain': set(['One', 'Two', 'Three']),
                      'action': set(['Four', 'Five', 'Six']),
                      'target': set(['Seven', 'Eight'])}
    assert expected_parts == wcp.parts

def test_wcp_setparts(default_wildcard_permission, monkeypatch):
    """
    unit tested:  setparts

    test case:
    verify normal, successful activity
    """
    wcp = default_wildcard_permission
    monkeypatch.setattr(wcp, 'case_sensitive', True)
    wildcardstring = "one,two,three:four,five,six:seven,eight"
    wcp.setparts(wildcard_string=wildcardstring)
    expected_parts = {}
    expected_parts['domain'] = set(['one', 'two', 'three'])
    expected_parts['action'] = set(['four', 'five', 'six'])
    expected_parts['target'] = set(['seven', 'eight'])
    assert expected_parts == wcp.parts

def test_wcp_implies_nonwildcardpermission(default_wildcard_permission):
    """
    unit tested:  implies

    test case:
    implies currently only supports instances of WildcardPermission
    """
    wcp = default_wildcard_permission
    otherpermission = type('OtherPermission', (object,), {})
    result = wcp.implies(otherpermission())
    assert result is False

@pytest.mark.parametrize("wildcardstring1,wildcardstring2",
                         [("something", "SOMETHING"),
                          ("SOMETHING", "something"),
                          ("something", "something")])
def test_wcp_implies_caseinsensitive_returns_true(
        wildcardstring1, wildcardstring2):
    """
    unit tested:  implies

    test case:
    Case insensitive, single-name permission, returns True
    """
    p1 = WildcardPermission(wildcardstring1)
    p2 = WildcardPermission(wildcardstring2)
    assert p1.implies(p2)

@pytest.mark.parametrize("wildcardstring1,wildcardstring2",
                         [("something", "SOMETHINGELSEENTIRELY"),
                          ("SOMETHINGELSE", "somethingAGAIN")])
def test_wcp_implies_caseinsensitive_returns_false(
        wildcardstring1, wildcardstring2):
    """
    unit tested:  implies

    test case:
    Case insensitive, single-name permission, returns False
    """
    p1 = WildcardPermission(wildcardstring1)
    p2 = WildcardPermission(wildcardstring2)
    assert not p1.implies(p2)

@pytest.mark.parametrize("wildcardstring1,wildcardstring2",
                         [("something", "something")])
def test_wcp_implies_casesensitive_returns_true(
        wildcardstring1, wildcardstring2):
    """
    unit tested:  implies

    test case:
    Case sensitive, single-name permission,returns True
    """
    p1 = WildcardPermission(wildcard_string=wildcardstring1,
                            case_sensitive=True)
    p2 = WildcardPermission(wildcard_string=wildcardstring2,
                            case_sensitive=True)
    assert p1.implies(p2)

@pytest.mark.parametrize("wildcardstring1,wildcardstring2",
                         [("Something", "someThing"),
                          ("diFFerent", "reallyDifferent")])
def test_wcp_implies_casesensitive_returns_false(
        wildcardstring1, wildcardstring2):
    """
    unit tested:  implies

    test case:
    Case sensitive, single-name permission, returns False
    """
    p1 = WildcardPermission(wildcard_string=wildcardstring1,
                            case_sensitive=True)
    p2 = WildcardPermission(wildcard_string=wildcardstring2,
                            case_sensitive=True)
    assert not p1.implies(p2)

@pytest.mark.parametrize("wildcardstring1,wildcardstring2",
                         [("one,two", "one"),
                          ("one,two,three", "one,three"),
                          ("one,two:one,two,three", "one:three"),
                          ("one,two:one,two,three", "one:two,three"),
                          ("one:two,three", "one:three"),
                          ("one,two,three:one,two,three:one,two",
                           "one:three:two"),
                          ("one", "one:two,three,four"),
                          ("one", "one:two,three,four:five:six:seven"),
                          ("one:two,three,four",
                           "one:two,three,four:five:six:seven")])
def test_wcp_implies_caseinsensitive_lists(
        wildcardstring1, wildcardstring2):
    """
    unit tested:  implies

    test case:
    Case insensitive, list-based permission, retrns True and the opposite False
    """

    p1 = WildcardPermission(wildcard_string=wildcardstring1)
    p2 = WildcardPermission(wildcard_string=wildcardstring2)

    assert p1.implies(p2) and not p2.implies(p1)


@pytest.mark.parametrize("wildcardstring1,wildcardstring2",
                         [("*", "one"),
                          ("*", "one:two"),
                          ("*", "one,two:three,four"),
                          ("*", "one,two:three,four,five:six:seven,eight"),
                          ("newsletter:*", "newsletter:read"),
                          ("newsletter:*", "newsletter:read,write"),
                          ("newsletter:*", "newsletter:*"),
                          ("newsletter:*", "newsletter:*:*"),
                          ("newsletter:*", "newsletter:*:read"),
                          ("newsletter:*", "newsletter:write:*"),
                          ("newsletter:*", "newsletter:read,write:*"),
                          ("newsletter:*:*", "newsletter:read"),
                          ("newsletter:*:*", "newsletter:read,write"),
                          ("newsletter:*:*", "newsletter:*"),
                          ("newsletter:*:*", "newsletter:*:*"),
                          ("newsletter:*:*", "newsletter:*:read"),
                          ("newsletter:*:*", "newsletter:write:*"),
                          ("newsletter:*:*", "newsletter:read,write:*"),
                          ("newsletter:*:*:*", "newsletter:read"),
                          ("newsletter:*:*:*", "newsletter:read,write"),
                          ("newsletter:*:*:*", "newsletter:*"),
                          ("newsletter:*:*:*", "newsletter:*:*"),
                          ("newsletter:*:*:*", "newsletter:*:read"),
                          ("newsletter:*:*:*", "newsletter:write:*"),
                          ("newsletter:*:*:*", "newsletter:read,write:*"),
                          ("newsletter:*:read", "newsletter:123:read"),
                          ("newsletter:*:read", "newsletter:123:read:write"),
                          ("newsletter:*:read:*", "newsletter:123:read"),
                          ("newsletter:*:read:*", "newsletter:123:read:write")])
def test_wcp_implies_caseinsensitive_wildcards_true(
        wildcardstring1, wildcardstring2):
    """
    unit tested:  implies

    test case:
    Case insensitive, wildcard-based permission, retrns True
    """
    p1 = WildcardPermission(wildcard_string=wildcardstring1)
    p2 = WildcardPermission(wildcard_string=wildcardstring2)

    assert p1.implies(p2)

@pytest.mark.parametrize("wildcardstring1,wildcardstring2",
                         [("newsletter:*:read", "newsletter:123,456:read,write"),
                          ("newsletter:*:read", "newsletter:read"),
                          ("newsletter:*:read", "newsletter:read,write")])
def test_wcp_implies_caseinsensitive_wildcards_false(
        wildcardstring1, wildcardstring2):
    """
    unit tested:  implies

    test case:
    Case insensitive, wildcard-based permission, retrns False
    """
    p1 = WildcardPermission(wildcard_string=wildcardstring1)
    p2 = WildcardPermission(wildcard_string=wildcardstring2)

    assert not p1.implies(p2)

def test_wcp_equals():
    """
    unit tested:

    test case:

    """

    wildcard_string = 'somestring'
    p1 = WildcardPermission(wildcard_string)
    p2 = WildcardPermission(wildcard_string)

    assert p1 == p2

def test_wcp_not_equals_bad_type():
    """
    unit tested:

    test case:

    """
    wildcard_string = 'somestring'
    p1 = WildcardPermission(wildcard_string)
    othertype = type('OtherPermissionType', (object,), {})
    p2 = othertype()

    assert not p1 == p2



# -----------------------------------------------------------------------------
# DefaultPermission Tests
# -----------------------------------------------------------------------------

@mock.patch.object(WildcardPermission, '__init__', return_value=None)
def test_dp_init_wildcard(mock_wpi):
    result = DefaultPermission(wildcard_string='domain1:action1')
    mock_wpi.assert_called_once_with(wildcard_string='domain1:action1')


def test_dp_init_parts():
    parts = {'domain': 'domain1', 'action': ['action1'], 'target': ['target1']}
    expected_parts = {'domain': {'domain1'}, 'action': {'action1'}, 'target': {'target1'}}
    dp = DefaultPermission(parts=parts)
    assert dp.parts == expected_parts


def test_dp_setstate():
    parts = {'domain': 'domain1', 'action': ['action1'], 'target': ['target1']}
    state = {'parts': parts}

    expected_parts = {'domain': {'domain1'}, 'action': {'action1'}, 'target': {'target1'}}

    dp = DefaultPermission.__new__(DefaultPermission)
    dp.__setstate__(state)

    assert dp.parts == expected_parts


@pytest.mark.parametrize(
    "domain,actions,targets,permission",
    [('domain', 'action1,action2,action3', 'target1,target2,target3',
      'domain:action1,action2,action3:target1,target2,target3'),
     ('domain', None, 'target1,target2,target3',
      'domain:*:target1,target2,target3'),
     ('domain', 'action1,action2,action3', None,
      'domain:action1,action2,action3:*')])
def test_dp_encode_parts_creates_permission(
        default_permission, domain, actions, targets, permission):
    """
    unit tested:  encode_parts

    test case:

    """
    ddp = default_permission
    encoded_permission = ddp.encode_parts(domain, actions, targets)
    assert encoded_permission == permission


def test_set_parts_domain(default_permission):
    """
    unit tested:  set_parts

    test case:
    sets are turned into strings and then passed on to super
    """

    ddp = default_permission
    with mock.patch.object(DefaultPermission, 'encode_parts') as ep:
        ep.return_value = None
        with mock.patch.object(WildcardPermission, 'setparts') as wc_sp:
            wc_sp.return_value = None
            ddp.set_parts({'domain'}, None, None)
            ep.assert_called_once_with(domain='domain', action=None, target=None)


def test_set_parts_action(default_permission):
    """
    unit tested:  set_parts

    test case:
    sets are turned into strings and then passed on to super
    """

    ddp = default_permission
    with mock.patch.object(DefaultPermission, 'encode_parts') as ep:
        ep.return_value = None
        with mock.patch.object(WildcardPermission, 'setparts') as wc_sp:
            wc_sp.return_value = None
            ddp.set_parts(None, {'action1', 'action2'}, None)
            call = ep.call_args_list[0]
            assert((call == mock.call(action='action1,action2', domain=None, target=None))
                   or
                   (call == mock.call(action='action2,action1', domain=None, target=None)))


def test_set_parts_target(default_permission):
    """
    unit tested:  set_parts

    test case:
    sets are turned into strings and then passed on to super
    """

    ddp = default_permission
    with mock.patch.object(DefaultPermission, 'encode_parts') as ep:
        ep.return_value = None
        with mock.patch.object(WildcardPermission, 'setparts') as wc_sp:
            wc_sp.return_value = None
            ddp.set_parts(None, None, {'target1', 'target2'})
            call = ep.call_args_list[0]
            assert((call == mock.call(action=None, domain=None, target='target1,target2'))
                   or
                   (call == mock.call(action=None, domain=None, target='target2,target1')))
