import pytest
from unittest import mock
from collections import OrderedDict

from yosai import (
    DefaultPermission,
    IllegalArgumentException,
    IllegalStateException,
    ModularRealmAuthorizer,
    SimpleRole,
    UnauthorizedException,
    WildcardPermission,
    WildcardPermissionResolver,
)

from .doubles import (
    MockPermission,
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
        wcs = WildcardPermission()
        assert not wcs.setparts.called

@pytest.mark.parametrize("wildcardstring", [None, '', "  ", ":::", "A:,,:C:D"])
def test_wcp_setparts_raises_illegalargumentexception(
        default_wildcard_permission, wildcardstring):
    """
    unit tested:  setparts

    test case:
    wilcard_string must be populated with parts, else an exception raises
    """

    wcp = default_wildcard_permission

    with pytest.raises(IllegalArgumentException):
        wcp.setparts(wildcard_string=wildcardstring)

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
    expected_parts = {'domain': frozenset(['One', 'Two', 'Three']),
                      'action': frozenset(['Four', 'Five', 'Six']),
                      'target': frozenset(['Seven', 'Eight'])}
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
    expected_parts['domain'] = frozenset(['one', 'two', 'three'])
    expected_parts['action'] = frozenset(['four', 'five', 'six'])
    expected_parts['target'] = frozenset(['seven', 'eight'])
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
# WildcardPermissionResolver Tests
# -----------------------------------------------------------------------------
def test_wcpr_returns_wcp():
    """
    unit tested:

    test case:

    """
    wcp = WildcardPermissionResolver.resolve_permission('testing123')
    assert isinstance(wcp, WildcardPermission)


# -----------------------------------------------------------------------------
# DefaultPermission Tests
# -----------------------------------------------------------------------------

@pytest.mark.parametrize(
    "actions,targets,actionset,targetset",
    [(None, None, set(['*']), set(['*'])),
     ('action1,action2', 'target1,target2',
      set(['action1', 'action2']), set(['target1', 'target2'])),
     (set(['action1', 'action2']), set(['target1', 'target2']),
      set(['action1', 'action2']), set(['target1', 'target2']))])
def test_dp_normal_init(actions, targets, actionset, targetset):
    """
    unit tested:  __init__

    test case:
    confirm that the DefaultPermission initializes as expected
    """
    ddp = DefaultPermission(action=actions, target=targets)
    assert (ddp.action == actionset and ddp.target == targetset)

def test_dp_domain_setter_sets_parts(default_permission):
    """
    unit tested:  domain.setter

    test case:
    setting domain in turn calls set_parts
    """
    ddp = default_permission
    ddp.domain = 'test'
    assert ddp.domain == frozenset({'test'})

def test_dp_action_setter_sets_parts(default_permission):
    """
    unit tested:  action.setter

    test case:
    setting actions in turn calls set_parts
    """
    ddp = default_permission
    dumbactions = set(['actiona', 'actionb', 'actionc'])
    ddp.action = dumbactions
    assert ddp.action == frozenset(dumbactions)

def test_dp_targets_setter_sets_parts(default_permission):
    """
    unit tested:  targets.setter

    test case:

    """
    ddp = default_permission
    dumbtargets = set(['targeta', 'targetb', 'targetc'])
    ddp.target = dumbtargets
    assert ddp.target == frozenset(dumbtargets)

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
