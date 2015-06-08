import pytest
from unittest import mock

from yosai import (
    DomainPermission,
    IllegalArgumentException,
    IllegalStateException,
    ModularRealmAuthorizer,
    OrderedSet,
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
    with mock.patch.object(WildcardPermission, 'set_parts') as wp_sp:
        wp_sp.return_value = None 
        wcs = WildcardPermission(wildcard_string='DOMAIN:ACTION:INSTANCE')
        assert wcs.set_parts.called

def test_wcp_init_without_wildcard_string(monkeypatch):
    """
    unit tested:  __init__

    test case:
    control flow depending on whether a wildcard_string is passed
    """
    with mock.patch.object(WildcardPermission, 'set_parts') as wp_sp:
        wp_sp.return_value = None 
        wcs = WildcardPermission()
        assert not wcs.set_parts.called

@pytest.mark.parametrize("wildcardstring", [None, '', "  ", ":::", "A:,,:C:D"])
def test_wcp_set_parts_raises_illegalargumentexception(
        default_wildcard_permission, wildcardstring):
    """
    unit tested:  set_parts

    test case:
    wilcard_string must be populated with parts, else an exception raises
    """

    wcp = default_wildcard_permission

    with pytest.raises(IllegalArgumentException):
        wcp.set_parts(wildcard_string=wildcardstring)

def test_wcp_set_parts_casesensitive(
        default_wildcard_permission, monkeypatch):
    """
    unit tested:  set_parts

    test case:
    case_sensitive parts remain as-is
    """
    wcp = default_wildcard_permission
    monkeypatch.setattr(wcp, 'case_sensitive', True)
    wildcardstring = "One,Two,Three:Four,Five,Six:Seven,Eight"
    wcp.set_parts(wildcard_string=wildcardstring)
    expected_parts = [OrderedSet(['One', 'Two', 'Three']),
                      OrderedSet(['Four', 'Five', 'Six']),
                      OrderedSet(['Seven', 'Eight'])]
    assert expected_parts == wcp.parts

def test_wcp_set_parts(default_wildcard_permission, monkeypatch):
    """
    unit tested:  set_parts

    test case:
    verify normal, successful activity
    """
    wcp = default_wildcard_permission
    monkeypatch.setattr(wcp, 'case_sensitive', True)
    wildcardstring = "one,two,three:four,five,six:seven,eight"
    wcp.set_parts(wildcard_string=wildcardstring)
    expected_parts = [OrderedSet(['one', 'two', 'three']),
                      OrderedSet(['four', 'five', 'six']),
                      OrderedSet(['seven', 'eight'])]
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
    wildcard_string = 'somestring'
    p1 = WildcardPermission(wildcard_string)
    p2 = WildcardPermission(wildcard_string)

    assert p1 == p2

def test_wcp_not_equals_bad_type():
    wildcard_string = 'somestring'
    p1 = WildcardPermission(wildcard_string)
    othertype = type('OtherPermissionType', (object,), {})
    p2 = othertype()

    assert not p1 == p2


# -----------------------------------------------------------------------------
# WildcardPermissionResolver Tests
# -----------------------------------------------------------------------------
def test_wcpr_returns_wcp():
    wcp = WildcardPermissionResolver.resolve_permission('testing123')
    assert isinstance(wcp, WildcardPermission)


# -----------------------------------------------------------------------------
# DomainPermission Tests
# -----------------------------------------------------------------------------
def test_dp_init_no_actions_no_targets(monkeypatch):
    """
    unit tested:  __init__

    test case:
    when neither actions nor targets are passed as arguments, set_parts is 
    called
    """
    with mock.patch.object(DomainPermission, 'set_parts') as sp:
        sp.return_value = None
        DomainPermission()
        assert sp.assert_called_once_with(domain='domain', actions=None, 
                                          targets=None) is None

def test_dp_init_setactions_settargets(monkeypatch):
    """
    unit tested:  __init__

    test case:
    when actions and targets are passed as sets, set_parts is called
    """
    with mock.patch.object(DomainPermission, 'set_parts') as sp:
        sp.return_value = None

        actions = OrderedSet(['action1', 'action2'])
        targets = OrderedSet(['target1', 'target2'])
        DomainPermission(actions=actions, targets=targets)
        assert sp.assert_called_once_with(domain='domain',
                                          actions=actions,
                                          targets=targets) is None

def test_dp_init_no_actions_default_targets(monkeypatch):
    """
    unit tested:  __init__

    test case:
    initializing without actions but with a targets raises an exception
    """
    targets = OrderedSet(['target1', 'target2'])
    with pytest.raises(IllegalArgumentException):
        DomainPermission(targets=targets)

def test_dp_init_stractions_strtargets(monkeypatch):
    """
    unit tested:  __init__

    test case:
    passing a string-typed actions or a string-typed targets converts 
    to set(s) and calls encode_parts
    """
    actions = 'action1,action2'
    actionset = OrderedSet(['action1', 'action2'])
    targets = 'target1,target2'
    targetset = OrderedSet(['target1', 'target2'])

    with mock.patch.object(DomainPermission, 'encode_parts') as ep:
        ep.return_value = None
        DomainPermission(actions=actions, targets=targets)
        assert ep.assert_called_once_with(domain='domain',
                                          actions=actionset,
                                          targets=targetset) is None


