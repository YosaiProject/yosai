def test_ipv_get_authzd_permissions(
        indexed_permission_verifier, monkeypatch, indexed_authz_info):
    """
    objects tested:  indexed_authz_info, indexed_authz_info

    test case:
    returns the permissions from the authzinfo that are relevant to the
    permission argument
    """
    ipv = indexed_permission_verifier
    perms = [DefaultPermission('domain4:action4'),
             DefaultPermission('domain5:action1')]

    expected = frozenset([DefaultPermission(domain={'domain4'}, 
                                            action={'action1', 'action2'}),
                          DefaultPermission(domain={'domain4'}, 
                                            action={'action3'}, 
                                            target={'target1'}),
                          DefaultPermission(wildcard_string='*:action5')])

    result = ipv.get_authzd_permissions(indexed_authz_info, perms)

    assert expected == result

