#def test_create_yosai_instance
    """
    Create a new WebYosai instance from env_var settings and from file_path
    settings.  This subsequently creates a configured WebSecurityManager.
    """

#def test_security_manager_configuration
    """
    Assert that upon creation of a new WebYosai instance that the managers
    automatically generated using yaml settings are as expected.
    """


#def test_cookie_secret_settings
    """
    confirm that the signed cookie secret settings are available from WebYosai
    """


#def test_web_context
    """
    When entering a new WebYosai context, a yosai instance is pushed onto a yosai_context
    stack and a web_registry is pushed onto a yosai_webregistry_context stack.
    When closing the context: the pushed yosai instance is popped from the
    yosai_context stack, the pushed web_registry is popped from the
    yosai_webregistry_context, and the current executing subject is popped
    from the global_subject_context stack.

    elements tested include:
        get_current_yosai
        get_current_webregistry
        get_current_subject
    """

#def test_requires_authentication
    """
    This test verifies that the decorator works as expected.
    Two parametrized tests:  one that succeeds and another that fails
    """

#def test_requires_user
    """
    This test verifies that the decorator works as expected.
    Two parametrized tests:  one that succeeds and another that fails
    """

#def test_requires_guest
    """
    This test verifies that the decorator works as expected.
    Two parametrized tests:  one that succeeds and another that fails
    """

#def test_requires_permission
    """
    This test verifies that the decorator works as expected.
    Two parametrized tests:  one that succeeds and another that fails
    """

#def test_requires_dynamic_permission
    """
    This test verifies that the decorator works as expected.
    Two parametrized tests:  one that succeeds and another that fails
    """

#def test_requires_role
    """
    This test verifies that the decorator works as expected.
    Two parametrized tests:  one that succeeds and another that fails
    """
