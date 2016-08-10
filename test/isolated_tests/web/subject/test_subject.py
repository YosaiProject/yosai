
# def test_web_subject_context_resolve_host_super
    """
    super resolves a host from session
    """

# def test_web_subject_context_resolve_host_webregistry
    """
    - super fails to resolve a host from session
    - resolve_web_registry().remote_host is returned
    """

# def test_web_subject_context_resolve_webregistry
    """
    returns self.web_registry
    """

# def test_web_subject_context_resolve_webregistry_no_registry_raises
    """
    - no self.web_registry exists
    - no subject.web_registry attribute
    - None is returned
    """

# def test_web_subject_context_resolve_webregistry_no_reg_returns_subject_wr
    """
    - no self.web_registry exists
    - returns subject.web_registry attribute
    """

# def test_web_subject_builder_create_subject_context

# def test_web_subject_builder_build_subject_raises
    """
    when the subject created by the security manager isn't a WebSubject, an
    exception raises
    """

# def test_web_subject_builder_build_subject_returns

# def test_web_delegating_subject_create_session_context

# def test_web_delegating_subject_get_session_not_create
    """
    when create=False, the session is touched
    """
# def test_web_delegating_subject_get_session_create
    """
    when create=True, the session is not touched -- verify this
    """

# def test_web_delegating_subject_proxied_session_stop
    """
    calls super's stop and owner.session_stopped()
    """

# def test_web_yosai_init_using_env_var
# def test_web_yosai_init_using_file_path
# def test_web_yosai_init_using_neither_arg_raises
    """
    A TypeError is raised when WebYosai is initialized without any arguments
    """

# def test_web_yosai_signed_cookie_secret_exists

# def test_web_yosai_get_subject_returns_subject

# def_context_sets

# def_context_pops

# def test_web_yosai_get_current_webregistry
# def test_web_yosai_get_current_webregistry_raises

# def test_web_yosai_requires_authentication
    """
    an authenticated subject will return a call to fn
    """

# def test_web_yosai_requires_authentication_raises
    """
    an unauthenticated subject will raise web_registry's unauthorized exception
    """

# def test_web_yosai_requires_user_calls_fn
# def test_web_yosai_requires_user_raises_unauthorized
    """
    a subject without identifiers will raise web_registry's unauthorized exception
    """

# def test_web_yosai_requires_guest_calls
# def test_web_yosai_requires_guest_raises
    """
    a subject with identifiers will raise web_registry's unauthorized exception
    """

# def test_web_yosai_requires_permission_calls
# def test_web_yosai_requires_permission_raises
    """
    a subject with insufficient permission raises
    """

# def test_web_yosai_requires_dynamic_permission_calls
# def test_web_yosai_requires_dynamic_permission_raises
    """
    a subject with insufficient permission raises
    """


# def test_web_yosai_requires_role_calls
# def test_web_yosai_requires_role_raises
