
#def test_web_subject_factory_create_subject_not_websubjectcontext
    """
    when the subject_context argument is a DefaultSubjectcontext, super's
    create_subject method is called and its value returned
    """

#def test_web_subject_factory_create_subject
    """
    A WebDelegatingSubject is created and returned when a fully formed web subject
    context is passed to create_subject
    """

#def test_web_security_manager_init
    """
    Initializes through super and sets the subject store's session_storage_evaluator.
    Confirm that the managers are created as expected.
    """

# def test_web_security_manager_create_subject_context_raises
    """
    without a security_utils, an exception is raised
    """

# def test_web_security_manager_create_subject_context
    """
    returns a new DefaultWebSubjectContext containing security_utils, self,
    and web_registry
    """

#def test_web_security_manager_session_manager_setter
    """
    calls super's session_manager setter and then sets the session_storage_evaluator's
    session_manager
    """

#def test_web_security_manager_create_session_context
    """
    creates and returns a DefaultWebSessionContext
    """

#def test_web_security_manager_get_session_key_raise_revert
    """
    if resolve_web_registry raises an AttributeError, it means a WebSubjectContext
    wasn't passed, and consequently super's get_session_key is called with
    the subject_context
    """

def test_web_security_manager_get_session_key
    """
    creates and returns a WebSessionKey
    """

#def test_web_security_manager_before_logout
    """
    super's before_logout is called and then remove_identity
    """

#def test_web_security_manager_remove_identity_raise_passes
    """
    an AttributeError indicates that a WebSubject wasn't passed, and so nothing
    happens
    """

#def test_web_security_manager_remove_identity
    """
    the subject's web_registry.remember_me cookie deleter is called
    """

#def test_web_security_manager_on_successful_login
    """
    a new csrf token gets generated and then super's remember_me_successful_login
    is called
    """

#def test_cookie_rmm_remember_init
    """
    calls super init
    """

#def test_cookie_rmm_remember_encrypted_identity
    """
    subject's web_registry remember_me cookie is set to the encoded value
    """

#def test_cookie_rmm_remember_encrypted_identity_raises
    """
    an AttributeError results simply in debug logging
    """

#def test_cookie_rmm_is_identityremoved_raises_returns_false
    """
    An AttributeError results in returning False
    """

# def test_cookie_rmm_is_identityremoved
    """
    The webregistry's remember_me cookie is resolved and returns a check whether
    remember_me is set
    """

# def test_get_remembered_encrypted_identity_removed_instance
    """
    scenario:
        - the subject_context already had its remember_me identity removed
        - the subject_context isnt a WebSubjectContext

    None returned
    """

# def test_get_remembered_encrypted_identity_removed_not_instance
    """
    scenario:
        - the subject_context already had its remember_me identity removed
        - the subject_context isnt a WebSubjectContext

    logger debug followed by None returned
    """

# def test_get_remembered_encrypted_identity_remember_me
    """
    remember_me cookie exists, so it is b64 decoded and the encrypted val returned
    """

# def test_get_remembered_encrypted_identity_no_remember_me
    """
    no remember_me cookie will return None
    """

#def test_forget_identity
    """
    the subject's webregistry remember_me cookie deleter is called
    """
