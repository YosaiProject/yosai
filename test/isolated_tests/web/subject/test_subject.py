import pytest
from unittest import mock
from yosai.core.subject.subject import global_subject_context, global_yosai_context
from yosai.web.subject.subject import global_webregistry_context

from yosai.core import (
    AuthorizationException,
    IdentifiersNotSetException,
)

from yosai.web import (
    WebYosai,
    WebDelegatingSubject,
)


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

# def test_web_yosai_get_current_webregistry
# def test_web_yosai_get_current_webregistry_raises


def test_web_context(web_yosai, mock_web_registry):
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
    # first ensure that the threadlocal is empty
    assert (global_subject_context.stack == [] and
            global_yosai_context.stack == [] and
            global_webregistry_context.stack == [])

    with WebYosai.context(web_yosai, mock_web_registry):
        assert (global_subject_context.stack == [] and
                global_yosai_context.stack == [web_yosai] and
                global_webregistry_context.stack == [mock_web_registry])

    # this tests context exit
    assert (global_subject_context.stack == [] and
            global_yosai_context.stack == [] and
            global_webregistry_context.stack == [])


def test_requires_authentication_succeeds(monkeypatch):
    """
    This test verifies that the decorator works as expected.
    """
    @staticmethod
    def mock_gcs():
        return mock.MagicMock(authenticated=True)

    @staticmethod
    def mock_cwr():
        m = mock.MagicMock()
        m.raise_unauthorized.return_value = Exception
        return m

    monkeypatch.setattr(WebYosai, 'get_current_subject', mock_gcs)
    monkeypatch.setattr(WebYosai, 'get_current_webregistry', mock_cwr)

    @WebYosai.requires_authentication
    def do_this():
        return 'dothis'

    result = do_this()

    assert result == 'dothis'


def test_requires_authentication_raises(monkeypatch):
    """
    This test verifies that the decorator works as expected.
    """
    @staticmethod
    def mock_gcs():
        return mock.MagicMock(authenticated=False)

    @staticmethod
    def mock_cwr():
        m = mock.MagicMock()
        m.raise_unauthorized.return_value = Exception
        return m

    monkeypatch.setattr(WebYosai, 'get_current_subject', mock_gcs)
    monkeypatch.setattr(WebYosai, 'get_current_webregistry', mock_cwr)

    @WebYosai.requires_authentication
    def do_this():
        return 'dothis'

    with pytest.raises(Exception):
        do_this()


def test_requires_user_succeeds(monkeypatch):
    """
    This test verifies that the decorator works as expected.
    """
    @staticmethod
    def mock_gcs():
        return mock.MagicMock(identifiers='username12345')

    @staticmethod
    def mock_cwr():
        m = mock.MagicMock()
        m.raise_unauthorized.return_value = Exception
        return m

    monkeypatch.setattr(WebYosai, 'get_current_subject', mock_gcs)
    monkeypatch.setattr(WebYosai, 'get_current_webregistry', mock_cwr)

    @WebYosai.requires_user
    def do_this():
        return 'dothis'

    result = do_this()

    assert result == 'dothis'


def test_requires_user_raises(monkeypatch):
    """
    This test verifies that the decorator works as expected.
    """
    @staticmethod
    def mock_gcs():
        return mock.MagicMock(identifiers=None)

    @staticmethod
    def mock_cwr():
        m = mock.MagicMock()
        m.raise_unauthorized.return_value = Exception
        return m

    monkeypatch.setattr(WebYosai, 'get_current_subject', mock_gcs)
    monkeypatch.setattr(WebYosai, 'get_current_webregistry', mock_cwr)

    @WebYosai.requires_user
    def do_this():
        return 'dothis'

    with pytest.raises(Exception):
        do_this()


def test_requires_guest(monkeypatch):
    """
    This test verifies that the decorator works as expected.
    Two parametrized tests:  one that succeeds and another that fails
    """
    @staticmethod
    def mock_gcs():
        return mock.MagicMock(identifiers=None)

    @staticmethod
    def mock_cwr():
        m = mock.MagicMock()
        m.raise_unauthorized.return_value = Exception
        return m

    monkeypatch.setattr(WebYosai, 'get_current_subject', mock_gcs)
    monkeypatch.setattr(WebYosai, 'get_current_webregistry', mock_cwr)

    @WebYosai.requires_guest
    def do_this():
        return 'dothis'

    result = do_this()

    assert result == 'dothis'


def test_requires_guest_raises(monkeypatch):

    @staticmethod
    def mock_gcs():
        return mock.MagicMock(identifiers='userid12345')

    @staticmethod
    def mock_cwr():
        m = mock.MagicMock()
        m.raise_unauthorized.return_value = Exception
        return m

    monkeypatch.setattr(WebYosai, 'get_current_subject', mock_gcs)
    monkeypatch.setattr(WebYosai, 'get_current_webregistry', mock_cwr)

    @WebYosai.requires_guest
    def do_this():
        return 'dothis'

    with pytest.raises(Exception):
        do_this()


def test_requires_permission_succeeds(monkeypatch):
    """
    This test verifies that the decorator works as expected.
    """
    mock_wds = mock.create_autospec(WebDelegatingSubject)

    @staticmethod
    def mock_gcs():
        return mock_wds

    monkeypatch.setattr(WebYosai, 'get_current_subject', mock_gcs)

    @WebYosai.requires_permission(['something:anything'])
    def do_this():
        return 'dothis'

    result = do_this()

    assert result == 'dothis'
    mock_wds.check_permission.assert_called_once_with(['something:anything'], all)


def test_requires_permission_raises_one(monkeypatch):

    @staticmethod
    def mock_gcs():
        m = mock.create_autospec(WebDelegatingSubject)
        m.check_permission.side_effect = IdentifiersNotSetException

    @staticmethod
    def mock_cwr():
        m = mock.MagicMock()
        m.raise_unauthorized.return_value = Exception
        m.raise_forbidden.return_value = Exception
        return m

    monkeypatch.setattr(WebYosai, 'get_current_subject', mock_gcs)
    monkeypatch.setattr(WebYosai, 'get_current_webregistry', mock_cwr)

    @WebYosai.requires_permission(['something_anything'])
    def do_this():
        return 'dothis'

    with pytest.raises(Exception):
        do_this()


def test_requires_permission_raises_two(monkeypatch):

    mock_wds = mock.create_autospec(WebDelegatingSubject)
    mock_wds.check_permission.side_effect = AuthorizationException

    @staticmethod
    def mock_gcs():
        return mock_wds

    @staticmethod
    def mock_cwr():
        m = mock.MagicMock()
        m.raise_unauthorized.return_value = Exception
        m.raise_forbidden.return_value = Exception
        return m

    monkeypatch.setattr(WebYosai, 'get_current_subject', mock_gcs)
    monkeypatch.setattr(WebYosai, 'get_current_webregistry', mock_cwr)

    @WebYosai.requires_permission(['something_anything'])
    def do_this():
        return 'dothis'

    with pytest.raises(Exception):
        do_this()


def test_requires_dynamic_permission_succeeds(monkeypatch):
    """
    This test verifies that the decorator works as expected.
    """
    mock_wds = mock.create_autospec(WebDelegatingSubject)

    @staticmethod
    def mock_gcs():
        return mock_wds

    @staticmethod
    def mock_cwr():
        m = mock.MagicMock()
        m.resource_params = {'one': 'one'}
        return m

    monkeypatch.setattr(WebYosai, 'get_current_subject', mock_gcs)
    monkeypatch.setattr(WebYosai, 'get_current_webregistry', mock_cwr)

    @WebYosai.requires_dynamic_permission(['something:anything:{one}'])
    def do_this():
        return 'dothis'

    result = do_this()

    assert result == 'dothis'
    mock_wds.check_permission.assert_called_once_with(['something:anything:one'], all)


def test_requires_dynamic_permission_raises_one(monkeypatch):
    """
    This test verifies that the decorator works as expected.
    """
    mock_wds = mock.create_autospec(WebDelegatingSubject)
    mock_wds.check_permission.side_effect = IdentifiersNotSetException

    @staticmethod
    def mock_gcs():
        return mock_wds

    @staticmethod
    def mock_cwr():
        m = mock.MagicMock()
        m.resource_params = {'one': 'one'}
        return m

    monkeypatch.setattr(WebYosai, 'get_current_subject', mock_gcs)
    monkeypatch.setattr(WebYosai, 'get_current_webregistry', mock_cwr)

    @WebYosai.requires_dynamic_permission(['something:anything:{one}'])
    def do_this():
        return 'dothis'

    with pytest.raises(Exception):
        do_this()


def test_requires_dynamic_permission_raises_two(monkeypatch):
    """
    This test verifies that the decorator works as expected.
    """
    mock_wds = mock.create_autospec(WebDelegatingSubject)
    mock_wds.check_permission.side_effect = AuthorizationException

    @staticmethod
    def mock_gcs():
        return mock_wds

    @staticmethod
    def mock_cwr():
        m = mock.MagicMock()
        m.resource_params = {'one': 'one'}
        return m

    monkeypatch.setattr(WebYosai, 'get_current_subject', mock_gcs)
    monkeypatch.setattr(WebYosai, 'get_current_webregistry', mock_cwr)

    @WebYosai.requires_dynamic_permission(['something:anything:{one}'])
    def do_this():
        return 'dothis'

    with pytest.raises(Exception):
        do_this()


def test_requires_role_succeeds(monkeypatch):
    """
    This test verifies that the decorator works as expected.
    """

    mock_wds = mock.create_autospec(WebDelegatingSubject)

    @staticmethod
    def mock_gcs():
        return mock_wds

    monkeypatch.setattr(WebYosai, 'get_current_subject', mock_gcs)

    @WebYosai.requires_role(['role1'])
    def do_this():
        return 'dothis'

    result = do_this()

    assert result == 'dothis'
    mock_wds.check_role.assert_called_once_with(['role1'], all)


def test_requires_role_raises_one(monkeypatch):
    """
    This test verifies that the decorator works as expected.
    """

    mock_wds = mock.create_autospec(WebDelegatingSubject)
    mock_wds.check_role.side_effect = IdentifiersNotSetException

    @staticmethod
    def mock_gcs():
        return mock_wds

    @staticmethod
    def mock_cwr():
        m = mock.MagicMock()
        m.resource_params = {'one': 'one'}
        return m

    monkeypatch.setattr(WebYosai, 'get_current_subject', mock_gcs)
    monkeypatch.setattr(WebYosai, 'get_current_webregistry', mock_cwr)

    @WebYosai.requires_role(['role1'])
    def do_this():
        return 'dothis'

    with pytest.raises(Exception):
        do_this()


def test_requires_role_raises_two(monkeypatch):
    """
    This test verifies that the decorator works as expected.
    """

    mock_wds = mock.create_autospec(WebDelegatingSubject)
    mock_wds.check_role.side_effect = AuthorizationException

    @staticmethod
    def mock_gcs():
        return mock_wds

    @staticmethod
    def mock_cwr():
        m = mock.MagicMock()
        m.resource_params = {'one': 'one'}
        return m

    monkeypatch.setattr(WebYosai, 'get_current_subject', mock_gcs)
    monkeypatch.setattr(WebYosai, 'get_current_webregistry', mock_cwr)

    @WebYosai.requires_role(['role1'])
    def do_this():
        return 'dothis'

    with pytest.raises(Exception):
        do_this()
