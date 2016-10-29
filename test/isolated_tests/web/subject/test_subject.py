import pytest
from unittest import mock
from yosai.core.subject.subject import global_subject_context, global_yosai_context
from yosai.web.subject.subject import global_webregistry_context

from yosai.core import (
    AuthorizationException,
    SubjectContext,
)

from yosai.web import (
    WebYosai,
    WebDelegatingSubject,
)


@mock.patch.object(SubjectContext, 'resolve_host', return_value='resolved_host')
def test_web_subject_context_resolve_host_super(
        super_resolve_host, web_subject_context):
    """
    super resolves a host from session
    """

    result = web_subject_context.resolve_host('session')
    super_resolve_host.assert_called_once_with('session')
    assert result == 'resolved_host'


@mock.patch.object(SubjectContext, 'resolve_host', return_value=None)
def test_web_subject_context_resolve_host_webregistry(
        super_resolve_host, web_subject_context, monkeypatch, mock_web_registry):
    """
    - super fails to resolve a host from session
    - resolve_web_registry().remote_host is returned
    """
    monkeypatch.setattr(web_subject_context, 'resolve_web_registry',
                        lambda: mock_web_registry)
    result = web_subject_context.resolve_host('session')
    super_resolve_host.assert_called_once_with('session')
    assert result == '123.45.6789'


def test_web_subject_context_resolve_webregistry(web_subject_context, monkeypatch):
    """
    returns self.web_registry
    """
    monkeypatch.setattr(web_subject_context, 'web_registry', 'webregistry')
    result = web_subject_context.resolve_web_registry()
    assert result == 'webregistry'


def test_web_subject_context_resolve_webregistry_no_registry_raises(
        web_subject_context, monkeypatch, caplog):
    """
    - no self.web_registry exists
    - no subject.web_registry attribute
    - None is returned
    """
    monkeypatch.setattr(web_subject_context, 'web_registry', None)
    monkeypatch.setattr(web_subject_context, 'subject', None)
    result = web_subject_context.resolve_web_registry()
    assert result is None and 'could not find a WebRegistry' in caplog.text


def test_web_subject_context_resolve_webregistry_no_reg_returns_subject_wr(
        web_subject_context, monkeypatch):
    """
    - no self.web_registry exists
    - returns subject.web_registry attribute
    """
    mock_subject = mock.create_autospec(WebDelegatingSubject)
    mock_subject.web_registry = 'mockwebregistry'
    monkeypatch.setattr(web_subject_context, 'subject', mock_subject)

    monkeypatch.setattr(web_subject_context, 'web_registry', None)

    result = web_subject_context.resolve_web_registry()
    assert result == 'mockwebregistry'

# ------------------------------------------------------------------------------
# WebDelegatingSubject
# ------------------------------------------------------------------------------

def test_web_delegating_subject_create_session_context(
        web_delegating_subject):
    result = web_delegating_subject.create_session_context()
    assert result['host'] == web_delegating_subject.host


# ------------------------------------------------------------------------------
# WebYosai
# ------------------------------------------------------------------------------

@mock.patch('yosai.web.subject.subject.WebSubjectContext', return_value='wsc')
def test_web_yosai_get_subject_returns_subject(
        mock_wsc, web_yosai, monkeypatch, mock_web_registry):

    @staticmethod
    def mock_cwr():
        return mock_web_registry

    monkeypatch.setattr(WebYosai, 'get_current_webregistry', mock_cwr)
    with mock.patch.object(web_yosai.security_manager, 'create_subject') as mock_cs:
        mock_ws = mock.create_autospec(WebDelegatingSubject)
        mock_ws.web_registry = 'wr'
        mock_cs.return_value = mock_ws
        result = web_yosai._get_subject()
        mock_wsc.assert_called_once_with(yosai=web_yosai,
                                         security_manager=web_yosai.security_manager,
                                         web_registry=mock_web_registry)
        mock_cs.assert_called_once_with(subject_context='wsc')
        assert result == mock_ws


def test_web_yosai_get_current_webregistry(web_yosai, monkeypatch):
    mock_stack = ['webregistry']
    monkeypatch.setattr(global_webregistry_context, 'stack', mock_stack)

    result = WebYosai.get_current_webregistry()

    assert result == 'webregistry'


def test_web_yosai_get_current_webregistry_raises(web_yosai, monkeypatch):
    mock_stack = []
    monkeypatch.setattr(global_webregistry_context, 'stack', mock_stack)

    with pytest.raises(IndexError):
        WebYosai.get_current_webregistry()


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
        m.check_permission.side_effect = ValueError

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
    mock_wds.check_permission.side_effect = ValueError

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
    mock_wds.check_role.side_effect = ValueError

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
