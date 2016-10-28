import pytest
from unittest import mock
from yosai.core import (
    AbstractSessionStore,
    CachingSessionStore,
    SessionKey,
)

# -----------------------------------------------------------------------------
# AbstractSessionStore
# -----------------------------------------------------------------------------


def test_asd_generate_session_id_succeeds(mock_abstract_session_store, monkeypatch):
    """
    unit tested:  generate_session_id

    test case:
    successfully generates a session_id (str)
    """
    masd = mock_abstract_session_store
    result = masd.generate_session_id()
    assert result


def test_asd_create(mock_abstract_session_store, monkeypatch):
    """
    unit tested:  create

    test case:
    creates a session_id by calling do_create and verifying it
    """
    masd = mock_abstract_session_store
    monkeypatch.setattr(masd, '_do_create', lambda x: 'sessionid123')
    with mock.patch.object(AbstractSessionStore, 'verify_session_id') as vsi:
        vsi.return_value = None
        result = masd.create(session='arbitrarysession')
        vsi.assert_called_once_with('sessionid123')
        assert result == 'sessionid123'


def test_asd_verify_session_id_raises(mock_abstract_session_store):
    """
    unit tested:  verify_session_id

    test case:
    calling method with a None value raises and exception
    """
    masd = mock_abstract_session_store
    with pytest.raises(ValueError):
        masd.verify_session_id(session_id=None)


def test_asd_verify_session_id_succeeds(mock_abstract_session_store):
    """
    unit tested:  verify_session_id

    test case:
    calling method with non-None value returns successfully
    """
    masd = mock_abstract_session_store
    masd.verify_session_id(session_id='arbitrarysessionid')


def test_asd_read_raises(mock_abstract_session_store, monkeypatch):
    """
    unit tested:  read

    test case:
    read should raise an exception when it cannot find a session
    identified by the session_id parameter
    """
    masd = mock_abstract_session_store
    monkeypatch.setattr(masd, '_do_read', lambda x: None)
    with pytest.raises(ValueError):
        masd.read('sessionid123')


def test_asd_read_succeeds(mock_abstract_session_store, monkeypatch):
    """
    unit tested:  read

    test case:
    read_session succeeds when do_read returns a session
    """
    masd = mock_abstract_session_store
    monkeypatch.setattr(masd, '_do_read', lambda x: 'mocksession')
    result = masd.read('sessionid123')
    assert result == 'mocksession'


# -----------------------------------------------------------------------------
# MemorySessionStore
# -----------------------------------------------------------------------------

def test_msd_do_create(memory_session_store):
    """
    unit tested:  _do_create

    test case:
    generates a session id, assigns it to the session, and stores the session
    """
    msd = memory_session_store
    mock_session = mock.MagicMock(session_id='sessionid123')

    with mock.patch.object(msd, 'generate_session_id') as mock_gsi:
        mock_gsi.return_value = 'sessionid123'
        with mock.patch.object(msd, 'store_session') as mock_ss:
            mock_ss.return_value = None

            result = msd._do_create(mock_session)

            mock_gsi.assert_called_once_with()
            mock_ss.assert_called_once_with('sessionid123', mock_session)
            assert result == 'sessionid123'


def test_msd_store_session(memory_session_store):
    """
    unit tested:  store_session

    test case:
    passing a valid (non-None) session_id and session will save it in the
    sessions dict
    """
    msd = memory_session_store
    result = msd.store_session(session_id='sessionid123', session='dumbsession')
    assert result == 'dumbsession'


@pytest.mark.parametrize("session_id, session",
                         [(None, 'dumbsession'), ('sessionid123', None)])
def test_msd_store_session_raises(memory_session_store, session_id, session):
    """
    unit tested:  store_session

    test case:
    if either session_id or session are not set, an exception will raise
    """
    msd = memory_session_store
    with pytest.raises(ValueError):
        msd.store_session(session_id, session)


@pytest.mark.parametrize("session_id, expected",
                         [('sessionid123', 'sessionid123session'),
                          ('sessionid345', None)])
def test_msd_do_read_session(
        memory_session_store, monkeypatch, session_id, expected):
    """
    unit tested:  do_read

    test case:
    normal code path exercise, returning a value or None
    """
    msd = memory_session_store
    monkeypatch.setitem(msd.sessions, 'sessionid123', 'sessionid123session')
    result = msd._do_read(session_id)
    assert result == expected


def test_msd_update(memory_session_store, mock_session):
    """
    unit tested:  update

    test case:
    calling update with a session will call store_session using it as param
    """
    msd = memory_session_store
    result = msd.update(mock_session)
    assert result.session_id == mock_session.session_id


def test_msd_delete_raises_ae(memory_session_store):
    """
    unit tested:  delete

    test case:
    calling delete while passing a session without a session_id attribute will
    raise an AttributeError
    """
    msd = memory_session_store
    with pytest.raises(AttributeError):
        msd.delete(session='dumbsession')


# -----------------------------------------------------------------------------
# CachingSessionStore
# -----------------------------------------------------------------------------

def test_csd_create(session_store):
    """
    unit tested:  create

    test case:
    calls two methods and returns sessionid
    """
    csd = session_store
    with mock.patch.object(AbstractSessionStore, 'create') as mock_asdc:
        mock_asdc.return_value = 'sessionid123'
        with mock.patch.object(CachingSessionStore, '_cache') as csdc:
            csdc.return_value = None

            result = csd.create('session')
            csdc.assert_called_once_with('session', 'sessionid123')
            assert result == 'sessionid123'


def test_csd_read_session_exists(
        session_store, monkeypatch, mock_session):
    """
    unit tested:  read

    test case:
    _get_cached_session returns a session, which in turn is returned by
    read
    """
    csd = session_store
    monkeypatch.setattr(csd, '_get_cached_session', lambda x: mock_session)
    result = csd.read('sessionid123')
    assert result == mock_session


def test_csd_update_isvalid(session_store, mock_session):
    """
    unit tested:  update

    test case:
    when a valid session is passed, cache is called
    """
    csd = session_store

    with mock.patch.object(csd, '_cache') as mock_cache_handler:
        mock_cache_handler.return_value = None

        csd.update(mock_session)

        mock_cache_handler.assert_called_once_with(
            mock_session, mock_session.session_id)


def test_csd_update_isnotvalid(
        session_store, mock_session, monkeypatch):
    """
    unit tested:  update

    test case:
    when a validating session is passed, and the session is invalid,
    uncache is called
    """
    csd = session_store
    mock_session.is_valid = False
    with mock.patch.object(csd, '_uncache') as mock_uncache:
        mock_uncache.return_value = None

        csd.update(mock_session)

        mock_uncache.assert_called_once_with(mock_session)


def test_csd_delete(session_store):
    """
    unit tested:  delete

    test case:
    basic code path exercise
    """
    csd = session_store
    with mock.patch.object(csd, '_uncache') as mock_uncache:
        mock_uncache.return_value = None
        csd.delete('session')
        mock_uncache.assert_called_once_with('session')


def test_csd_getcachedsession_returns(
        session_store, mock_cache_handler, monkeypatch):
    """
    unit tested:  _get_cached_session

    test case:
        when no cache param is passed, the cache is obtained by method call
        and then used to get the sessionid
    """
    csd = session_store
    monkeypatch.setattr(mock_cache_handler, 'get',
                        lambda domain, identifier: 'session_123')
    monkeypatch.setattr(csd, 'cache_handler', mock_cache_handler)
    result = csd._get_cached_session('sessionid123')
    assert result == 'session_123'


def test_csd_getcachedsession_none_default(
        session_store, mock_cache_handler, monkeypatch):
    """
    unit tested:  get_cached_session

    test case:
        when cache param is passed, it is used to get the sessionid
    """
    csd = session_store
    result = csd._get_cached_session(sessionid='sessionid123')
    assert result is None


def test_csd_cache_with_cachehandler(
        session_store, mock_cache_handler, monkeypatch, mock_session):
    """
    unit tested:  cache

    test case:
    uses cache_handler to set session entry
    """
    csd = session_store
    monkeypatch.setattr(csd, 'cache_handler', mock_cache_handler)

    with mock.patch.object(mock_cache_handler, 'set') as ch_set:
        ch_set.return_value = None
        csd._cache(mock_session, 'sessionid123')
        ch_set.assert_called_once_with(domain='session',
                                       identifier='sessionid123',
                                       value=mock_session)


def test_csd_uncache(
        session_store, mock_cache_handler, mock_session, monkeypatch,
        simple_identifier_collection):
    """
    unit tested:  uncache

    test case:
    session is removed by sessionid
    """
    csd = session_store
    sic = simple_identifier_collection
    monkeypatch.setattr(csd, 'cache_handler', mock_cache_handler)
    monkeypatch.setattr(mock_session, 'get_internal_attribute', lambda x: sic)
    with mock.patch.object(mock_cache_handler, 'delete') as mock_remove:
        mock_remove.return_value = None
        csd._uncache(mock_session)

        mock_remove.assert_called_once_with(domain='session',
                                            identifier=mock_session.session_id)
